// New package: internal/process/manager.go
package process

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("hera")

type ProcessManager struct {
	processes map[string]*ProcessState
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

type ProcessState struct {
	cmd          *exec.Cmd
	config       *Config
	logFile      *os.File // Log file handle (must be closed on restart/stop)
	state        State
	restartCount int
	lastRestart  time.Time
	backoff      time.Duration
	mu           sync.Mutex // Per-process lock for state transitions
}

type Config struct {
	ConfigPath string
	LogFile    string
}

type State int

const (
	StateStopped State = iota
	StateStarting
	StateRunning
	StateBackoff
	StateFatal
)

func NewProcessManager() *ProcessManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &ProcessManager{
		processes: make(map[string]*ProcessState),
		ctx:       ctx,
		cancel:    cancel,
	}
}

func (pm *ProcessManager) Start(hostname string, config *Config) error {
	// Validate inputs
	if hostname == "" {
		return fmt.Errorf("hostname cannot be empty")
	}
	if config == nil || config.ConfigPath == "" {
		return fmt.Errorf("invalid config for %s", hostname)
	}

	// Check if already exists
	pm.mu.RLock()
	_, exists := pm.processes[hostname]
	pm.mu.RUnlock()
	if exists {
		return fmt.Errorf("process %s already exists", hostname)
	}

	// Open log file
	logFile, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	cmd := exec.Command("cloudflared", "--config", config.ConfigPath, "--name", hostname)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// CRITICAL: Prevent orphans and enable process group management
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM, // Kill if Hera dies
		Setpgid:   true,             // Create new process group
	}

	if err := cmd.Start(); err != nil {
		if err := logFile.Close(); err != nil {
			log.Errorf("failed to close log file for %s: %v", hostname, err)
		}
		return fmt.Errorf("failed to start %s: %w", hostname, err)
	}

	ps := &ProcessState{
		cmd:         cmd,
		config:      config,
		logFile:     logFile,
		state:       StateRunning,
		backoff:     time.Second,
		lastRestart: time.Now(),
	}

	pm.mu.Lock()
	pm.processes[hostname] = ps
	pm.mu.Unlock()

	log.Infof("Started process %s (PID: %d)", hostname, cmd.Process.Pid)

	// Monitor process and restart if it dies
	go pm.supervise(hostname, ps)
	return nil
}

// FIXED: Properly reuses ProcessState and handles context cancellation
func (pm *ProcessManager) supervise(hostname string, ps *ProcessState) {
	err := ps.cmd.Wait()

	// Check if shutdown was requested
	select {
	case <-pm.ctx.Done():
		log.Infof("Process %s stopped due to shutdown", hostname)
		return
	default:
	}

	ps.mu.Lock()
	if ps.state == StateStopped {
		ps.mu.Unlock()
		log.Infof("Process %s stopped intentionally", hostname)
		return
	}

	// Reset restart counter if process ran successfully for 5+ minutes
	if time.Since(ps.lastRestart) > 5*time.Minute {
		log.Infof("Process %s ran successfully for 5+ minutes, resetting restart counter", hostname)
		ps.restartCount = 0
		ps.backoff = time.Second
	}

	// Implement exponential backoff
	ps.restartCount++
	if ps.restartCount > 10 {
		ps.state = StateFatal
		ps.mu.Unlock()
		log.Errorf("Process %s failed too many times (attempt %d), marking as FATAL",
			hostname, ps.restartCount)
		return
	}

	ps.state = StateBackoff
	backoffDuration := ps.backoff
	ps.backoff = ps.backoff * 2
	if ps.backoff > 60*time.Second {
		ps.backoff = 60 * time.Second
	}
	ps.mu.Unlock()

	log.Errorf("Process %s exited with error: %v, restarting in %v (attempt %d)",
		hostname, err, backoffDuration, ps.restartCount)

	// Wait before restarting (with context cancellation support)
	select {
	case <-time.After(backoffDuration):
		// Continue with restart
	case <-pm.ctx.Done():
		log.Infof("Restart of %s cancelled due to shutdown", hostname)
		return
	}

	// Restart the SAME ProcessState with new cmd (CRITICAL FIX)
	// Close old log file before opening new one to prevent FD leak
	ps.mu.Lock()
	if ps.logFile != nil {
		if err := ps.logFile.Close(); err != nil {
			log.Errorf("failed to close log file for %s: %v", hostname, err)
		}
	}
	ps.mu.Unlock()

	logFile, err := os.OpenFile(ps.config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Errorf("Failed to open log file for %s: %v", hostname, err)
		return
	}

	cmd := exec.Command("cloudflared", "--config", ps.config.ConfigPath, "--name", hostname)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
		Setpgid:   true,
	}

	if err := cmd.Start(); err != nil {
		if err := logFile.Close(); err != nil {
			log.Errorf("failed to close log file for %s: %v", hostname, err)
		}
		log.Errorf("Failed to restart %s: %v", hostname, err)

		ps.mu.Lock()
		ps.cmd = nil // Clear stale process reference
		ps.state = StateFatal
		ps.mu.Unlock()
		return
	}

	ps.mu.Lock()
	ps.cmd = cmd
	ps.logFile = logFile // Store new log file handle
	ps.state = StateRunning
	ps.lastRestart = time.Now()
	ps.mu.Unlock()

	log.Infof("Restarted process %s (PID: %d, attempt %d)", hostname, cmd.Process.Pid, ps.restartCount)

	// Recursive call with SAME ProcessState
	go pm.supervise(hostname, ps)
}

// FIXED: Properly waits for process and kills process group
func (pm *ProcessManager) Stop(hostname string) error {
	pm.mu.RLock()
	ps, exists := pm.processes[hostname]
	pm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("process %s not found", hostname)
	}

	// Mark as stopped to prevent supervise from restarting
	ps.mu.Lock()
	ps.state = StateStopped
	ps.mu.Unlock()

	if ps.cmd == nil || ps.cmd.Process == nil {
		// Close log file even if process already stopped
		ps.mu.Lock()
		if ps.logFile != nil {
			if err := ps.logFile.Close(); err != nil {
				log.Errorf("failed to close log file for %s: %v", hostname, err)
			}
			ps.logFile = nil
		}
		ps.mu.Unlock()

		pm.mu.Lock()
		delete(pm.processes, hostname)
		pm.mu.Unlock()
		return nil
	}

	pid := ps.cmd.Process.Pid
	log.Infof("Stopping process %s (PID: %d)", hostname, pid)

	// Try to kill entire process group first (cloudflared might have children)
	pgid, err := syscall.Getpgid(pid)
	if err == nil && pgid > 0 {
		// Kill entire process group with SIGTERM
		if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil {
			log.Errorf("Failed to send SIGTERM to process group %d: %v", pgid, err)
		}
	} else {
		// Fallback: kill just the main process
		ps.cmd.Process.Signal(syscall.SIGTERM)
	}

	// Wait up to 10 seconds for graceful shutdown
	done := make(chan error, 1)
	go func() {
		done <- ps.cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			log.Infof("Process %s exited with: %v", hostname, err)
		} else {
			log.Infof("Process %s stopped gracefully", hostname)
		}
	case <-time.After(10 * time.Second):
		log.Errorf("Process %s didn't exit gracefully, force killing", hostname)

		// Force kill entire process group
		if pgid, err := syscall.Getpgid(pid); err == nil && pgid > 0 {
			syscall.Kill(-pgid, syscall.SIGKILL)
		} else {
			ps.cmd.Process.Kill()
		}

		// CRITICAL FIX: Must Wait() after Kill() to reap zombie
		ps.cmd.Wait()
	}

	// Close log file to prevent file descriptor leak
	ps.mu.Lock()
	if ps.logFile != nil {
		if err := ps.logFile.Close(); err != nil {
			log.Errorf("failed to close log file for %s: %v", hostname, err)
		}
		ps.logFile = nil
	}
	ps.mu.Unlock()

	pm.mu.Lock()
	delete(pm.processes, hostname)
	pm.mu.Unlock()

	return nil
}

// FIXED: Uses context cancellation and concurrent shutdown
func (pm *ProcessManager) Shutdown() error {
	log.Info("Shutting down all processes...")

	// Cancel context to stop all supervise goroutines
	pm.cancel()

	pm.mu.RLock()
	hostnames := make([]string, 0, len(pm.processes))
	for hostname := range pm.processes {
		hostnames = append(hostnames, hostname)
	}
	pm.mu.RUnlock()

	// Stop all processes concurrently with timeout
	var wg sync.WaitGroup
	for _, hostname := range hostnames {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			if err := pm.Stop(h); err != nil {
				log.Errorf("Error stopping %s: %v", h, err)
			}
		}(hostname)
	}

	// Wait for all stops with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Info("All processes shut down successfully")
	case <-time.After(30 * time.Second):
		log.Error("Shutdown timeout reached, some processes may still be running")
	}

	return nil
}

// GetState returns the current state of a process
func (pm *ProcessManager) GetState(hostname string) (State, error) {
	pm.mu.RLock()
	ps, exists := pm.processes[hostname]
	pm.mu.RUnlock()

	if !exists {
		return StateStopped, fmt.Errorf("process %s not found", hostname)
	}

	ps.mu.Lock()
	state := ps.state
	ps.mu.Unlock()

	return state, nil
}

// IsRunning returns true if a process is in Running state
func (pm *ProcessManager) IsRunning(hostname string) bool {
	state, err := pm.GetState(hostname)
	return err == nil && state == StateRunning
}

// ListProcesses returns a map of all processes and their states
func (pm *ProcessManager) ListProcesses() map[string]State {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	result := make(map[string]State, len(pm.processes))
	for hostname, ps := range pm.processes {
		ps.mu.Lock()
		result[hostname] = ps.state
		ps.mu.Unlock()
	}
	return result
}
