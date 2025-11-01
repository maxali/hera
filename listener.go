package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/spf13/afero"
)

// Listener holds config for an event listener and is used to listen for container events
type Listener struct {
	Client *Client
	Fs     afero.Fs
}

// NewListener returns a new Listener
func NewListener() (*Listener, error) {
	client, err := NewClient()
	if err != nil {
		log.Error("Unable to connect to Docker", "error", err)
		return nil, err
	}

	listener := &Listener{
		Client: client,
		Fs:     afero.NewOsFs(),
	}

	return listener, nil
}

// Revive revives tunnels for currently running containers in parallel
func (l *Listener) Revive() error {
	startTime := time.Now()
	log.Info("Starting parallel tunnel revival")

	containers, err := l.Client.ListContainers()
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	if len(containers) == 0 {
		log.Info("No containers found to revive")
		return nil
	}

	log.Info("Found containers to revive", "count", len(containers))

	// Get concurrency limit from environment variable
	maxConcurrency := getRevivalConcurrency()
	timeout := getRevivalTimeout()

	log.Info("Using revival settings", "max_concurrency", maxConcurrency, "timeout", timeout)

	// Semaphore for rate limiting
	semaphore := make(chan struct{}, maxConcurrency)

	// WaitGroup to track completion
	var wg sync.WaitGroup

	// Channel for collecting errors (buffered to prevent goroutine blocking)
	errChan := make(chan revivalError, len(containers))

	// Launch goroutines for each container
	for _, c := range containers {
		wg.Add(1)
		go func(containerID string) {
			defer wg.Done()

			// Acquire semaphore (rate limit)
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Create context with timeout for this specific tunnel
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			// Create handler for this goroutine
			handler := NewHandler(l.Client)

			// Run tunnel revival with timeout
			errChan <- l.reviveContainerWithTimeout(ctx, handler, containerID)
		}(c.ID)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(errChan)

	// Collect results
	var errors []revivalError
	successCount := 0
	timeoutCount := 0

	for err := range errChan {
		if err.err != nil {
			errors = append(errors, err)
			if err.timeout {
				timeoutCount++
			}
		} else {
			successCount++
		}
	}

	duration := time.Since(startTime)

	// Log summary
	if len(errors) > 0 {
		log.Error("Revival completed with errors",
			"total", len(containers),
			"success", successCount,
			"failed", len(errors),
			"timeouts", timeoutCount,
			"duration", duration)

		// Log individual failures
		for _, e := range errors {
			log.Error("Container revival failed",
				"container_id", e.containerID,
				"error", e.err,
				"timeout", e.timeout)
		}

		// Return aggregated error with details
		return fmt.Errorf("tunnel revival completed with %d failures out of %d containers (timeouts: %d)",
			len(errors), len(containers), timeoutCount)
	}

	log.Info("Revival completed successfully",
		"total", len(containers),
		"success", successCount,
		"duration", duration,
		"avg_per_tunnel", duration/time.Duration(len(containers)))

	return nil
}

// Listen listens for container events to be handled
func (l *Listener) Listen() {
	log.Info("Hera is listening")

	handler := NewHandler(l.Client)
	messages, errs := l.Client.Events()

	for {
		select {
		case event := <-messages:
			handler.HandleEvent(event)

		case err := <-errs:
			if err != nil && err != io.EOF {
				log.Error("Docker event error", "error", err)
			}
		}
	}
}

// gcResult holds the result of garbage collection for one certificate
type gcResult struct {
	certName string
	scanned  int
	deleted  int
	failed   int
}

// GarbageCollectOrphanedTunnels removes tunnels that no longer have containers
// Processes each certificate in parallel for multi-domain support
func (l *Listener) GarbageCollectOrphanedTunnels() error {
	// Check for dry-run mode
	dryRun := os.Getenv("HERA_GC_DRY_RUN") == "true"
	if dryRun {
		log.Info("Starting garbage collection in DRY-RUN mode (no deletions will occur)...")
	} else {
		log.Info("Starting garbage collection for orphaned tunnels...")
	}

	// Get all certificates to process each domain independently
	certs, err := l.getAllCertificates()
	if err != nil {
		log.Warn("Failed to get certificates", "error", err)
		return nil // Don't fail startup on GC errors
	}

	if len(certs) == 0 {
		log.Warn("No certificates found, skipping garbage collection")
		return nil
	}

	// Get expected tunnels once (shared across all certificates)
	expectedTunnels := l.getExpectedTunnels()

	// Process each certificate in parallel with panic recovery
	var wg sync.WaitGroup
	results := make(chan gcResult, len(certs))

	for _, cert := range certs {
		wg.Add(1)
		go func(c *Certificate) {
			defer func() {
				if r := recover(); r != nil {
					log.Error("Panic in GC for certificate", "certificate", c.Name, "panic", r)
					// Send empty result to prevent blocking
					results <- gcResult{certName: c.Name, failed: 1}
				}
				wg.Done()
			}()
			result := l.garbageCollectForCertificate(c, expectedTunnels)
			results <- result
		}(cert)
	}

	// Wait for all certificates to be processed with panic safety
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("Panic in GC result collector", "panic", r)
			}
			close(results)
		}()
		wg.Wait()
	}()

	// Collect and log aggregated results
	totalDeleted := 0
	totalFailed := 0
	totalScanned := 0

	for result := range results {
		log.Info("Certificate GC results", "certificate", result.certName, "scanned", result.scanned, "deleted", result.deleted, "failed", result.failed)
		totalDeleted += result.deleted
		totalFailed += result.failed
		totalScanned += result.scanned
	}

	log.Info("Garbage collection complete", "scanned", totalScanned, "deleted", totalDeleted, "failed", totalFailed)

	return nil
}

// garbageCollectForCertificate performs GC for a single certificate/domain
func (l *Listener) garbageCollectForCertificate(cert *Certificate,
	expectedTunnels map[string]bool) gcResult {

	result := gcResult{
		certName: cert.Name,
	}

	log.Info("Processing certificate", "name", cert.Name)

	// List all tunnels for this certificate
	allTunnels, err := ListAllCloudflaredTunnels(cert.FullPath())
	if err != nil {
		log.Error("Failed to list tunnels for certificate", "certificate", cert.Name, "error", err)
		return result
	}

	result.scanned = len(allTunnels)
	if len(allTunnels) == 0 {
		return result
	}

	// Read and validate minimum age configuration
	minAgeMinutes := 10 // Default: 10 minutes
	if env := os.Getenv("HERA_GC_MIN_AGE_MINUTES"); env != "" {
		if minutes, err := strconv.Atoi(env); err == nil {
			if minutes < 1 {
				log.Warn("Invalid HERA_GC_MIN_AGE_MINUTES (must be >= 1), using default", "value", minutes, "default", 10)
				minAgeMinutes = 10
			} else if minutes > 1440 {
				log.Warn("HERA_GC_MIN_AGE_MINUTES seems excessive (>24h), using anyway", "minutes", minutes)
				minAgeMinutes = minutes
			} else {
				minAgeMinutes = minutes
			}
		} else {
			log.Warn("Invalid HERA_GC_MIN_AGE_MINUTES (not a number), using default", "value", env, "default", 10)
		}
	}
	minAge := time.Duration(minAgeMinutes) * time.Minute
	log.Info("Using minimum tunnel age", "age", minAge)

	// Identify orphaned tunnels with safety checks
	orphanedTunnels := make([]TunnelInfo, 0)

	for _, tunnel := range allTunnels {
		// CRITICAL: Only process tunnels created by Hera (with hera- prefix)
		// This prevents Hera from deleting manually created tunnels or tunnels
		// created by other tools/processes
		if !isHeraTunnel(tunnel.Name) {
			log.Debug("Skipping tunnel - not created by Hera (no hera- prefix)", "tunnel", tunnel.Name)
			continue
		}

		// Skip if tunnel has an active container
		if expectedTunnels[tunnel.Name] {
			log.Debug("Tunnel has active container, skipping", "tunnel", tunnel.Name)
			continue
		}

		// Safety check 1: Only delete tunnels with zero connections
		if tunnel.Connections > 0 {
			log.Warn("Skipping tunnel - has active connections", "tunnel", tunnel.Name, "connections", tunnel.Connections)
			continue
		}

		// Safety check 2: Only delete tunnels older than minimum age
		if !tunnel.CreatedAt.IsZero() && time.Since(tunnel.CreatedAt) < minAge {
			age := time.Since(tunnel.CreatedAt).Round(time.Second)
			log.Info("Skipping recent tunnel", "tunnel", tunnel.Name, "age", age, "min_age", minAge)
			continue
		}

		orphanedTunnels = append(orphanedTunnels, tunnel)
	}

	if len(orphanedTunnels) == 0 {
		log.Info("No orphaned tunnels found for certificate", "certificate", cert.Name)
		return result
	}

	log.Info("Found orphaned tunnels to clean up", "count", len(orphanedTunnels), "certificate", cert.Name)

	// Delete orphaned tunnels in parallel with proper synchronization
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, tunnel := range orphanedTunnels {
		wg.Add(1)
		go func(t TunnelInfo) {
			defer wg.Done()

			age := time.Since(t.CreatedAt).Round(time.Second)

			// CRITICAL RACE CONDITION FIX (Issue #2):
			// Re-check if tunnel is still orphaned immediately before deletion
			// A container could have started between initial check and now

			// Safety check 1: Re-verify no container exists for this hostname
			containers, err := l.Client.ListContainers()
			if err != nil {
				log.Error("Failed to re-verify containers", "tunnel", t.Name, "error", err)
				mu.Lock()
				result.failed++
				mu.Unlock()
				return
			}

			for _, c := range containers {
				container, err := l.Client.Inspect(c.ID)
				if err != nil {
					continue
				}
				hostname := getLabel(heraHostname, container)
				if hostname != "" {
					expectedTunnelName := getTunnelName(hostname)
					if expectedTunnelName == t.Name {
						log.Info("Tunnel now has active container, skipping deletion", "tunnel", t.Name)
						return // Container started during GC - abort deletion
					}
				}
			}

			// Safety check 2: Verify tunnel is NOT in local registry (thread-safe)
			// CRITICAL: tunnel.Start() registers BEFORE starting process (tunnel.go:128)
			// A tunnel in registry but without running process is in "creation phase"
			// Deleting it would cause the pending cloudflared process to fail
			// NOTE: Registry uses hostname (without prefix) as key
			hostname := getHostnameFromTunnelName(t.Name)
			if _, err := GetTunnelForHost(hostname); err == nil {
				log.Info("Tunnel now in registry, skipping deletion", "tunnel", t.Name)
				return // Tunnel was registered during GC - abort deletion
			}

			// Safety check 3: Verify process is NOT running
			// (double-check against ProcessManager state)
			// NOTE: ProcessManager uses hostname (without prefix) as key
			if processManager.IsRunning(hostname) {
				log.Warn("Tunnel has running process, skipping deletion", "tunnel", t.Name)
				return // Process is active - abort deletion
			}

			// Check dry-run mode before deleting
			dryRun := os.Getenv("HERA_GC_DRY_RUN") == "true"

			if dryRun {
				log.Info("[DRY-RUN] Would delete orphaned tunnel", "tunnel", t.Name, "age", age, "connections", t.Connections)
				mu.Lock()
				result.deleted++ // Count as "would delete"
				mu.Unlock()
			} else {
				log.Info("Deleting orphaned tunnel", "tunnel", t.Name, "age", age, "connections", t.Connections)

				if err := DeleteTunnelByName(t.Name, cert.FullPath()); err != nil {
					mu.Lock()
					result.failed++
					mu.Unlock()
					log.Error("Failed to delete orphaned tunnel", "tunnel", t.Name, "error", err)
				} else {
					mu.Lock()
					result.deleted++
					mu.Unlock()
				}
			}
		}(tunnel)
	}

	wg.Wait() // Wait for all deletions to complete
	return result
}

// getExpectedTunnels returns hostnames that should have tunnels (have containers)
func (l *Listener) getExpectedTunnels() map[string]bool {
	expectedTunnels := make(map[string]bool)

	containers, err := l.Client.ListContainers()
	if err != nil {
		log.Error("Failed to list containers", "error", err)
		return expectedTunnels
	}

	// Parallelize container inspection with concurrency limit
	// Limit concurrent inspections to avoid overwhelming Docker API
	const maxConcurrency = 20
	semaphore := make(chan struct{}, maxConcurrency)

	type containerHostname struct {
		hostname string
	}

	results := make(chan containerHostname, len(containers))
	var wg sync.WaitGroup

	for _, c := range containers {
		wg.Add(1)
		go func(containerID string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			container, err := l.Client.Inspect(containerID)
			if err != nil {
				log.Debug("Failed to inspect container", "container_id", containerID, "error", err)
				return
			}

			hostname := getLabel(heraHostname, container)
			if hostname != "" {
				results <- containerHostname{hostname: hostname}
			}
		}(c.ID)
	}

	// Close results channel when all inspections complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results and convert to prefixed tunnel names
	for result := range results {
		tunnelName := getTunnelName(result.hostname)
		expectedTunnels[tunnelName] = true
	}

	log.Info("Found containers with hera.hostname labels", "count", len(expectedTunnels))
	return expectedTunnels
}

// getAllCertificates returns all .pem certificates from the certs directory
// Uses the same discovery logic as FindAllCertificates from certificate.go
func (l *Listener) getAllCertificates() ([]*Certificate, error) {
	certs, err := FindAllCertificates(l.Fs)
	if err != nil {
		return nil, fmt.Errorf("failed to find certificates: %w", err)
	}

	// Validate that certificates are readable (Issue #26)
	validCerts := make([]*Certificate, 0, len(certs))
	for _, cert := range certs {
		// Verify certificate file exists and is readable
		if exists, err := afero.Exists(l.Fs, cert.FullPath()); !exists || err != nil {
			log.Warn("Certificate is not accessible", "certificate", cert.Name, "error", err)
			continue
		}
		validCerts = append(validCerts, cert)
	}

	log.Info("Found valid certificates", "count", len(validCerts), "path", CertificatePath)
	return validCerts, nil
}

// getRevivalConcurrency returns the maximum concurrent tunnel revivals
// Default: 5, Range: 1-100. Values above 10 may cause rate limiting
func getRevivalConcurrency() int {
	concurrency := 5 // Conservative default

	if env := os.Getenv("HERA_REVIVAL_CONCURRENCY"); env != "" {
		if val, err := strconv.Atoi(env); err == nil {
			if val < 1 {
				log.Warn("Invalid HERA_REVIVAL_CONCURRENCY (must be >= 1), using default",
					"value", val, "default", 5)
				return 5
			}
			if val > 100 {
				log.Warn("HERA_REVIVAL_CONCURRENCY exceeds recommended maximum (100)",
					"value", val, "warning", "May cause rate limiting")
			}
			concurrency = val
		} else {
			log.Warn("Invalid HERA_REVIVAL_CONCURRENCY (not a number), using default",
				"value", env, "default", 5)
		}
	}

	return concurrency
}

// getRevivalTimeout returns the timeout for each individual tunnel revival
// Default: 30s
func getRevivalTimeout() time.Duration {
	timeout := 30 * time.Second // 6x normal creation time

	if env := os.Getenv("HERA_REVIVAL_TIMEOUT"); env != "" {
		if duration, err := time.ParseDuration(env); err == nil {
			if duration < 5*time.Second {
				log.Warn("HERA_REVIVAL_TIMEOUT too low (minimum 5s), using default",
					"value", duration, "default", timeout)
				return timeout
			}
			if duration > 5*time.Minute {
				log.Warn("HERA_REVIVAL_TIMEOUT very high, may delay startup",
					"value", duration)
			}
			timeout = duration
		} else {
			log.Warn("Invalid HERA_REVIVAL_TIMEOUT, using default",
				"value", env, "default", timeout)
		}
	}

	return timeout
}

// revivalError holds error information for a single container revival
type revivalError struct {
	containerID string
	err         error
	timeout     bool
}

// reviveContainerWithTimeout handles a single container with timeout
func (l *Listener) reviveContainerWithTimeout(ctx context.Context, handler *Handler, containerID string) revivalError {
	// Channel to receive result from HandleContainer
	done := make(chan error, 1)

	go func() {
		done <- handler.HandleContainer(containerID)
	}()

	select {
	case err := <-done:
		if err != nil {
			return revivalError{containerID: containerID, err: err, timeout: false}
		}
		return revivalError{containerID: containerID, err: nil, timeout: false}

	case <-ctx.Done():
		return revivalError{
			containerID: containerID,
			err:         fmt.Errorf("tunnel revival timed out after %v", ctx.Err()),
			timeout:     true,
		}
	}
}
