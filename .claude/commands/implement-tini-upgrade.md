---
description: Implement the tini + native Go process manager upgrade
model: sonnet
---

You are implementing the comprehensive upgrade to replace s6-overlay with tini + native Go process management. This is a major architectural refactor documented in @docs/upgrade-plan-s6-alpine.md.

<context>
## Current Architecture Problem
Hera currently uses s6-overlay v1.21.4.0 (from 2018) which is 7 years old with security vulnerabilities. Upgrading to s6-overlay v3 is NOT viable because it removed dynamic service creation at runtime - a core feature Hera depends on.

## Chosen Solution: tini + Direct Go Process Management
After comprehensive research and evaluation, tini + native Go process management is the ONLY viable path forward:
- **tini (~100KB)** handles PID 1 responsibilities (signal forwarding, zombie reaping)
- **Hera (PID 2)** manages cloudflared processes in pure Go
- **43% smaller image** (100MB → 57MB)
- **Battle-tested**: tini is Docker's default init system
- **All alternatives ruled out**: s6-overlay v3 (no dynamic services), supervisord (Python overhead), pure Go as PID 1 (complex init code)
</context>

<critical-bugs-fixed>
## ⚠️ CRITICAL: Implementation Contains 8 Fixed Bugs
The upgrade plan document contains bug-free code. The original proposal had these bugs that are NOW FIXED:

1. **Memory Leak in supervise()** - ✅ FIXED: Reuses ProcessState instead of calling Start()
2. **File Descriptor Leak** - ✅ FIXED: Stores logFile in ProcessState, closes before reopening
3. **Restart Counter Never Resets** - ✅ FIXED: Resets after 5 minutes of stability
4. **Zombie After Kill()** - ✅ FIXED: Always calls Wait() after Kill()
5. **Goroutine Lifecycle Race** - ✅ FIXED: Uses context.Context for cancellation
6. **Missing Process Groups** - ✅ FIXED: Sets Setpgid: true and kills entire group
7. **Inadequate Error Handling** - ✅ FIXED: Comprehensive validation and error wrapping
8. **Missing `os` Import** - ✅ FIXED: Added to import list

**DO NOT improvise the process manager code. Use the exact implementation from the upgrade plan document.**
</critical-bugs-fixed>

<implementation-phases>
## Phase 1: Process Manager Implementation
1. Create `internal/process/manager.go` **using the EXACT code from the upgrade plan**
   - The document contains the complete, bug-free implementation
   - Includes: ProcessManager struct with context, ProcessState with per-process mutex and logFile
   - Key features: Start(), supervise(), Stop(), Shutdown(), GetState(), IsRunning(), ListProcesses()
   - **CRITICAL**: The supervise() function reuses ProcessState, does NOT call Start()
   - **CRITICAL**: logFile stored in ProcessState and closed on restart/stop
   - **CRITICAL**: Restart counter resets after 5 minutes of stability
   - **CRITICAL**: Process groups enabled with Setpgid: true
   - **CRITICAL**: Context-based cancellation for clean shutdown
2. Create comprehensive tests in `internal/process/manager_test.go`
3. Test scenarios: start/stop, auto-restart, zombie verification, context cancellation, FD leak testing

## Phase 2: Integration with Hera
1. Update `main.go` **using the EXACT integration code from the upgrade plan**:
   - Add global `processManager` variable
   - Initialize ProcessManager in main()
   - Add setupSignalHandlers() function
2. Update `tunnel.go` **using the EXACT integration code from the upgrade plan**:
   - Replace Service with direct ProcessManager calls
   - Update Start() to create config directory and call processManager.Start()
   - Update Stop() to call processManager.Stop()
   - Add configFilePath() and logFilePath() helper methods
   - Remove writeRunFile() (no longer needed)
3. **DELETE `service.go` entirely** - no longer needed
4. Update constants:
   - Change ConfigPath from "/var/run/s6/services" to "/etc/hera/tunnels"
   - Keep LogPath as "/var/log/hera"
5. No changes needed to handler.go - it already calls tunnel.Start()/Stop()
6. Update all tests to mock process execution

## Phase 3: Docker & Alpine Upgrade
1. Update Dockerfile **using the EXACT Dockerfile from the upgrade plan**:
   - Builder: `FROM golang:1.23-alpine3.20 AS builder`
   - Final: `FROM alpine:3.20`
   - **CRITICAL**: `RUN apk add --no-cache ca-certificates tini`
   - **CRITICAL**: `ENTRYPOINT ["/sbin/tini", "--", "/bin/hera"]`
   - Remove ALL s6-overlay installation code
2. Remove the entire `rootfs/` directory (s6 init scripts)
3. Update go.mod dependencies for Go 1.23 compatibility

## Phase 4: Testing & Validation
1. Run all unit tests and ensure >90% coverage
2. Build the new Docker image and verify tini is present
3. Test integration scenarios from the upgrade plan
4. **Edge case testing** (from upgrade plan document):
   - Goroutine/thread monitoring
   - Zombie process verification: `ps aux | grep defunct`
   - Process group testing with pstree
   - Pdeathsig verification: `kill -9 $(pidof hera)`
   - Context cancellation during backoff
   - Concurrent Start/Stop operations

## Phase 5: Documentation
1. Update @CLAUDE.md with new architecture (remove all s6 references)
2. Update README.md if it exists
3. Document the new architecture with tini
</implementation-phases>

<instructions>
## Your Task
Implement the phases above systematically. For each phase:

1. **Read the upgrade plan FIRST**: @docs/upgrade-plan-s6-alpine.md contains complete, bug-free code
2. **Use TodoWrite tool** to track progress through all phases
3. **Copy code EXACTLY** from the upgrade plan - do NOT modify the bug fixes
4. **Read files first** before editing - use Read tool for @service.go, @tunnel.go, @Dockerfile
5. **Test frequently** - after each phase, verify the code compiles
6. **Use exact Dockerfile** from the plan - tini setup is critical

## DO NOT Improvise These Critical Parts

### ❌ DO NOT modify the supervise() implementation
The upgrade plan's supervise() function has been carefully designed to:
- Reuse ProcessState (prevents memory leaks)
- Check context cancellation (prevents goroutine leaks)
- Handle backoff with context support
- Restart with new cmd but same ProcessState

### ❌ DO NOT modify the Stop() implementation
The upgrade plan's Stop() function:
- Uses process groups (Setpgid)
- Kills entire process group with -pgid
- Always calls Wait() after Kill()

### ❌ DO NOT modify the Shutdown() implementation
Uses context cancellation and concurrent shutdown with timeout

### ❌ DO NOT modify the Dockerfile tini setup
The ENTRYPOINT must be: `["/sbin/tini", "--", "/bin/hera"]`
This makes tini PID 1, which forwards signals and reaps zombies

## Critical Implementation Requirements

### 1. Process Manager MUST Use Context
```go
type ProcessManager struct {
    processes map[string]*ProcessState
    mu        sync.RWMutex
    ctx       context.Context  // ✅ REQUIRED
    cancel    context.CancelFunc  // ✅ REQUIRED
}
```

### 2. Process Groups MUST Be Enabled
```go
cmd.SysProcAttr = &syscall.SysProcAttr{
    Pdeathsig: syscall.SIGTERM,
    Setpgid:   true,  // ✅ REQUIRED - creates process group
}
```

### 3. supervise() MUST Reuse ProcessState
```go
// ✅ CORRECT - from upgrade plan
ps.mu.Lock()
ps.cmd = cmd
ps.state = StateRunning
ps.mu.Unlock()
go pm.supervise(hostname, ps)  // Recursive with SAME ps

// ❌ WRONG - causes memory leak
pm.Start(hostname, ps.config)  // Creates NEW ProcessState
```

### 4. Always Wait() After Kill()
```go
// ✅ CORRECT
ps.cmd.Process.Kill()
ps.cmd.Wait()  // MUST call Wait() to reap zombie

// ❌ WRONG
ps.cmd.Process.Kill()
// Missing Wait() - process becomes zombie
```

### 5. Signal Handlers MUST Have Timeout
```go
// ✅ From upgrade plan - has timeout
select {
case <-done:
    log.Info("Shutdown complete")
case <-time.After(45 * time.Second):
    log.Error("Shutdown timeout, forcing exit")
}
```
</instructions>

<edge-cases-to-test>
Based on research, these edge cases MUST be tested:

1. **File Descriptor Leak Testing** ⚠️ CRITICAL
   ```bash
   # Monitor open file descriptors for log files
   lsof -p $(pidof hera) | grep -c ".log"

   # Force 100 restarts and verify FD count doesn't grow
   for i in {1..100}; do
       kill -9 $(pidof cloudflared)
       sleep 2
   done

   # Verify FD count is still reasonable (should be number of active tunnels)
   lsof -p $(pidof hera) | grep ".log"
   ```

2. **Thread/Goroutine Monitoring**
   ```bash
   # Monitor threads
   watch -n 1 'ls -l /proc/$(pidof hera)/task/ | wc -l'
   ```

3. **Zombie Process Verification**
   ```bash
   ps aux | grep defunct  # Should be empty
   ps -eo pid,ppid,comm,state | grep Z  # Should be empty
   ```

4. **Process Group Testing**
   ```bash
   pstree -p $(pidof hera)  # Verify process hierarchy
   ```

5. **Pdeathsig Verification**
   ```bash
   kill -9 $(pidof hera)  # Kill Hera ungracefully
   # Verify cloudflared processes exit (not orphaned)
   ```

6. **Restart Counter Reset Verification**
   ```bash
   # Start a tunnel, force 9 crashes quickly (< 5 min)
   # Let it run successfully for 5+ minutes
   # Force 9 more crashes
   # Verify it doesn't hit FATAL (counter should have reset)
   ```

7. **Context Cancellation**
   - Trigger shutdown during exponential backoff
   - Verify supervise goroutines exit immediately

8. **Concurrent Operations**
   - Start/stop 20 tunnels simultaneously
   - Verify no deadlocks or race conditions
</edge-cases-to-test>

<success-criteria>
When complete, verify ALL of these:
- [ ] All existing functionality works (tunnel creation, monitoring, stopping)
- [ ] No memory leaks over 24-hour test period
- [ ] Image size reduced by at least 40MB (target: ~57MB)
- [ ] **Zero zombie processes after 1000+ tunnel lifecycle events**
- [ ] Build time reduced (no s6-overlay download, tini from apk)
- [ ] All tests pass with >90% coverage
- [ ] No s6-related code remains in the codebase
- [ ] **tini is PID 1**: Verify with `docker exec <container> ps aux | head`
- [ ] **Graceful shutdown works**: `docker stop` completes in <30s
- [ ] **Exponential backoff works**: Failed processes don't spam restarts
- [ ] **Process groups work**: Children killed when parent stops
</success-criteria>

<tools-guidance>
- Use **Read** tool to view @docs/upgrade-plan-s6-alpine.md for complete code
- Use **Read** tool extensively to understand current implementation
- Use **Edit** tool for surgical changes to existing files
- Use **Write** tool only for new files (copy from upgrade plan)
- Use **Bash** tool for testing builds: `cd hera && docker build -t hera:test .`
- Use **Grep** tool to find all s6-related code that needs removal
- Use **TodoWrite** tool to track progress through all phases
- DO NOT use Task tool - implement systematically with full visibility
</tools-guidance>

<argument-handling>
$ARGUMENTS - Use this to specify which phase to focus on, or leave empty to start from Phase 1
</argument-handling>

Begin by reading @docs/upgrade-plan-s6-alpine.md thoroughly, create a comprehensive TodoWrite list for all phases, then start implementing Phase 1 using the EXACT code from the document.
