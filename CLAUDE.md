# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

Hera is a Docker container monitoring service that automates the creation of Cloudflare Tunnels. It watches Docker container events and automatically creates/manages persistent tunnel connections using tini as PID 1 and native Go process management for cloudflared processes.

## Architecture

### Process Hierarchy

```
Container Start
    ↓
tini (PID 1) - handles signals, zombie reaping, orphan adoption
    ↓
Hera (PID 2) - Go application with process manager
    ↓
cloudflared processes (children of Hera)
```

### Core Flow

1. **main.go**: Entry point that initializes the logger, ProcessManager, signal handlers, creates a Listener, verifies certificates, revives existing tunnels, runs garbage collection, and starts the event listener
2. **logger.go**: Configures structured logging (slog) with JSON/text format, configurable log levels, writes to both stderr and file
3. **listener.go**: Manages Docker event listening, coordinates container event handling, and implements garbage collection for orphaned tunnels
4. **handler.go**: Processes container start/die events and orchestrates tunnel creation/destruction
5. **tunnel.go**: Core tunnel management - maintains a registry of active tunnels and handles their lifecycle, provides GC helper functions
6. **internal/process/manager.go**: Native Go process manager that supervises cloudflared processes with automatic restart, exponential backoff, and graceful shutdown
7. **certificate.go**: Manages Cloudflare certificate discovery and matching for hostnames

### Key Concepts

- **Container Discovery**: Hera only monitors containers with `hera.hostname` and `hera.port` labels
- **Hostname Resolution**: Uses net.LookupHost with retry logic (up to 5 attempts) to resolve container IPs
- **Certificate Matching**: Certificates must be named `<domain>.pem` (e.g., `mysite.com.pem`) and stored in `/certs`
- **Tunnel Registry**: In-memory map tracking active tunnels by hostname (tunnel.go:20)
- **Structured Logging**: Uses Go's slog for production-ready logging:
  - Configurable log levels (debug, info, warn, error) via `HERA_LOG_LEVEL`
  - JSON format (default) for log aggregation platforms (ELK, Datadog, Grafana Loki)
  - Text format option for human-readable console output with clean formatting
  - Colorized output in text mode for better readability (auto-detects TTY)
    - DEBUG: Gray, INFO: Blue, WARN: Yellow, ERROR: Red+Bold
  - Writes to both stderr (for `docker logs`) and file (`/var/log/hera/hera.log`)
  - All logs use key-value structured fields for machine parsing
  - Optional source file/line inclusion via `HERA_LOG_SOURCE`
- **Process Supervision**: Native Go ProcessManager supervises cloudflared processes with:
  - Automatic restart on failure with exponential backoff (1s, 2s, 4s, ... max 60s)
  - Reset restart counter after 5 minutes of stability
  - Fatal state after 10 consecutive failures
  - Process groups (Setpgid) to kill entire process tree
  - Pdeathsig to prevent orphans if Hera crashes
  - Context-based cancellation for clean shutdown
  - Proper zombie reaping (tini handles this as PID 1)
- **Config Location**: Tunnel configs stored in `/etc/hera/tunnels/` (changed from `/var/run/s6/services/`)
- **Log Location**: Tunnel logs stored in `/var/log/hera/`
- **Parallel Tunnel Revival**: Concurrent tunnel creation during startup for fast recovery:
  - Uses semaphore pattern with configurable concurrency limit (default: 20 concurrent tunnels)
  - Expected performance: 5 tunnels in ~5s, 100 tunnels in ~30s (vs 8 minutes sequential)
  - Individual timeout per tunnel (default: 30s) to prevent startup hangs
  - Graceful error handling with partial success support (continues even if some tunnels fail)
  - Comprehensive logging of success/failure metrics and timing
  - Thread-safe with existing registry mutexes
- **Garbage Collection**: Automatic cleanup of orphaned tunnels on startup with safety checks:
  - Only tunnels with zero connections and minimum age (10 min default)
  - Triple-check verification: Docker containers, local registry, ProcessManager state
  - Parallel processing per certificate for multi-domain setups
  - Configurable via environment variables (HERA_GC_ENABLED, HERA_GC_DRY_RUN, HERA_GC_MIN_AGE_MINUTES)
  - Thread-safe registry access with sync.RWMutex
  - Panic recovery and timeout handling (30s) on all cloudflared CLI calls

## Development Commands

### Building
```bash
make build          # Build Docker image
make test           # Run Go tests in builder container
```

### Running Locally
```bash
# Prerequisites
docker network create hera
mkdir -p .certs     # Add your *.pem files here

# Run Hera
make run            # Starts Hera with mounted Docker socket and certs
```

### Testing Tunnels
```bash
# Create a test tunnel (requires HOSTNAME env var)
HOSTNAME=mysite.com make tunnel
```

### Release
```bash
make release        # Build and push multi-arch image
```

## Testing

Tests are run in a Docker builder container:
- Unit tests: `*_test.go` files
- Run with: `docker run --rm -e CGO_ENABLED=0 hera-builder go test`
- Coverage includes: certificate matching, tunnel creation, service management, handler logic

## Important Constants

- Docker API Version: `v1.40` (client.go:13)
- Docker Socket: `unix:///var/run/docker.sock`
- Certificate Path: `/certs` (certificate.go:13)
- Config Path: `/etc/hera/tunnels` (tunnel.go:15)
- Log Path: `/var/log/hera` (tunnel.go:16)
- Init System: `tini` (installed at `/sbin/tini`)
- Go Version: `1.23` (go.mod:3)
- Alpine Version: `3.20` (Dockerfile)

## Configuration

### Container Labels

Containers must have these Docker labels:
- `hera.hostname`: The public hostname/domain for the tunnel
- `hera.port`: The internal container port to expose

### Environment Variables

**Logging configuration:**
- `HERA_LOG_LEVEL`: Set log verbosity - `debug`, `info`, `warn`, `error` (default: `info`)
- `HERA_LOG_FORMAT`: Output format - `json`, `text` (default: `json`)
  - `json`: Machine-readable format for log aggregation platforms (ELK, Datadog, Grafana Loki)
  - `text`: Human-readable colorized format with clean output: `2025-10-31T23:49:52Z INFO Message key=value`
- `HERA_LOG_COLOR`: Colorize console output - `auto`, `true`, `false` (default: `true` for text mode)
  - Default behavior: Colors enabled for text format, disabled for JSON
  - `auto`: Enable colors only if stderr is a TTY (terminal detection)
  - `true`: Always use colors (default for text format)
  - `false`: Never use colors (useful for log parsers or CI/CD)
- `HERA_LOG_SOURCE`: Include source file/line in logs - `true`, `false` (default: `false`)

**Garbage collection configuration:**
- `HERA_GC_ENABLED`: Enable/disable garbage collection (default: `true`)
- `HERA_GC_DRY_RUN`: Preview deletions without executing (default: `false`)
- `HERA_GC_MIN_AGE_MINUTES`: Minimum tunnel age before deletion in minutes (default: `10`, min: `1`)

**Parallel tunnel revival configuration:**
- `HERA_REVIVAL_CONCURRENCY`: Maximum concurrent tunnel revivals during startup (default: `20`, range: `1-100`)
  - Controls how many tunnels are created in parallel when Hera starts
  - Higher values = faster startup but may trigger Cloudflare rate limits
  - Recommended: 20 for most deployments, 10 for conservative setups, 50 for high-performance needs
- `HERA_REVIVAL_TIMEOUT`: Timeout per individual tunnel revival (default: `30s`)
  - Format: Go duration string (e.g., `30s`, `1m`, `90s`)
  - Minimum: `5s`, recommended: `30s` (6x normal creation time)
  - Prevents indefinite hangs during startup

## Dependencies

- **Docker SDK**: github.com/docker/docker (v24.0.7+)
- **tini**: Minimal init system for PID 1 (installed from Alpine packages)
- **cloudflared**: Cloudflare tunnel client (latest binary downloaded in Dockerfile)
- **afero**: Filesystem abstraction for testability
- **slog**: Go standard library structured logging (log/slog)

## Process Manager

The native Go process manager (`internal/process/manager.go`) provides:

- **State Machine**: Stopped → Starting → Running → Backoff → Fatal
- **Auto-restart**: Exponential backoff (1s, 2s, 4s, 8s, 16s, 32s, 60s max)
- **Stability Detection**: Restart counter resets after 5 minutes of successful operation
- **Process Groups**: Uses Setpgid to kill entire process tree
- **Orphan Prevention**: Pdeathsig ensures cloudflared dies if Hera crashes
- **Graceful Shutdown**: 10s timeout for SIGTERM, then SIGKILL
- **Context Cancellation**: Clean goroutine lifecycle management
- **File Descriptor Management**: Properly closes log files on restart/stop

## Go Module Setup

When modifying dependencies, update both go.mod and run `go mod tidy`. The Dockerfile now runs `go mod tidy` during build to ensure consistency.
