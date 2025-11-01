package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"hera/internal/process"
)

var processManager *process.ProcessManager

func main() {
	InitLogger("hera")

	// Initialize process manager
	processManager = process.NewProcessManager()

	// Setup graceful shutdown handler
	setupSignalHandlers()

	listener, err := NewListener()
	if err != nil {
		log.Error("Unable to start", "error", err)
		os.Exit(1)
	}

	log.Info("Hera has started", "version", CurrentVersion)
	log.Info("Tunnel name prefix: 'hera-' (only tunnels with this prefix will be managed)")

	err = VerifyCertificates(listener.Fs)
	if err != nil {
		log.Error("Certificate verification failed", "error", err)
	}

	err = listener.Revive()
	if err != nil {
		log.Error("Failed to revive tunnels", "error", err)
	}

	// Run garbage collection for orphaned tunnels
	// Check if GC is enabled (default: enabled)
	gcEnabled := os.Getenv("HERA_GC_ENABLED")
	if gcEnabled != "false" {
		// Check for dry-run mode
		if os.Getenv("HERA_GC_DRY_RUN") == "true" {
			log.Info("Running garbage collection in DRY-RUN mode (no tunnels will be deleted)")
		}

		err = listener.GarbageCollectOrphanedTunnels()
		if err != nil {
			log.Error("Garbage collection failed", "error", err)
			// Don't fail startup on GC errors
		}
	} else {
		log.Info("Garbage collection disabled via HERA_GC_ENABLED=false")
	}

	listener.Listen()
}

func setupSignalHandlers() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigChan
		log.Info("Received shutdown signal, shutting down gracefully...", "signal", sig)

		// Stop all tunnels with timeout
		done := make(chan struct{})
		go func() {
			if processManager != nil {
				processManager.Shutdown()
			}
			close(done)
		}()

		// Wait max 45 seconds for graceful shutdown
		select {
		case <-done:
			log.Info("Shutdown complete")
		case <-time.After(45 * time.Second):
			log.Error("Shutdown timeout, forcing exit")
		}

		os.Exit(0)
	}()
}
