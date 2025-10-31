package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/op/go-logging"

	"hera/internal/process"
)

var log = logging.MustGetLogger("hera")
var processManager *process.ProcessManager

func main() {
	InitLogger("hera")

	// Initialize process manager
	processManager = process.NewProcessManager()

	// Setup graceful shutdown handler
	setupSignalHandlers()

	listener, err := NewListener()
	if err != nil {
		log.Fatalf("Unable to start: %s", err)
	}

	log.Infof("Hera v%s has started", CurrentVersion)

	err = VerifyCertificates(listener.Fs)
	if err != nil {
		log.Error(err.Error())
	}

	err = listener.Revive()
	if err != nil {
		log.Error(err.Error())
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
			log.Error(err.Error())
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
		log.Infof("Received signal %v, shutting down gracefully...", sig)

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
