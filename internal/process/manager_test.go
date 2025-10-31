package process

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProcessManager_StartStop(t *testing.T) {
	pm := NewProcessManager()
	defer pm.Shutdown()

	// Create temp directory for test files
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	logPath := filepath.Join(tmpDir, "test.log")

	// Create a minimal config file
	if err := os.WriteFile(configPath, []byte("# test config"), 0644); err != nil {
		t.Fatalf("Failed to create config file: %v", err)
	}

	// Test starting a process (using a long-running command)
	config := &Config{
		ConfigPath: configPath,
		LogFile:    logPath,
	}

	// For testing, we'll use 'sleep' instead of cloudflared
	// In real tests, you'd mock exec.Command
	// This test verifies the structure works correctly

	// Note: This test would need proper mocking of exec.Command to work
	// For now, it serves as a structural example
	t.Skip("Skipping integration test - requires exec.Command mocking")
}

func TestProcessManager_GetState(t *testing.T) {
	pm := NewProcessManager()
	defer pm.Shutdown()

	// Test getting state for non-existent process
	_, err := pm.GetState("nonexistent")
	if err == nil {
		t.Error("Expected error for nonexistent process")
	}
}

func TestProcessManager_IsRunning(t *testing.T) {
	pm := NewProcessManager()
	defer pm.Shutdown()

	// Test IsRunning for non-existent process
	if pm.IsRunning("nonexistent") {
		t.Error("Expected false for nonexistent process")
	}
}

func TestProcessManager_ListProcesses(t *testing.T) {
	pm := NewProcessManager()
	defer pm.Shutdown()

	// Test listing processes when empty
	processes := pm.ListProcesses()
	if len(processes) != 0 {
		t.Errorf("Expected 0 processes, got %d", len(processes))
	}
}

func TestProcessManager_Shutdown(t *testing.T) {
	pm := NewProcessManager()

	// Test shutdown with no processes
	if err := pm.Shutdown(); err != nil {
		t.Errorf("Unexpected error during shutdown: %v", err)
	}

	// Verify context was cancelled
	select {
	case <-pm.ctx.Done():
		// Expected
	case <-time.After(1 * time.Second):
		t.Error("Expected context to be cancelled")
	}
}

func TestConfig_Validation(t *testing.T) {
	pm := NewProcessManager()
	defer pm.Shutdown()

	tests := []struct {
		name     string
		hostname string
		config   *Config
		wantErr  bool
	}{
		{
			name:     "empty hostname",
			hostname: "",
			config:   &Config{ConfigPath: "/tmp/config.yml", LogFile: "/tmp/log.txt"},
			wantErr:  true,
		},
		{
			name:     "nil config",
			hostname: "test",
			config:   nil,
			wantErr:  true,
		},
		{
			name:     "empty config path",
			hostname: "test",
			config:   &Config{ConfigPath: "", LogFile: "/tmp/log.txt"},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pm.Start(tt.hostname, tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("Start() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
