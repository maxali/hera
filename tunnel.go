package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/afero"
	"hera/internal/process"
)

var (
	registry         = make(map[string]*Tunnel)
	registryMu       sync.RWMutex // Protects registry from concurrent access
	tunnelConfigPath = "/etc/hera/tunnels"
	tunnelLogPath    = "/var/log/hera"
)

// Tunnel holds the corresponding config and certificate for a tunnel
type Tunnel struct {
	Config      *TunnelConfig
	Certificate *Certificate
}

// TunnelConfig holds the necessary configuration for a tunnel
type TunnelConfig struct {
	IP       string
	Hostname string
	Port     string
}

// NewTunnel returns a Tunnel with its corresponding config and certificate
func NewTunnel(config *TunnelConfig, certificate *Certificate) *Tunnel {
	tunnel := &Tunnel{
		Config:      config,
		Certificate: certificate,
	}

	return tunnel
}

// GetTunnelForHost returns the tunnel for a given hostname (thread-safe)
func GetTunnelForHost(hostname string) (*Tunnel, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()

	tunnel, ok := registry[hostname]
	if !ok {
		return nil, fmt.Errorf("No tunnel exists for %s", hostname)
	}
	return tunnel, nil
}

// RegisterTunnel adds a tunnel to the registry (thread-safe)
func RegisterTunnel(hostname string, tunnel *Tunnel) error {
	registryMu.Lock()
	defer registryMu.Unlock()

	_, ok := registry[hostname]
	if ok {
		return fmt.Errorf("Tunnel already exists for %s", hostname)
	}
	registry[hostname] = tunnel
	return nil
}

// DeregisterTunnel removes a tunnel from the registry (thread-safe)
func DeregisterTunnel(hostname string) error {
	registryMu.Lock()
	defer registryMu.Unlock()

	_, ok := registry[hostname]
	if !ok {
		return fmt.Errorf("No tunnel registered for %s", hostname)
	}
	delete(registry, hostname)
	return nil
}

// Start starts a tunnel and registers it
func (t *Tunnel) Start() error {
	log.Infof("Starting tunnel for %s", t.Config.Hostname)

	// Create config directory if it doesn't exist
	err := os.MkdirAll(tunnelConfigPath, 0755)
	if err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create log directory if it doesn't exist
	err = os.MkdirAll(tunnelLogPath, 0755)
	if err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Write config file
	err = t.writeConfigFile()
	if err != nil {
		return err
	}

	// Start the process using ProcessManager
	config := &process.Config{
		ConfigPath: t.ConfigFilePath(),
		LogFile:    t.LogFilePath(),
	}

	err = processManager.Start(t.Config.Hostname, config)
	if err != nil {
		return fmt.Errorf("failed to start process for %s: %w", t.Config.Hostname, err)
	}

	// Register the tunnel
	err = RegisterTunnel(t.Config.Hostname, t)
	if err != nil {
		// If registration fails, stop the process
		processManager.Stop(t.Config.Hostname)
		return err
	}

	// Create DNS route for the tunnel
	err = t.createDNSRoute()
	if err != nil {
		log.Errorf("Failed to create DNS route for %s: %v", t.Config.Hostname, err)
		// Don't fail the entire start process if DNS route creation fails
		// The tunnel is already running and can be manually routed
	}

	return nil
}

// Stop stops a tunnel and deregisters it
func (t *Tunnel) Stop() error {
	log.Infof("Stopping tunnel for %s", t.Config.Hostname)

	// Stop the process
	err := processManager.Stop(t.Config.Hostname)
	if err != nil {
		log.Errorf("Failed to stop process for %s: %v", t.Config.Hostname, err)
	}

	// Delete the tunnel and its DNS route from Cloudflare
	err = t.deleteTunnelAndRoute()
	if err != nil {
		log.Errorf("Failed to delete tunnel from Cloudflare for %s: %v", t.Config.Hostname, err)
	}

	// Remove config file
	configFile := t.ConfigFilePath()
	if _, err := os.Stat(configFile); err == nil {
		os.Remove(configFile)
	}

	// Deregister the tunnel
	err = DeregisterTunnel(t.Config.Hostname)
	if err != nil {
		return err
	}

	return nil
}

// deleteTunnelAndRoute deletes the tunnel and its DNS route from Cloudflare
func (t *Tunnel) deleteTunnelAndRoute() error {
	// First, try to delete the DNS route
	// The DNS route must be deleted before the tunnel can be deleted
	log.Debugf("Attempting to delete DNS route for %s", t.Config.Hostname)

	// Delete DNS route using cloudflared
	// Note: cloudflared doesn't have a direct "unroute" command,
	// but deleting the tunnel will also clean up the CNAME

	// Check if tunnel exists before attempting deletion
	tunnelExists, tunnelUUID := t.checkTunnelExists()
	if !tunnelExists {
		log.Debugf("Tunnel %s doesn't exist in Cloudflare, skipping deletion", t.Config.Hostname)
		return nil
	}

	// Delete the tunnel using cloudflared
	// This will also remove the associated CNAME record
	cmd := exec.Command("cloudflared",
		"--origincert", t.Certificate.FullPath(),
		"tunnel", "delete",
		t.Config.Hostname) // Use tunnel name for deletion

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if error is because tunnel is already deleted
		outputStr := string(output)
		if strings.Contains(outputStr, "not found") || strings.Contains(outputStr, "does not exist") {
			log.Debugf("Tunnel %s already deleted or doesn't exist", t.Config.Hostname)
			return nil
		}
		return fmt.Errorf("failed to delete tunnel %s: %v, output: %s", t.Config.Hostname, err, outputStr)
	}

	log.Infof("Successfully deleted tunnel %s (UUID: %s) from Cloudflare", t.Config.Hostname, tunnelUUID)
	return nil
}

// writeConfigFile creates the config file for a tunnel
func (t *Tunnel) writeConfigFile() error {
	// Check if tunnel already exists and handle accordingly
	tunnelExists, tunnelUUID := t.checkTunnelExists()

	var contents string

	if tunnelExists && tunnelUUID != "" {
		// Tunnel exists - use the UUID directly with ingress rules
		// This works even without credential files
		configLines := []string{
			"tunnel: %s",
			"origincert: %s",
			"logfile: %s",
			"no-autoupdate: true",
			"",
			"ingress:",
			"  - hostname: %s",
			"    service: http://%s:%s",
			"  - service: http_status:404",
		}

		contents = fmt.Sprintf(strings.Join(configLines, "\n"),
			tunnelUUID,  // Use UUID instead of name for existing tunnels
			t.Certificate.FullPath(),
			t.LogFilePath(),
			t.Config.Hostname,
			t.Config.IP,
			t.Config.Port)
	} else {
		// Tunnel doesn't exist - let cloudflared create it with proper ingress rules
		configLines := []string{
			"tunnel: %s",
			"origincert: %s",
			"logfile: %s",
			"no-autoupdate: true",
			"",
			"ingress:",
			"  - hostname: %s",
			"    service: http://%s:%s",
			"  - service: http_status:404",
		}

		contents = fmt.Sprintf(strings.Join(configLines, "\n"),
			t.Config.Hostname,  // Use name for new tunnels (will auto-create)
			t.Certificate.FullPath(),
			t.LogFilePath(),
			t.Config.Hostname,
			t.Config.IP,
			t.Config.Port)
	}

	// Use afero.NewOsFs() directly since we're working with real filesystem
	fs := afero.NewOsFs()
	err := afero.WriteFile(fs, t.ConfigFilePath(), []byte(contents), 0644)
	if err != nil {
		return err
	}

	return nil
}

// checkTunnelExists checks if a tunnel with this name exists in Cloudflare
// Returns (exists bool, uuid string)
func (t *Tunnel) checkTunnelExists() (bool, string) {
	// Use cloudflared tunnel list to check if tunnel exists
	cmd := exec.Command("cloudflared", "--origincert", t.Certificate.FullPath(), "tunnel", "list", "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		log.Debugf("Failed to list tunnels: %v", err)
		return false, ""
	}

	// Parse JSON output
	var tunnels []map[string]interface{}
	if err := json.Unmarshal(output, &tunnels); err != nil {
		log.Debugf("Failed to parse tunnel list: %v", err)
		return false, ""
	}

	// Look for our tunnel by name
	for _, tunnel := range tunnels {
		if name, ok := tunnel["name"].(string); ok && name == t.Config.Hostname {
			if id, ok := tunnel["id"].(string); ok {
				log.Infof("Found existing tunnel %s with UUID %s", t.Config.Hostname, id)
				return true, id
			}
		}
	}

	return false, ""
}

// createDNSRoute creates or updates the DNS route for this tunnel
func (t *Tunnel) createDNSRoute() error {
	// Check if tunnel exists to get its name or UUID
	tunnelExists, tunnelUUID := t.checkTunnelExists()

	var tunnelIdentifier string
	if tunnelExists && tunnelUUID != "" {
		// Use UUID for existing tunnels
		tunnelIdentifier = tunnelUUID
		log.Infof("Creating DNS route for existing tunnel %s (UUID: %s)", t.Config.Hostname, tunnelUUID)
	} else {
		// Use hostname for new tunnels
		tunnelIdentifier = t.Config.Hostname
		log.Infof("Creating DNS route for new tunnel %s", t.Config.Hostname)
	}

	// Create DNS route using cloudflared
	// --overwrite-dns ensures it updates existing records if present
	cmd := exec.Command("cloudflared",
		"--origincert", t.Certificate.FullPath(),
		"tunnel", "route", "dns",
		"--overwrite-dns",
		tunnelIdentifier,  // tunnel name or UUID
		t.Config.Hostname) // hostname to route

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create DNS route: %v, output: %s", err, string(output))
	}

	log.Infof("Successfully created DNS route for %s: %s", t.Config.Hostname, string(output))
	return nil
}

// ConfigFilePath returns the path to the config file for the tunnel
func (t *Tunnel) ConfigFilePath() string {
	return filepath.Join(tunnelConfigPath, fmt.Sprintf("%s.yml", t.Config.Hostname))
}

// LogFilePath returns the path to the log file for the tunnel
func (t *Tunnel) LogFilePath() string {
	return filepath.Join(tunnelLogPath, fmt.Sprintf("%s.log", t.Config.Hostname))
}

// TunnelInfo holds basic tunnel information from Cloudflare
type TunnelInfo struct {
	ID          string
	Name        string
	Connections int       // Count of active connections
	CreatedAt   time.Time
	DeletedAt   time.Time // Non-zero if tunnel is deleted
}

// Connection represents a single tunnel connection from Cloudflare
type Connection struct {
	ColoName           string `json:"colo_name"`
	ID                 string `json:"id"`
	IsPendingReconnect bool   `json:"is_pending_reconnect"`
	OriginIP           string `json:"origin_ip"`
	OpenedAt           string `json:"opened_at"`
}

// TunnelListResponse matches the actual JSON structure from cloudflared
// Based on verified output from: cloudflared tunnel list --output json
type TunnelListResponse struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	CreatedAt   string       `json:"created_at"`
	DeletedAt   string       `json:"deleted_at"`
	Connections []Connection `json:"connections"`
}

// ListAllCloudflaredTunnels queries Cloudflare for all tunnels
// Returns only active (non-deleted) tunnels with proper error handling
func ListAllCloudflaredTunnels(certPath string) ([]TunnelInfo, error) {
	// Create context with 30-second timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "cloudflared",
		"--origincert", certPath,
		"tunnel", "list",
		"--output", "json")

	output, err := cmd.Output()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("cloudflared tunnel list timed out after 30s")
		}
		return nil, fmt.Errorf("failed to list tunnels: %w", err)
	}

	// Use strongly-typed struct for JSON parsing
	var rawTunnels []TunnelListResponse
	if err := json.Unmarshal(output, &rawTunnels); err != nil {
		return nil, fmt.Errorf("failed to parse tunnel list: %w", err)
	}

	tunnels := make([]TunnelInfo, 0, len(rawTunnels))
	for _, raw := range rawTunnels {
		tunnel := TunnelInfo{
			ID:          raw.ID,
			Name:        raw.Name,
			Connections: len(raw.Connections),
		}

		// Parse created_at timestamp (RFC3339 format) - REQUIRED for age check
		if raw.CreatedAt != "" && raw.CreatedAt != "0001-01-01T00:00:00Z" {
			t, err := time.Parse(time.RFC3339, raw.CreatedAt)
			if err != nil {
				log.Warningf("Failed to parse created_at for tunnel %s: %v - SKIPPING for safety", raw.Name, err)
				// CRITICAL: Skip tunnels with unparseable timestamps to prevent bypassing age check
				continue
			}
			tunnel.CreatedAt = t
		} else {
			// CRITICAL: Skip tunnels without valid created_at to prevent bypassing age check
			log.Warningf("Tunnel %s has no valid created_at timestamp - SKIPPING for safety", raw.Name)
			continue
		}

		// Check if tunnel is deleted using robust detection
		// A tunnel is deleted if deleted_at is set to a real timestamp (not zero time)
		if raw.DeletedAt != "" && raw.DeletedAt != "0001-01-01T00:00:00Z" {
			t, err := time.Parse(time.RFC3339, raw.DeletedAt)
			if err == nil && !t.IsZero() && t.Year() > 1 {
				tunnel.DeletedAt = t
				// Skip deleted tunnels - they're already cleaned up
				log.Debugf("Skipping deleted tunnel %s (deleted at %s)",
					raw.Name, raw.DeletedAt)
				continue
			}
		}

		tunnels = append(tunnels, tunnel)
	}

	return tunnels, nil
}

// DeleteTunnelByName deletes a tunnel from Cloudflare
// Idempotent: returns success if tunnel doesn't exist
// NOTE: tunnelName and certPath come from trusted sources (Cloudflare API and local filesystem)
// but input validation is added for defense in depth (Issue #27)
func DeleteTunnelByName(tunnelName string, certPath string) error {
	// Validate inputs to prevent command injection (defense in depth)
	if tunnelName == "" || strings.Contains(tunnelName, "..") || strings.ContainsAny(tunnelName, ";&|`$") {
		return fmt.Errorf("invalid tunnel name: %s", tunnelName)
	}
	if certPath == "" || strings.Contains(certPath, "..") {
		return fmt.Errorf("invalid certificate path: %s", certPath)
	}

	// Create context with 30-second timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "cloudflared",
		"--origincert", certPath,
		"tunnel", "delete",
		"-f", // Force delete without confirmation
		tunnelName)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("cloudflared tunnel delete timed out after 30s for %s", tunnelName)
		}
		outputStr := string(output)
		// Idempotent: treat "already deleted" as success
		if strings.Contains(outputStr, "not found") ||
			strings.Contains(outputStr, "does not exist") {
			log.Debugf("Tunnel %s already deleted", tunnelName)
			return nil
		}
		return fmt.Errorf("failed to delete tunnel %s: %w, output: %s",
			tunnelName, err, outputStr)
	}

	log.Infof("Deleted orphaned tunnel: %s", tunnelName)
	return nil
}