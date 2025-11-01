package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/afero"
	"golang.org/x/net/publicsuffix"
	"hera/internal/process"
)

var (
	registry         = make(map[string]*Tunnel)
	registryMu       sync.RWMutex // Protects registry from concurrent access
	tunnelConfigPath = "/etc/hera/tunnels"
	tunnelLogPath    = "/var/log/hera"

	// Tunnel naming prefix to identify Hera-managed tunnels
	tunnelNamePrefix = "hera-"

	// Zone ID cache for DNS operations
	zoneIDCache   = make(map[string]string) // domain -> zone_id
	zoneIDCacheMu sync.RWMutex              // Protects zone ID cache
)

// getTunnelName returns the full tunnel name with Hera prefix
// Normalizes hostname to lowercase for consistency
func getTunnelName(hostname string) string {
	if hostname == "" {
		log.Warn("getTunnelName called with empty hostname")
		return tunnelNamePrefix
	}
	// Normalize to lowercase to prevent case-sensitivity issues
	normalized := strings.ToLower(hostname)
	// Warn if hostname already has the prefix
	if strings.HasPrefix(normalized, tunnelNamePrefix) {
		log.Warn("Hostname already has 'hera-' prefix", "hostname", hostname, "tunnel_name", tunnelNamePrefix+normalized)
	}
	return tunnelNamePrefix + normalized
}

// getHostnameFromTunnelName extracts the original hostname from a prefixed tunnel name
func getHostnameFromTunnelName(tunnelName string) string {
	return strings.TrimPrefix(tunnelName, tunnelNamePrefix)
}

// isHeraTunnel checks if a tunnel name was created by Hera
func isHeraTunnel(tunnelName string) bool {
	return strings.HasPrefix(tunnelName, tunnelNamePrefix) &&
		len(tunnelName) > len(tunnelNamePrefix)
}

// Tunnel holds the corresponding config and certificate for a tunnel
type Tunnel struct {
	Config            *TunnelConfig
	Certificate       *Certificate
	DNSCleanupEnabled bool // Whether to clean up DNS records on tunnel deletion
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
	tunnelName := getTunnelName(t.Config.Hostname)
	log.Info("Starting tunnel", "tunnel_name", tunnelName, "hostname", t.Config.Hostname)

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
		log.Error("Failed to create DNS route", "hostname", t.Config.Hostname, "error", err)
		// Don't fail the entire start process if DNS route creation fails
		// The tunnel is already running and can be manually routed
	}

	return nil
}

// Stop stops a tunnel and deregisters it
func (t *Tunnel) Stop() error {
	log.Info("Stopping tunnel", "hostname", t.Config.Hostname)

	// Stop the process
	log.Info("Step 1/4: Stopping cloudflared process", "hostname", t.Config.Hostname)
	err := processManager.Stop(t.Config.Hostname)
	if err != nil {
		log.Error("Failed to stop process", "hostname", t.Config.Hostname, "error", err)
	} else {
		log.Info("Successfully stopped cloudflared process", "hostname", t.Config.Hostname)
	}

	// Delete the tunnel and its DNS route from Cloudflare
	log.Info("Step 2/4: Deleting tunnel from Cloudflare", "hostname", t.Config.Hostname)
	err = t.deleteTunnelAndRoute()
	if err != nil {
		log.Error("Failed to delete tunnel from Cloudflare", "hostname", t.Config.Hostname, "error", err)
		// Continue with cleanup even if Cloudflare deletion fails
	} else {
		log.Info("Successfully deleted tunnel from Cloudflare", "hostname", t.Config.Hostname)
	}

	// Remove config file
	log.Info("Step 3/4: Removing config file", "hostname", t.Config.Hostname)
	configFile := t.ConfigFilePath()
	if _, err := os.Stat(configFile); err == nil {
		if err := os.Remove(configFile); err != nil {
			log.Error("Failed to remove config file", "hostname", t.Config.Hostname, "error", err)
		} else {
			log.Info("Successfully removed config file", "hostname", t.Config.Hostname)
		}
	}

	// Deregister the tunnel
	log.Info("Step 4/4: Deregistering tunnel from registry", "hostname", t.Config.Hostname)
	err = DeregisterTunnel(t.Config.Hostname)
	if err != nil {
		log.Error("Failed to deregister tunnel", "hostname", t.Config.Hostname, "error", err)
		return err
	}

	log.Info("Successfully completed all stop steps", "hostname", t.Config.Hostname)
	return nil
}

// deleteTunnelAndRoute deletes the tunnel and its DNS route from Cloudflare
func (t *Tunnel) deleteTunnelAndRoute() error {
	log.Info("Attempting to delete tunnel and DNS route from Cloudflare", "hostname", t.Config.Hostname)

	// Step 1: Clean up DNS record using Cloudflare API (if enabled)
	// This must happen BEFORE tunnel deletion because cloudflared doesn't remove DNS records
	log.Info("Step 1: Attempting DNS record cleanup", "hostname", t.Config.Hostname)
	err := t.cleanupDNSRecord()
	if err != nil {
		// Log error but continue with tunnel deletion
		log.Warn("DNS cleanup failed - continuing with tunnel deletion", "hostname", t.Config.Hostname, "error", err)
	}

	// Step 2: Delete the tunnel using cloudflared
	// Note: cloudflared tunnel delete does NOT remove DNS records automatically

	// Delete DNS route using cloudflared
	// Note: cloudflared doesn't have a direct "unroute" command,
	// but deleting the tunnel will also clean up the CNAME

	// Check if tunnel exists before attempting deletion
	log.Info("Checking if tunnel exists in Cloudflare", "hostname", t.Config.Hostname)
	tunnelExists, tunnelUUID := t.checkTunnelExists()
	if !tunnelExists {
		log.Info("Tunnel doesn't exist in Cloudflare, skipping deletion", "hostname", t.Config.Hostname)
		return nil
	}

	log.Info("Tunnel exists in Cloudflare, proceeding with deletion", "hostname", t.Config.Hostname, "uuid", tunnelUUID)

	// Delete the tunnel using cloudflared
	// This will also remove the associated CNAME record
	// CRITICAL: Must use UUID, not hostname, for deletion
	cmd := exec.Command("cloudflared",
		"--origincert", t.Certificate.FullPath(),
		"tunnel", "delete",
		"-f", // Force delete without confirmation
		tunnelUUID) // Use UUID instead of name for deletion

	log.Info("Executing cloudflared delete", "cert", t.Certificate.FullPath(), "uuid", tunnelUUID)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if error is because tunnel is already deleted
		outputStr := string(output)
		log.Error("cloudflared delete command failed", "error", err, "output", outputStr)
		if strings.Contains(outputStr, "not found") || strings.Contains(outputStr, "does not exist") {
			log.Info("Tunnel already deleted or doesn't exist (treating as success)", "hostname", t.Config.Hostname)
			return nil
		}
		return fmt.Errorf("failed to delete tunnel %s: %v, output: %s", t.Config.Hostname, err, outputStr)
	}

	log.Info("Successfully deleted tunnel from Cloudflare", "hostname", t.Config.Hostname, "uuid", tunnelUUID, "output", string(output))
	return nil
}

// writeConfigFile creates the config file for a tunnel
func (t *Tunnel) writeConfigFile() error {
	// Check if tunnel already exists and handle accordingly
	tunnelExists, tunnelUUID := t.checkTunnelExists()

	var contents string

	tunnelName := getTunnelName(t.Config.Hostname)

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
			t.Config.Hostname,  // Use original hostname for DNS routing
			t.Config.IP,
			t.Config.Port)
	} else {
		// Tunnel doesn't exist - create it first
		log.Info("Tunnel doesn't exist in Cloudflare, creating it", "tunnel_name", tunnelName)
		err := t.createTunnel()
		if err != nil {
			return fmt.Errorf("failed to create tunnel in Cloudflare: %w", err)
		}
		log.Info("Successfully created tunnel in Cloudflare", "tunnel_name", tunnelName)

		// Now write config with the prefixed tunnel name
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
			tunnelName,          // Use prefixed name for tunnel
			t.Certificate.FullPath(),
			t.LogFilePath(),
			t.Config.Hostname,  // Use original hostname for DNS routing
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
// Supports backward compatibility: checks for both prefixed (hera-) and legacy (unprefixed) tunnels
// Uses cloudflared tunnel info for O(1) direct lookup (much faster than listing all tunnels)
func (t *Tunnel) checkTunnelExists() (bool, string) {
	// Priority 1: Try prefixed tunnel name first (new format)
	tunnelName := getTunnelName(t.Config.Hostname)
	exists, uuid := t.checkSingleTunnelExists(tunnelName)
	if exists {
		log.Info("Found existing tunnel", "tunnel_name", tunnelName, "uuid", uuid)
		return true, uuid
	}

	// Priority 2: Fallback to legacy unprefixed tunnel name for backward compatibility
	// This allows Hera to adopt existing tunnels created before the prefix was added
	exists, uuid = t.checkSingleTunnelExists(t.Config.Hostname)
	if exists {
		log.Warn("Found legacy tunnel without prefix - will use it but consider migrating", "name", t.Config.Hostname, "uuid", uuid)
		log.Warn("To migrate, delete the old tunnel and restart the container", "command", fmt.Sprintf("cloudflared tunnel delete %s", t.Config.Hostname))
		return true, uuid
	}

	return false, ""
}

// checkSingleTunnelExists checks if a specific tunnel name exists using cloudflared tunnel info
// Returns (exists bool, uuid string)
// This is O(1) lookup compared to O(N) for listing all tunnels
func (t *Tunnel) checkSingleTunnelExists(tunnelName string) (bool, string) {
	// Create context with 30-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use cloudflared tunnel info for direct O(1) lookup
	cmd := exec.CommandContext(ctx, "cloudflared",
		"--origincert", t.Certificate.FullPath(),
		"tunnel", "info",
		tunnelName,
		"--output", "json")

	output, err := cmd.Output()
	if err != nil {
		// Tunnel doesn't exist or other error occurred
		if ctx.Err() == context.DeadlineExceeded {
			log.Warn("Tunnel info lookup timed out", "tunnel_name", tunnelName)
		} else {
			log.Debug("Tunnel does not exist", "tunnel_name", tunnelName)
		}
		return false, ""
	}

	// Parse JSON output matching cloudflared tunnel info response structure
	var tunnelInfo struct {
		ID        string        `json:"id"`
		Name      string        `json:"name"`
		CreatedAt string        `json:"createdAt"`
		Conns     []interface{} `json:"conns"`
	}

	if err := json.Unmarshal(output, &tunnelInfo); err != nil {
		log.Debug("Failed to parse tunnel info", "tunnel_name", tunnelName, "error", err)
		return false, ""
	}

	// Verify we got a valid tunnel ID
	if tunnelInfo.ID == "" {
		log.Debug("Tunnel info returned empty ID", "tunnel_name", tunnelName)
		return false, ""
	}

	return true, tunnelInfo.ID
}

// createTunnel creates a new tunnel in Cloudflare using cloudflared CLI
func (t *Tunnel) createTunnel() error {
	// Create context with 30-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Use prefixed tunnel name
	tunnelName := getTunnelName(t.Config.Hostname)

	// Execute: cloudflared --origincert <cert> tunnel create <tunnel-name>
	cmd := exec.CommandContext(ctx, "cloudflared",
		"--origincert", t.Certificate.FullPath(),
		"tunnel", "create",
		tunnelName)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("tunnel creation timed out after 30s")
		}
		outputStr := string(output)
		// Check if tunnel already exists (race condition with another process)
		if strings.Contains(outputStr, "already exists") || strings.Contains(outputStr, "A tunnel with that name already exists") {
			log.Info("Tunnel already exists (created by another process)", "tunnel_name", tunnelName)
			return nil
		}
		return fmt.Errorf("cloudflared tunnel create failed: %v, output: %s", err, outputStr)
	}

	log.Info("Tunnel creation output", "output", string(output))
	return nil
}

// createDNSRoute creates or updates the DNS route for this tunnel
func (t *Tunnel) createDNSRoute() error {
	// Check if tunnel exists to get its name or UUID
	tunnelExists, tunnelUUID := t.checkTunnelExists()

	tunnelName := getTunnelName(t.Config.Hostname)

	var tunnelIdentifier string
	if tunnelExists && tunnelUUID != "" {
		// Use UUID for existing tunnels
		tunnelIdentifier = tunnelUUID
		log.Info("Creating DNS route for existing tunnel", "tunnel_name", tunnelName, "uuid", tunnelUUID)
	} else {
		// Use prefixed tunnel name for new tunnels
		tunnelIdentifier = tunnelName
		log.Info("Creating DNS route for new tunnel", "tunnel_name", tunnelName)
	}

	// Create DNS route using cloudflared
	// --overwrite-dns ensures it updates existing records if present
	cmd := exec.Command("cloudflared",
		"--origincert", t.Certificate.FullPath(),
		"tunnel", "route", "dns",
		"--overwrite-dns",
		tunnelIdentifier,  // tunnel name or UUID (with hera- prefix)
		t.Config.Hostname) // hostname to route (original hostname without prefix)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create DNS route: %v, output: %s", err, string(output))
	}

	log.Info("Successfully created DNS route", "hostname", t.Config.Hostname, "output", string(output))
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
				log.Warn("Failed to parse created_at for tunnel - SKIPPING for safety", "tunnel", raw.Name, "error", err)
				// CRITICAL: Skip tunnels with unparseable timestamps to prevent bypassing age check
				continue
			}
			tunnel.CreatedAt = t
		} else {
			// CRITICAL: Skip tunnels without valid created_at to prevent bypassing age check
			log.Warn("Tunnel has no valid created_at timestamp - SKIPPING for safety", "tunnel", raw.Name)
			continue
		}

		// Check if tunnel is deleted using robust detection
		// A tunnel is deleted if deleted_at is set to a real timestamp (not zero time)
		if raw.DeletedAt != "" && raw.DeletedAt != "0001-01-01T00:00:00Z" {
			t, err := time.Parse(time.RFC3339, raw.DeletedAt)
			if err == nil && !t.IsZero() && t.Year() > 1 {
				tunnel.DeletedAt = t
				// Skip deleted tunnels - they're already cleaned up
				log.Debug("Skipping deleted tunnel", "tunnel", raw.Name, "deleted_at", raw.DeletedAt)
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
			log.Debug("Tunnel already deleted", "tunnel", tunnelName)
			return nil
		}
		return fmt.Errorf("failed to delete tunnel %s: %w, output: %s",
			tunnelName, err, outputStr)
	}

	log.Info("Deleted orphaned tunnel", "tunnel", tunnelName)
	return nil
}

// ============================================
// DNS Record Cleanup Functions (Cloudflare API)
// ============================================

// CloudflareZoneResponse represents the response from Cloudflare zones API
type CloudflareZoneResponse struct {
	Result []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"result"`
	Success bool `json:"success"`
}

// CloudflareDNSRecordResponse represents the response from Cloudflare DNS records API
type CloudflareDNSRecordResponse struct {
	Result []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		Name string `json:"name"`
	} `json:"result"`
	Success bool `json:"success"`
}

// CloudflareDeleteResponse represents the response from Cloudflare delete API
type CloudflareDeleteResponse struct {
	Result struct {
		ID string `json:"id"`
	} `json:"result"`
	Success bool `json:"success"`
}

// getZoneID retrieves the zone ID for a domain from Cloudflare API
// Results are cached to avoid repeated API calls
func getZoneID(domain string, apiToken string) (string, error) {
	// Check cache first
	zoneIDCacheMu.RLock()
	if zoneID, ok := zoneIDCache[domain]; ok {
		zoneIDCacheMu.RUnlock()
		log.Debug("Using cached zone ID", "domain", domain, "zone_id", zoneID)
		return zoneID, nil
	}
	zoneIDCacheMu.RUnlock()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Build API request
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones?name=%s", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiToken))
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get zone ID: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var zoneResp CloudflareZoneResponse
	if err := json.Unmarshal(body, &zoneResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if !zoneResp.Success || len(zoneResp.Result) == 0 {
		return "", fmt.Errorf("zone not found for domain %s", domain)
	}

	zoneID := zoneResp.Result[0].ID

	// Cache the result
	zoneIDCacheMu.Lock()
	zoneIDCache[domain] = zoneID
	zoneIDCacheMu.Unlock()

	log.Info("Retrieved zone ID", "domain", domain, "zone_id", zoneID)
	return zoneID, nil
}

// getDNSRecordID retrieves the DNS record ID for a hostname from Cloudflare API
func getDNSRecordID(zoneID, hostname, apiToken string) (string, error) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Build API request
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?type=CNAME&name=%s", zoneID, hostname)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiToken))
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to get DNS records: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var dnsResp CloudflareDNSRecordResponse
	if err := json.Unmarshal(body, &dnsResp); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	if !dnsResp.Success || len(dnsResp.Result) == 0 {
		return "", fmt.Errorf("DNS record not found for hostname %s", hostname)
	}

	recordID := dnsResp.Result[0].ID
	log.Info("Found DNS record ID", "hostname", hostname, "record_id", recordID)
	return recordID, nil
}

// deleteDNSRecord deletes a DNS record from Cloudflare
func deleteDNSRecord(zoneID, recordID, apiToken string) error {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Build API request
	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recordID)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", apiToken))
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete DNS record: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var deleteResp CloudflareDeleteResponse
	if err := json.Unmarshal(body, &deleteResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if !deleteResp.Success {
		return fmt.Errorf("failed to delete DNS record")
	}

	log.Info("Successfully deleted DNS record", "record_id", recordID)
	return nil
}

// cleanupDNSRecord attempts to delete the DNS record for this tunnel from Cloudflare
// Returns error only for critical failures; logs warnings for non-critical issues
func (t *Tunnel) cleanupDNSRecord() error {
	// Check if DNS cleanup is enabled for this tunnel
	if !t.DNSCleanupEnabled {
		log.Debug("DNS cleanup disabled, skipping", "hostname", t.Config.Hostname)
		return nil
	}

	// Check if API token is available
	apiToken := os.Getenv("CLOUDFLARE_API_TOKEN")
	if apiToken == "" {
		log.Warn("CLOUDFLARE_API_TOKEN not set, skipping DNS cleanup", "hostname", t.Config.Hostname)
		return nil
	}

	log.Info("Starting DNS cleanup", "hostname", t.Config.Hostname)

	// Get root domain for zone lookup
	domain, err := publicsuffix.EffectiveTLDPlusOne(t.Config.Hostname)
	if err != nil {
		log.Warn("Failed to extract root domain - skipping DNS cleanup", "hostname", t.Config.Hostname, "error", err)
		return nil
	}

	// Get zone ID
	zoneID, err := getZoneID(domain, apiToken)
	if err != nil {
		log.Warn("Failed to get zone ID - skipping DNS cleanup", "domain", domain, "error", err)
		return nil
	}

	// Get DNS record ID
	recordID, err := getDNSRecordID(zoneID, t.Config.Hostname, apiToken)
	if err != nil {
		log.Warn("Failed to get DNS record ID - skipping DNS cleanup", "hostname", t.Config.Hostname, "error", err)
		return nil
	}

	// Delete DNS record
	err = deleteDNSRecord(zoneID, recordID, apiToken)
	if err != nil {
		log.Warn("Failed to delete DNS record - proceeding with tunnel deletion", "hostname", t.Config.Hostname, "error", err)
		return nil
	}

	log.Info("Successfully cleaned up DNS record", "hostname", t.Config.Hostname)
	return nil
}