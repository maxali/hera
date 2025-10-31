package main

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/spf13/afero"
	"golang.org/x/net/publicsuffix"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
)

const (
	heraHostname   = "hera.hostname"
	heraPort       = "hera.port"
	heraDNSCleanup = "hera.dns.cleanup"
)

var (
	// containerRegistry maps container IDs to hostnames
	// This allows us to look up hostnames even after containers are removed
	containerRegistry   = make(map[string]string)
	containerRegistryMu sync.RWMutex
)

// A Handler is responsible for responding to container start and die events
type Handler struct {
	Client *Client
}

// NewHandler returns a new Handler instance
func NewHandler(client *Client) *Handler {
	handler := &Handler{
		Client: client,
	}

	return handler
}

// HandleEvent dispatches an event to the appropriate handler method depending on its status
func (h *Handler) HandleEvent(event events.Message) {
	switch status := event.Status; status {
	case "start":
		log.Debugf("Received START event for container %s", event.ID[:12])
		err := h.handleStartEvent(event)
		if err != nil {
			log.Error(err.Error())
		}

	case "die":
		log.Infof("Received DIE event for container %s", event.ID[:12])
		err := h.handleDieEvent(event)
		if err != nil {
			log.Errorf("Failed to handle DIE event for %s: %v", event.ID[:12], err)
		} else {
			log.Infof("Successfully handled DIE event for %s", event.ID[:12])
		}
	}
}

// HandleContainer allows immediate tunnel creation when hera is started by treating existing
// containers as start events
func (h *Handler) HandleContainer(id string) error {
	event := events.Message{
		ID: id,
	}

	err := h.handleStartEvent(event)
	if err != nil {
		return err
	}

	return nil
}

// handleStartEvent inspects the container from a start event and creates a tunnel if the container
// has been appropriately labeled and a certificate exists for its hostname
func (h *Handler) handleStartEvent(event events.Message) error {
	container, err := h.Client.Inspect(event.ID)
	if err != nil {
		return err
	}

	hostname := getLabel(heraHostname, container)
	port := getLabel(heraPort, container)
	if hostname == "" || port == "" {
		return nil
	}

	// Store container ID → hostname mapping for later lookup
	// This is critical for handling DIE events when containers are already removed
	containerRegistryMu.Lock()
	containerRegistry[container.ID] = hostname
	containerRegistryMu.Unlock()
	log.Debugf("Registered container %s with hostname %s", container.ID[:12], hostname)

	log.Infof("Container found, connecting to %s...", container.ID[:12])

	ip, err := h.resolveHostname(container)
	if err != nil {
		return err
	}

	cert, err := getCertificate(hostname)
	if err != nil {
		return err
	}

	config := &TunnelConfig{
		IP:       ip,
		Hostname: hostname,
		Port:     port,
	}

	tunnel := NewTunnel(config, cert)

	// Configure DNS cleanup behavior
	// Priority: container label > environment variable
	tunnel.DNSCleanupEnabled = getDNSCleanupEnabled(container)
	if tunnel.DNSCleanupEnabled {
		log.Infof("DNS cleanup enabled for %s", hostname)
	} else {
		log.Debugf("DNS cleanup disabled for %s", hostname)
	}

	tunnel.Start()

	return nil
}

// handleDieEvent inspects the container from a die event and stops the tunnel if one exists.
// An error is returned if a tunnel cannot be found or if the tunnel fails to stop
func (h *Handler) handleDieEvent(event events.Message) error {
	var hostname string

	// Try to inspect the container first (works for normal container stop)
	container, err := h.Client.Inspect(event.ID)
	if err != nil {
		// Container already removed (e.g., docker-compose down)
		// Fall back to container registry lookup
		log.Infof("Container %s already removed, checking registry for hostname", event.ID[:12])

		containerRegistryMu.RLock()
		var ok bool
		hostname, ok = containerRegistry[event.ID]
		containerRegistryMu.RUnlock()

		if !ok {
			log.Warningf("Container %s not found in registry, unable to clean up tunnel", event.ID[:12])
			return nil
		}

		log.Infof("Found hostname %s in registry for removed container %s", hostname, event.ID[:12])
	} else {
		// Container still exists, get hostname from labels
		hostname = getLabel("hera.hostname", container)
		if hostname == "" {
			log.Debugf("Container %s has no hera.hostname label, skipping", event.ID[:12])
			// Clean up registry entry even though no tunnel exists
			containerRegistryMu.Lock()
			delete(containerRegistry, event.ID)
			containerRegistryMu.Unlock()
			return nil
		}
	}

	log.Infof("Container %s stopped, looking up tunnel for hostname: %s", event.ID[:12], hostname)

	tunnel, err := GetTunnelForHost(hostname)
	if err != nil {
		log.Errorf("Failed to find tunnel for %s: %v", hostname, err)
		// Clean up registry entry even if tunnel lookup fails
		containerRegistryMu.Lock()
		delete(containerRegistry, event.ID)
		containerRegistryMu.Unlock()
		return err
	}

	log.Infof("Found tunnel for %s, calling tunnel.Stop() to delete from Cloudflare", hostname)
	err = tunnel.Stop()
	if err != nil {
		log.Errorf("Failed to stop tunnel for %s: %v", hostname, err)
		// Don't return error - still clean up registry entry
	} else {
		log.Infof("Successfully stopped and deleted tunnel for %s", hostname)
	}

	// Clean up container registry entry
	containerRegistryMu.Lock()
	delete(containerRegistry, event.ID)
	containerRegistryMu.Unlock()
	log.Debugf("Removed container %s from registry", event.ID[:12])

	return err
}

// resolveHostname returns the IP address of a container from its hostname.
// An error is returned if the hostname cannot be resolved after five attempts.
func (h *Handler) resolveHostname(container types.ContainerJSON) (string, error) {
	var resolved []string
	var err error

	attempts := 0
	maxAttempts := 5

	for attempts < maxAttempts {
		attempts++
		resolved, err = net.LookupHost(container.Config.Hostname)

		if err != nil {
			time.Sleep(2 * time.Second)
			log.Infof("Unable to connect, retrying... (%d/%d)", attempts, maxAttempts)

			continue
		}

		return resolved[0], nil
	}

	return "", fmt.Errorf("Unable to connect to %s", container.ID[:12])
}

// getLabel returns the label value from a given label name and container JSON.
func getLabel(name string, container types.ContainerJSON) string {
	value, ok := container.Config.Labels[name]
	if !ok {
		return ""
	}

	return value
}

// getCertificate returns a Certificate for a given hostname.
// An error is returned if the root hostname cannot be parsed or if the certificate cannot be found.
func getCertificate(hostname string) (*Certificate, error) {
	rootHostname, err := getRootDomain(hostname)
	if err != nil {
		return nil, err
	}

	cert, err := FindCertificateForHost(rootHostname, afero.NewOsFs())
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// getRootDomain returns the root domain for a given hostname
func getRootDomain(hostname string) (string, error) {
	domain, err := publicsuffix.EffectiveTLDPlusOne(hostname)
	if err != nil {
		return "", err
	}

	return domain, nil
}

// getDNSCleanupEnabled determines if DNS cleanup should be enabled for a container
// Priority: container label (hera.dns.cleanup) > environment variable (CLOUDFLARE_DNS_CLEANUP_ENABLED)
// Returns true if enabled, false otherwise
func getDNSCleanupEnabled(container types.ContainerJSON) bool {
	// Check container label first (highest priority)
	labelValue := getLabel(heraDNSCleanup, container)
	if labelValue != "" {
		// Parse label value as boolean
		if labelValue == "true" || labelValue == "1" || labelValue == "yes" {
			log.Debugf("DNS cleanup enabled via container label for %s", container.ID[:12])
			return true
		}
		if labelValue == "false" || labelValue == "0" || labelValue == "no" {
			log.Debugf("DNS cleanup disabled via container label for %s", container.ID[:12])
			return false
		}
		log.Warningf("Invalid hera.dns.cleanup label value '%s' for container %s, falling back to environment variable", labelValue, container.ID[:12])
	}

	// Check environment variable (lower priority)
	envValue := os.Getenv("CLOUDFLARE_DNS_CLEANUP_ENABLED")
	if envValue != "" {
		if envValue == "true" || envValue == "1" || envValue == "yes" {
			log.Debugf("DNS cleanup enabled via environment variable for %s", container.ID[:12])
			return true
		}
		if envValue == "false" || envValue == "0" || envValue == "no" {
			log.Debugf("DNS cleanup disabled via environment variable for %s", container.ID[:12])
			return false
		}
		log.Warningf("Invalid CLOUDFLARE_DNS_CLEANUP_ENABLED value '%s', defaulting to false", envValue)
	}

	// Default to false if neither is set
	log.Debugf("DNS cleanup disabled (default) for %s", container.ID[:12])
	return false
}
