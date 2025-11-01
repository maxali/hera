package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	LogDir = "/var/log/hera"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

var log *slog.Logger

// PrettyHandler is a custom handler for human-readable console output
type PrettyHandler struct {
	handler slog.Handler
	w       io.Writer
	useColor bool
}

func NewPrettyHandler(w io.Writer, opts *slog.HandlerOptions, useColor bool) *PrettyHandler {
	return &PrettyHandler{
		handler:  slog.NewTextHandler(w, opts),
		w:        w,
		useColor: useColor,
	}
}

func (h *PrettyHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *PrettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &PrettyHandler{
		handler:  h.handler.WithAttrs(attrs),
		w:        h.w,
		useColor: h.useColor,
	}
}

func (h *PrettyHandler) WithGroup(name string) slog.Handler {
	return &PrettyHandler{
		handler:  h.handler.WithGroup(name),
		w:        h.w,
		useColor: h.useColor,
	}
}

func (h *PrettyHandler) Handle(ctx context.Context, r slog.Record) error {
	// Format: 2025-10-31T23:49:52.157Z INFO Logger initialized service=hera version=0.2.5

	timeStr := r.Time.Format(time.RFC3339Nano)
	level := r.Level.String()
	msg := r.Message

	// Apply colors if enabled
	if h.useColor {
		switch r.Level {
		case slog.LevelDebug:
			level = colorGray + level + colorReset
		case slog.LevelInfo:
			level = colorBlue + level + colorReset
		case slog.LevelWarn:
			level = colorYellow + level + colorReset
		case slog.LevelError:
			level = colorRed + colorBold + level + colorReset
		}
		timeStr = colorGray + timeStr + colorReset
	}

	// Build output: timestamp level message
	var sb strings.Builder
	sb.WriteString(timeStr)
	sb.WriteString(" ")
	sb.WriteString(level)
	sb.WriteString(" ")
	sb.WriteString(msg)

	// Add attributes as key=value
	r.Attrs(func(a slog.Attr) bool {
		sb.WriteString(" ")
		sb.WriteString(a.Key)
		sb.WriteString("=")

		// Format value - quote if contains spaces or newlines, escape newlines
		value := a.Value.String()
		if needsQuoting(value) {
			// Escape newlines and quotes
			value = strings.ReplaceAll(value, "\n", "\\n")
			value = strings.ReplaceAll(value, "\r", "\\r")
			value = strings.ReplaceAll(value, "\"", "\\\"")
			sb.WriteString("\"")
			sb.WriteString(value)
			sb.WriteString("\"")
		} else {
			sb.WriteString(value)
		}
		return true
	})

	sb.WriteString("\n")
	_, err := h.w.Write([]byte(sb.String()))
	return err
}

// needsQuoting checks if a value needs to be quoted
func needsQuoting(s string) bool {
	// Quote if contains spaces, newlines, or quotes
	return strings.ContainsAny(s, " \n\r\t\"")
}

// InitLogger sets up structured logging with configurable format and log level
// Logs are written to both stderr (for docker logs) and a file
//
// Environment variables:
// - HERA_LOG_LEVEL: debug, info, warn, error (default: info)
// - HERA_LOG_FORMAT: json, text (default: json)
// - HERA_LOG_COLOR: auto, true, false - colorize console output (default: true for text, false for json)
//   - auto: Enable colors only if stderr is a TTY
//   - true: Always use colors
//   - false: Never use colors
// - HERA_LOG_SOURCE: true, false - include file:line in logs (default: false)
func InitLogger(name string) {
	logPath := filepath.Join(LogDir, fmt.Sprintf("%s.log", name))

	// Create log directory if it doesn't exist
	if err := os.MkdirAll(LogDir, 0755); err != nil {
		slog.Error("Failed to create log directory", "error", err, "path", LogDir)
	}

	// Open log file
	logFile, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		slog.Error("Unable to open file for logging", "error", err, "path", logPath)
		// Fall back to stderr only
		setupLogger(os.Stderr, name)
		return
	}

	// Write to both stderr and file
	multiWriter := io.MultiWriter(os.Stderr, logFile)
	setupLogger(multiWriter, name)
}

// setupLogger creates a logger with structured fields and timestamps
// Configurable via environment variables for flexibility across environments
func setupLogger(w io.Writer, name string) {
	// Parse log level from environment (default: info for production)
	level := parseLogLevel(os.Getenv("HERA_LOG_LEVEL"))

	// Parse AddSource from environment (default: false)
	addSource := parseLogSource(os.Getenv("HERA_LOG_SOURCE"))

	// Configure handler options
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: addSource,
	}

	// Parse format from environment (default: json for machine consumption)
	format := strings.ToLower(os.Getenv("HERA_LOG_FORMAT"))

	// Determine if we should use colors
	useColor := shouldUseColor(format, os.Getenv("HERA_LOG_COLOR"))

	var handler slog.Handler
	switch format {
	case "text":
		// Use custom pretty handler for cleaner, colorized output
		handler = NewPrettyHandler(w, opts, useColor)
	default: // "json" or empty
		handler = slog.NewJSONHandler(w, opts)
	}

	// Create logger with service name attribute
	log = slog.New(handler).With("service", name)

	// Set as default logger for compatibility with internal packages
	slog.SetDefault(log)

	// Log the configuration for debugging
	log.Info("Logger initialized",
		"level", level.String(),
		"format", getFormat(format),
		"color", useColor,
		"source", addSource,
		"log_file", filepath.Join(LogDir, fmt.Sprintf("%s.log", name)))
}

// parseLogLevel converts string log level to slog.Level
func parseLogLevel(levelStr string) slog.Level {
	switch strings.ToLower(levelStr) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		// Default to info for production (debug is too verbose)
		return slog.LevelInfo
	}
}

// parseLogSource converts string to boolean for AddSource
func parseLogSource(sourceStr string) bool {
	return strings.ToLower(sourceStr) == "true"
}

// getFormat returns the actual format being used
func getFormat(format string) string {
	if format == "text" {
		return "text"
	}
	return "json"
}

// shouldUseColor determines if colored output should be used
// Only applies to text format, JSON is never colored
func shouldUseColor(format string, colorOption string) bool {
	// Never color JSON output
	if format != "text" {
		return false
	}

	switch strings.ToLower(colorOption) {
	case "true", "always":
		return true
	case "false", "never":
		return false
	case "auto":
		// Auto-detect: use color if stderr is a TTY
		return isTTY(os.Stderr)
	default: // empty - default to true for text mode
		// Default: enable colors for text format
		return true
	}
}

// isTTY checks if a file descriptor is a terminal
func isTTY(file *os.File) bool {
	// Check if file descriptor points to a terminal
	// This works on Unix-like systems (Linux, macOS)
	fileInfo, err := file.Stat()
	if err != nil {
		return false
	}
	// Check if it's a character device (terminal)
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
