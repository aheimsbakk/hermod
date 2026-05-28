// Package cli: verbosity helpers — shared logger and level parsing.
package cli

import (
	"io"
	stdlog "log"
	"log/slog"
	"os"
	"strings"
)

// VerboseLevel controls how much output is produced.
type VerboseLevel int

const (
	VerboseNone    VerboseLevel = iota // no output except user-facing results
	VerboseError                       // errors only
	VerboseWarning                     // errors + warnings
	VerboseInfo                        // + progress / status messages
	VerboseDebug                       // + internal diagnostics (quic-go, etc.)
)

// currentLevel holds the active level for the current invocation.
var currentLevel VerboseLevel = VerboseNone

// parseVerboseLevel converts a string flag value to a VerboseLevel.
// Valid values: none, error, warning, info, debug.
func parseVerboseLevel(s string) (VerboseLevel, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "none":
		return VerboseNone, true
	case "error":
		return VerboseError, true
	case "warning":
		return VerboseWarning, true
	case "info":
		return VerboseInfo, true
	case "debug":
		return VerboseDebug, true
	}
	return VerboseNone, false
}

// toSlogLevel maps a VerboseLevel to the equivalent slog.Level.
func toSlogLevel(level VerboseLevel) slog.Level {
	switch level {
	case VerboseError:
		return slog.LevelError
	case VerboseWarning:
		return slog.LevelWarn
	case VerboseInfo:
		return slog.LevelInfo
	case VerboseDebug:
		return slog.LevelDebug
	default:
		return slog.LevelError // VerboseNone: handler is discard anyway
	}
}

// newLogger builds a slog.Logger writing to stderr at the given verbosity level.
// At VerboseNone the logger discards all records.
func newLogger(level VerboseLevel) *slog.Logger {
	if level == VerboseNone {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: toSlogLevel(level),
	}))
}

// applyVerbosity configures the global logger and stdlib log redirect.
func applyVerbosity(level VerboseLevel) {
	currentLevel = level
	slog.SetDefault(newLogger(level))
	if level >= VerboseDebug {
		stdlog.SetOutput(os.Stderr)
	} else {
		stdlog.SetOutput(io.Discard)
	}
}

// logInfo logs at INFO level. Visible at --verbose info and above.
func logInfo(msg string, args ...any) {
	slog.Info(msg, args...)
}

// logWarn logs at WARN level. Visible at --verbose warning and above.
func logWarn(msg string, args ...any) {
	slog.Warn(msg, args...)
}

// logDebug logs at DEBUG level. Visible at --verbose debug only.
func logDebug(msg string, args ...any) {
	slog.Debug(msg, args...)
}
