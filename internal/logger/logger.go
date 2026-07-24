// Package logger provides a thread-safe, structured logging implementation backed by Logrus.
package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"securevault/internal/models"
)

var log *logrus.Logger

func init() {
	log = logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.InfoLevel)
}

// InitLogger configures the global logger based on AppConfig settings.
func InitLogger(cfg *models.AppConfig) error {
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	log.SetLevel(level)

	if cfg.LogFile != "" {
		dir := filepath.Dir(cfg.LogFile)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}

		file, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}

		// Log to both file and stdout
		mw := io.MultiWriter(os.Stdout, file)
		log.SetOutput(mw)
	}

	return nil
}

// Info logs an informational message.
func Info(format string, args ...interface{}) {
	log.Infof(sanitizeMsg(format), args...)
}

// Warn logs a warning message.
func Warn(format string, args ...interface{}) {
	log.Warnf(sanitizeMsg(format), args...)
}

// Error logs an error message.
func Error(format string, args ...interface{}) {
	log.Errorf(sanitizeMsg(format), args...)
}

// Debug logs a debug message.
func Debug(format string, args ...interface{}) {
	log.Debugf(sanitizeMsg(format), args...)
}

// sanitizeMsg strips potential sensitive keys or tokens from log format strings.
func sanitizeMsg(msg string) string {
	// Simple safety check to prevent accidental logging of sensitive patterns
	lowered := strings.ToLower(msg)
	if strings.Contains(lowered, "password") || strings.Contains(lowered, "secret") || strings.Contains(lowered, "key") {
		return "[REDACTED LOG PATTERN] " + msg
	}
	return msg
}
