package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndSaveConfig(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "config_test_*")
	if err != nil {
		t.Fatalf("failed creating temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cfgPath := filepath.Join(tempDir, "test_config.yaml")

	defaultCfg := DefaultConfig()
	defaultCfg.LogLevel = "debug"
	defaultCfg.SessionTimeoutMinutes = 30

	if err := SaveConfig(defaultCfg, cfgPath); err != nil {
		t.Fatalf("failed saving config: %v", err)
	}

	loaded, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("failed loading config: %v", err)
	}

	if loaded.LogLevel != "debug" {
		t.Errorf("expected LogLevel 'debug', got '%s'", loaded.LogLevel)
	}
	if loaded.SessionTimeoutMinutes != 30 {
		t.Errorf("expected SessionTimeoutMinutes 30, got %d", loaded.SessionTimeoutMinutes)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.MaxLoginAttempts != 5 {
		t.Errorf("expected MaxLoginAttempts 5, got %d", cfg.MaxLoginAttempts)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected LogLevel 'info', got '%s'", cfg.LogLevel)
	}
}
