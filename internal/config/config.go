// Package config manages application configuration using Viper with environment variable support.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"

	"securevault/internal/models"
)

// DefaultConfig returns default runtime configuration options.
func DefaultConfig() *models.AppConfig {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}
	baseDir := filepath.Join(homeDir, ".securevault")

	return &models.AppConfig{
		DatabasePath:           filepath.Join(baseDir, "data", "securevault.db"),
		BackupDir:              filepath.Join(baseDir, "backups"),
		LogLevel:               "info",
		LogFile:                filepath.Join(baseDir, "securevault.log"),
		SessionTimeoutMinutes:  15,
		ClipboardTimeoutSec:    30,
		MaxLoginAttempts:       5,
		LockoutDurationMinutes: 15,
		BackupRotationCount:    10,
	}
}

// LoadConfig reads configuration from file or populates default settings.
func LoadConfig(configPath string) (*models.AppConfig, error) {
	cfg := DefaultConfig()

	v := viper.New()
	v.SetEnvPrefix("SECUREVAULT")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Set defaults in Viper
	v.SetDefault("database_path", cfg.DatabasePath)
	v.SetDefault("backup_dir", cfg.BackupDir)
	v.SetDefault("log_level", cfg.LogLevel)
	v.SetDefault("log_file", cfg.LogFile)
	v.SetDefault("session_timeout_minutes", cfg.SessionTimeoutMinutes)
	v.SetDefault("clipboard_timeout_sec", cfg.ClipboardTimeoutSec)
	v.SetDefault("max_login_attempts", cfg.MaxLoginAttempts)
	v.SetDefault("lockout_duration_minutes", cfg.LockoutDurationMinutes)
	v.SetDefault("backup_rotation_count", cfg.BackupRotationCount)

	if configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.AddConfigPath("./configs")
		v.AddConfigPath(".")
		v.SetConfigName("config")
		v.SetConfigType("yaml")
	}

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok && !os.IsNotExist(err) {
			// Ignore missing config files and fallback to defaults
		}
	}

	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	// Ensure directories exist
	if err := os.MkdirAll(filepath.Dir(cfg.DatabasePath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}
	if err := os.MkdirAll(cfg.BackupDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	return cfg, nil
}

// SaveConfig writes the given configuration to a YAML file.
func SaveConfig(cfg *models.AppConfig, targetPath string) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	v := viper.New()
	v.Set("database_path", cfg.DatabasePath)
	v.Set("backup_dir", cfg.BackupDir)
	v.Set("log_level", cfg.LogLevel)
	v.Set("log_file", cfg.LogFile)
	v.Set("session_timeout_minutes", cfg.SessionTimeoutMinutes)
	v.Set("clipboard_timeout_sec", cfg.ClipboardTimeoutSec)
	v.Set("max_login_attempts", cfg.MaxLoginAttempts)
	v.Set("lockout_duration_minutes", cfg.LockoutDurationMinutes)
	v.Set("backup_rotation_count", cfg.BackupRotationCount)

	v.SetConfigFile(targetPath)
	if err := v.WriteConfigAs(targetPath); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	return nil
}
