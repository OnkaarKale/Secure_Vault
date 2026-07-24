// Package models defines all core domain data structures and entities used throughout SecureVault.
package models

import (
	"time"
)

// Argon2Params defines the security parameters for Argon2id key derivation and password hashing.
type Argon2Params struct {
	Memory      uint32 `json:"memory" yaml:"memory"`
	Iterations  uint32 `json:"iterations" yaml:"iterations"`
	Parallelism uint8  `json:"parallelism" yaml:"parallelism"`
	KeyLen      uint32 `json:"key_len" yaml:"key_len"`
	SaltLen     uint32 `json:"salt_len" yaml:"salt_len"`
}

// DefaultArgon2Params returns recommended production Argon2id security settings.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      64 * 1024, // 64 MB
		Iterations:  3,
		Parallelism: 4,
		KeyLen:      32, // 256 bits
		SaltLen:     32, // 256 bits
	}
}

// User represents a registered account in the multi-user system.
type User struct {
	ID           string       `json:"id"`
	Email        string       `json:"email"`
	MasterHash   string       `json:"master_hash"`
	MasterSalt   []byte       `json:"master_salt"`
	Argon2Params Argon2Params `json:"argon2_params"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

// VaultMetadata holds vault initialization metadata.
type VaultMetadata struct {
	Initialized   bool         `json:"initialized"`
	MasterHash    string       `json:"master_hash"`
	MasterSalt    []byte       `json:"master_salt"`
	Argon2Params  Argon2Params `json:"argon2_params"`
	VaultID       string       `json:"vault_id"`
	CreatedAt     time.Time    `json:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
}

// VaultEntry represents a single secret record stored within the encrypted vault.
type VaultEntry struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Title     string    `json:"title"`
	Website   string    `json:"website"`
	Username  string    `json:"username"`
	Password  string    `json:"password"` // Plaintext in memory only when decrypted
	Notes     string    `json:"notes"`
	Category  string    `json:"category"`
	Tags      []string  `json:"tags"`
	Favorite  bool      `json:"favorite"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AuditLog records security-relevant events without storing sensitive data.
type AuditLog struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
	Status    string    `json:"status"`
	Timestamp time.Time `json:"timestamp"`
}

// GeneratorOptions specifies parameters for generating random passwords.
type GeneratorOptions struct {
	Length           int  `json:"length"`
	IncludeUppercase bool `json:"include_uppercase"`
	IncludeLowercase bool `json:"include_lowercase"`
	IncludeNumbers   bool `json:"include_numbers"`
	IncludeSymbols   bool `json:"include_symbols"`
	ExcludeAmbiguous bool `json:"exclude_ambiguous"`
}

// DefaultGeneratorOptions returns recommended default options for password generation.
func DefaultGeneratorOptions() GeneratorOptions {
	return GeneratorOptions{
		Length:           20,
		IncludeUppercase: true,
		IncludeLowercase: true,
		IncludeNumbers:   true,
		IncludeSymbols:   true,
		ExcludeAmbiguous: true,
	}
}

// PassphraseOptions specifies options for generating word-based passphrases.
type PassphraseOptions struct {
	WordCount     int    `json:"word_count"`
	Separator     string `json:"separator"`
	Capitalize    bool   `json:"capitalize"`
	IncludeNumber bool   `json:"include_number"`
}

// DefaultPassphraseOptions returns default settings for passphrase generation.
func DefaultPassphraseOptions() PassphraseOptions {
	return PassphraseOptions{
		WordCount:     5,
		Separator:     "-",
		Capitalize:    true,
		IncludeNumber: true,
	}
}

// PasswordStrength represents the security analysis result for a password.
type PasswordStrength struct {
	Score    int      `json:"score"`    // 0 to 4 rating scale
	Rating   string   `json:"rating"`   // Weak, Fair, Good, Strong, Excellent
	Entropy  float64  `json:"entropy"`  // Bit entropy value
	Feedback []string `json:"feedback"` // Suggestions for improvement
}

// SearchFilter specifies criteria for filtering vault entries.
type SearchFilter struct {
	Query        string `json:"query"`
	Category     string `json:"category"`
	Tag          string `json:"tag"`
	FavoriteOnly bool   `json:"favorite_only"`
}

// BackupMetadata describes an encrypted backup file.
type BackupMetadata struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Version    string    `json:"version"`
	EntryCount int       `json:"entry_count"`
	FilePath   string    `json:"file_path"`
	Checksum   string    `json:"checksum"`
}

// EncryptedPayload represents data encrypted with AES-256-GCM.
type EncryptedPayload struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
}

// AppConfig represents global runtime configuration settings.
type AppConfig struct {
	DatabasePath           string `mapstructure:"database_path" yaml:"database_path"`
	BackupDir              string `mapstructure:"backup_dir" yaml:"backup_dir"`
	LogLevel               string `mapstructure:"log_level" yaml:"log_level"`
	LogFile                string `mapstructure:"log_file" yaml:"log_file"`
	SessionTimeoutMinutes  int    `mapstructure:"session_timeout_minutes" yaml:"session_timeout_minutes"`
	ClipboardTimeoutSec    int    `mapstructure:"clipboard_timeout_sec" yaml:"clipboard_timeout_sec"`
	MaxLoginAttempts       int    `mapstructure:"max_login_attempts" yaml:"max_login_attempts"`
	LockoutDurationMinutes int    `mapstructure:"lockout_duration_minutes" yaml:"lockout_duration_minutes"`
	BackupRotationCount    int    `mapstructure:"backup_rotation_count" yaml:"backup_rotation_count"`
}
