// Package crypto provides production cryptographic primitives including Argon2id key derivation and AES-256-GCM encryption.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"

	"securevault/internal/models"
	"securevault/internal/utils"
)

// GenerateRandomBytes returns securely generated random bytes of length n.
func GenerateRandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("invalid byte count: %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// GenerateSalt returns a random salt of specified length.
func GenerateSalt(length uint32) ([]byte, error) {
	return GenerateRandomBytes(int(length))
}

// DeriveKey derives a cryptographic key from a master password and salt using Argon2id.
func DeriveKey(password string, salt []byte, params models.Argon2Params) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLen,
	)
}

// HashMasterPassword generates a secure Argon2id hash for master password verification.
func HashMasterPassword(password string, salt []byte, params models.Argon2Params) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}
	if len(salt) == 0 {
		return nil, fmt.Errorf("salt cannot be empty")
	}
	key := DeriveKey(password, salt, params)
	return key, nil
}

// VerifyMasterPassword compares a candidate master password against a known Argon2id hash in constant time.
func VerifyMasterPassword(password string, salt []byte, targetHash []byte, params models.Argon2Params) bool {
	candidateHash := DeriveKey(password, salt, params)
	defer utils.WipeBytes(candidateHash)

	if len(candidateHash) != len(targetHash) {
		return false
	}
	return subtle.ConstantTimeCompare(candidateHash, targetHash) == 1
}

// Encrypt encrypts plaintext using AES-256-GCM authenticated encryption with a unique random nonce.
func Encrypt(plaintext []byte, key []byte) (*models.EncryptedPayload, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be exactly 32 bytes (256 bits), got %d", len(key))
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("cannot encrypt empty payload")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonce, err := GenerateRandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &models.EncryptedPayload{
		Ciphertext: ciphertext,
		Nonce:      nonce,
	}, nil
}

// Decrypt decrypts an AES-256-GCM encrypted payload and verifies message integrity.
func Decrypt(payload *models.EncryptedPayload, key []byte) ([]byte, error) {
	if payload == nil || len(payload.Ciphertext) == 0 || len(payload.Nonce) == 0 {
		return nil, fmt.Errorf("invalid encrypted payload")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("encryption key must be 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	if len(payload.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length: expected %d, got %d", gcm.NonceSize(), len(payload.Nonce))
	}

	plaintext, err := gcm.Open(nil, payload.Nonce, payload.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (tampered data or wrong key): %w", err)
	}

	return plaintext, nil
}
