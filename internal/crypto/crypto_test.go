package crypto

import (
	"bytes"
	"testing"

	"securevault/internal/models"
)

func TestArgon2idAndKeyDerivation(t *testing.T) {
	params := models.DefaultArgon2Params()
	salt, err := GenerateSalt(params.SaltLen)
	if err != nil {
		t.Fatalf("failed generating salt: %v", err)
	}

	pass := "SuperSecretMasterPassword123!"
	hash1, err := HashMasterPassword(pass, salt, params)
	if err != nil {
		t.Fatalf("failed hashing master password: %v", err)
	}

	if !VerifyMasterPassword(pass, salt, hash1, params) {
		t.Error("expected master password verification to succeed")
	}

	if VerifyMasterPassword("WrongPassword", salt, hash1, params) {
		t.Error("expected wrong password verification to fail")
	}
}

func TestAES256GCMEncryptionDecryption(t *testing.T) {
	key, err := GenerateRandomBytes(32)
	if err != nil {
		t.Fatalf("failed generating key: %v", err)
	}

	plaintext := []byte("Sensitive vault entry data payload")

	payload, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if bytes.Equal(payload.Ciphertext, plaintext) {
		t.Error("ciphertext matches plaintext")
	}

	decrypted, err := Decrypt(payload, key)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("expected '%s', got '%s'", plaintext, decrypted)
	}
}

func TestAES256GCMTamperDetection(t *testing.T) {
	key, _ := GenerateRandomBytes(32)
	plaintext := []byte("Tamper test payload")

	payload, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Tamper ciphertext
	payload.Ciphertext[0] ^= 0xFF

	_, err = Decrypt(payload, key)
	if err == nil {
		t.Error("expected decryption failure for tampered ciphertext")
	}
}
