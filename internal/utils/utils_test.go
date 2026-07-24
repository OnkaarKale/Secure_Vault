package utils

import (
	"testing"
)

func TestWipeBytes(t *testing.T) {
	b := []byte("secret_password")
	WipeBytes(b)
	for i, val := range b {
		if val != 0 {
			t.Errorf("byte at index %d not zeroed", i)
		}
	}
}

func TestCalculateEntropy(t *testing.T) {
	tests := []struct {
		password string
		minBits  float64
	}{
		{"123456", 15.0},
		{"password", 30.0},
		{"P@ssw0rd12345!", 70.0},
	}

	for _, tt := range tests {
		entropy := CalculateEntropy(tt.password)
		if entropy < tt.minBits {
			t.Errorf("expected minimum entropy of %f for '%s', got %f", tt.minBits, tt.password, entropy)
		}
	}
}

func TestContainsString(t *testing.T) {
	slice := []string{"Apple", "Banana", "Cherry"}
	if !ContainsString(slice, "apple", true) {
		t.Error("expected case-insensitive match")
	}
	if ContainsString(slice, "apple", false) {
		t.Error("unexpected match for case-sensitive search")
	}
}
