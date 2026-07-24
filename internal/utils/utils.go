// Package utils provides general helper functions including memory zeroing, string sanitation, and math calculations.
package utils

import (
	"math"
	"path/filepath"
	"strings"
	"time"
)

// WipeBytes securely overwrites a byte slice with zeros to clear sensitive data from memory.
func WipeBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}

// CalculateEntropy calculates the bit entropy of a password based on character pool size.
func CalculateEntropy(password string) float64 {
	if len(password) == 0 {
		return 0.0
	}

	var poolSize float64
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSymbol := false

	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= '0' && char <= '9':
			hasDigit = true
		default:
			hasSymbol = true
		}
	}

	if hasUpper {
		poolSize += 26
	}
	if hasLower {
		poolSize += 26
	}
	if hasDigit {
		poolSize += 10
	}
	if hasSymbol {
		poolSize += 32
	}

	if poolSize == 0 {
		return 0.0
	}

	// Shannon entropy formula: length * log2(poolSize)
	return float64(len(password)) * math.Log2(poolSize)
}

// ContainsString checks if a target string exists in a slice (case-insensitive option).
func ContainsString(slice []string, target string, caseInsensitive bool) bool {
	for _, item := range slice {
		if caseInsensitive {
			if strings.EqualFold(item, target) {
				return true
			}
		} else {
			if item == target {
				return true
			}
		}
	}
	return false
}

// FormatTime converts a time.Time to standard RFC3339 formatted string.
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return "N/A"
	}
	return t.Format("2006-01-02 15:04:05")
}

// CleanPath cleans and evaluates a filesystem path.
func CleanPath(path string) string {
	return filepath.Clean(path)
}
