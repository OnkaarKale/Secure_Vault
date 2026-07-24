package generator

import (
	"testing"

	"securevault/internal/models"
)

func TestGeneratePassword(t *testing.T) {
	opts := models.DefaultGeneratorOptions()
	opts.Length = 24

	pass, err := GeneratePassword(opts)
	if err != nil {
		t.Fatalf("failed generating password: %v", err)
	}

	if len(pass) != 24 {
		t.Errorf("expected length 24, got %d", len(pass))
	}

	strength := EvaluateStrength(pass)
	if strength.Score < 3 {
		t.Errorf("expected high strength score for 24-char generated password, got %d", strength.Score)
	}
}

func TestGeneratePassphrase(t *testing.T) {
	opts := models.DefaultPassphraseOptions()
	opts.WordCount = 4

	phrase, err := GeneratePassphrase(opts)
	if err != nil {
		t.Fatalf("failed generating passphrase: %v", err)
	}

	if phrase == "" {
		t.Error("passphrase should not be empty")
	}
}

func TestGenerateUsername(t *testing.T) {
	user, err := GenerateUsername()
	if err != nil {
		t.Fatalf("failed generating username: %v", err)
	}

	if user == "" {
		t.Error("generated username should not be empty")
	}
}
