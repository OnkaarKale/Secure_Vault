package tests

import (
	"testing"

	"securevault/internal/crypto"
	"securevault/internal/generator"
	"securevault/internal/models"
)

func BenchmarkAES256GCMEncryption(b *testing.B) {
	key, _ := crypto.GenerateRandomBytes(32)
	plaintext := []byte("Benchmark AES-256-GCM encryption payload text for performance measurement.")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.Encrypt(plaintext, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAES256GCMDecryption(b *testing.B) {
	key, _ := crypto.GenerateRandomBytes(32)
	plaintext := []byte("Benchmark AES-256-GCM decryption payload text for performance measurement.")
	payload, _ := crypto.Encrypt(plaintext, key)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := crypto.Decrypt(payload, key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPasswordGeneration(b *testing.B) {
	opts := models.DefaultGeneratorOptions()
	opts.Length = 32

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := generator.GeneratePassword(opts)
		if err != nil {
			b.Fatal(err)
		}
	}
}
