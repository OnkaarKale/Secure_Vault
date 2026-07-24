// Package generator provides cryptographically secure random password, passphrase, and username generation.
package generator

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"securevault/internal/models"
	"securevault/internal/utils"
)

const (
	upperChars     = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowerChars     = "abcdefghijklmnopqrstuvwxyz"
	numberChars    = "0123456789"
	symbolChars    = "!@#$%^&*()_+-=[]{}|;:,.<>?"
	ambiguousChars = "l1Io0O5S2Z8B"
)

var defaultWordList = []string{
	"amber", "anchor", "beacon", "breeze", "canvas", "canyon", "castle", "cedar", "cobalt", "comet",
	"crest", "crystal", "delta", "drift", "echo", "ember", "falcon", "fossil", "frost", "galaxy",
	"glacier", "granite", "harbor", "haven", "horizon", "island", "jasper", "jungle", "lagoon", "lunar",
	"marble", "meadow", "meteor", "mirage", "mountain", "nebula", "nexus", "oasis", "ocean", "orbit",
	"orchid", "palace", "path", "phantom", "phoenix", "pine", "planet", "prism", "pulse", "quartz",
	"radar", "river", "rocket", "ruby", "safari", "shadow", "signal", "silver", "solar", "spark",
	"spectrum", "sphere", "summit", "sunfall", "surge", "timber", "titan", "tower", "trace", "tundra",
	"valley", "velvet", "vortex", "whisper", "wild", "willow", "winter", "zenith", "zephyr", "zodiac",
}

var adjectives = []string{"swift", "silent", "brave", "clever", "cosmic", "golden", "iron", "shadow", "lunar", "solar"}
var nouns = []string{"falcon", "wolf", "tiger", "eagle", "dragon", "phoenix", "panther", "knight", "ranger", "hunter"}

// GeneratePassword constructs a cryptographically secure random password based on specified options.
func GeneratePassword(opts models.GeneratorOptions) (string, error) {
	if opts.Length < 4 {
		return "", fmt.Errorf("password length must be at least 4 characters")
	}

	var charset string
	var requiredChars []byte

	if opts.IncludeUppercase {
		charset += upperChars
		ch, err := randomChar(upperChars, opts.ExcludeAmbiguous)
		if err == nil {
			requiredChars = append(requiredChars, ch)
		}
	}
	if opts.IncludeLowercase {
		charset += lowerChars
		ch, err := randomChar(lowerChars, opts.ExcludeAmbiguous)
		if err == nil {
			requiredChars = append(requiredChars, ch)
		}
	}
	if opts.IncludeNumbers {
		charset += numberChars
		ch, err := randomChar(numberChars, opts.ExcludeAmbiguous)
		if err == nil {
			requiredChars = append(requiredChars, ch)
		}
	}
	if opts.IncludeSymbols {
		charset += symbolChars
		ch, err := randomChar(symbolChars, opts.ExcludeAmbiguous)
		if err == nil {
			requiredChars = append(requiredChars, ch)
		}
	}

	if opts.ExcludeAmbiguous {
		for _, amb := range ambiguousChars {
			charset = strings.ReplaceAll(charset, string(amb), "")
		}
	}

	if len(charset) == 0 {
		return "", fmt.Errorf("no character types selected for password generation")
	}

	remainingLen := opts.Length - len(requiredChars)
	result := make([]byte, opts.Length)
	copy(result, requiredChars)

	for i := 0; i < remainingLen; i++ {
		idx, err := randInt(len(charset))
		if err != nil {
			return "", fmt.Errorf("failed to generate random character index: %w", err)
		}
		result[len(requiredChars)+i] = charset[idx]
	}

	// Shuffle result slice to avoid predictable placement of required character categories
	if err := shuffleBytes(result); err != nil {
		return "", err
	}

	return string(result), nil
}

// GeneratePassphrase creates a word-based passphrase separated by a delimiter.
func GeneratePassphrase(opts models.PassphraseOptions) (string, error) {
	if opts.WordCount < 2 {
		return "", fmt.Errorf("word count must be at least 2")
	}

	words := make([]string, opts.WordCount)
	for i := 0; i < opts.WordCount; i++ {
		idx, err := randInt(len(defaultWordList))
		if err != nil {
			return "", fmt.Errorf("failed picking random word: %w", err)
		}
		word := defaultWordList[idx]
		if opts.Capitalize {
			word = strings.Title(word)
		}
		words[i] = word
	}

	if opts.IncludeNumber {
		num, err := randInt(100)
		if err == nil {
			words[len(words)-1] += fmt.Sprintf("%d", num)
		}
	}

	return strings.Join(words, opts.Separator), nil
}

// GenerateUsername generates a friendly, memorable username.
func GenerateUsername() (string, error) {
	adjIdx, err := randInt(len(adjectives))
	if err != nil {
		return "", err
	}
	nounIdx, err := randInt(len(nouns))
	if err != nil {
		return "", err
	}
	num, err := randInt(1000)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s_%s_%d", adjectives[adjIdx], nouns[nounIdx], num), nil
}

// EvaluateStrength analyzes password entropy and provides a detailed strength score and feedback.
func EvaluateStrength(password string) models.PasswordStrength {
	entropy := utils.CalculateEntropy(password)
	var feedback []string

	if len(password) < 8 {
		feedback = append(feedback, "Password length is under 8 characters.")
	}
	if len(password) < 12 {
		feedback = append(feedback, "Consider increasing password length to 12+ characters.")
	}
	if !strings.ContainsAny(password, upperChars) {
		feedback = append(feedback, "Add uppercase letters.")
	}
	if !strings.ContainsAny(password, lowerChars) {
		feedback = append(feedback, "Add lowercase letters.")
	}
	if !strings.ContainsAny(password, numberChars) {
		feedback = append(feedback, "Add numeric digits.")
	}
	if !strings.ContainsAny(password, symbolChars) {
		feedback = append(feedback, "Add special symbols.")
	}

	var score int
	var rating string

	switch {
	case entropy < 30:
		score = 0
		rating = "Weak"
	case entropy < 50:
		score = 1
		rating = "Fair"
	case entropy < 70:
		score = 2
		rating = "Good"
	case entropy < 90:
		score = 3
		rating = "Strong"
	default:
		score = 4
		rating = "Excellent"
	}

	return models.PasswordStrength{
		Score:    score,
		Rating:   rating,
		Entropy:  entropy,
		Feedback: feedback,
	}
}

func randomChar(pool string, excludeAmbiguous bool) (byte, error) {
	if excludeAmbiguous {
		for _, amb := range ambiguousChars {
			pool = strings.ReplaceAll(pool, string(amb), "")
		}
	}
	idx, err := randInt(len(pool))
	if err != nil {
		return 0, err
	}
	return pool[idx], nil
}

func randInt(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("invalid max bound")
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func shuffleBytes(slice []byte) error {
	for i := len(slice) - 1; i > 0; i-- {
		j, err := randInt(i + 1)
		if err != nil {
			return err
		}
		slice[i], slice[j] = slice[j], slice[i]
	}
	return nil
}
