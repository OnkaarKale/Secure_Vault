// Package session handles vault unlock states, master key retention, login attempt throttling, and auto-lock logic.
package session

import (
	"fmt"
	"sync"
	"time"

	"securevault/internal/models"
	"securevault/internal/utils"
)

// SessionManager manages active session state, encryption keys in memory, and login lockout timers.
type SessionManager struct {
	mu             sync.RWMutex
	masterKey      []byte
	activeUser     *models.User
	unlocked       bool
	lastActivity   time.Time
	failedAttempts int
	lockoutUntil   time.Time
	config         *models.AppConfig
}

// NewSessionManager creates a new thread-safe SessionManager.
func NewSessionManager(cfg *models.AppConfig) *SessionManager {
	return &SessionManager{
		config: cfg,
	}
}

// RecordFailedAttempt increments failed login counter and enforces temporary lockout if max attempts exceeded.
func (s *SessionManager) RecordFailedAttempt() (int, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.failedAttempts++
	if s.failedAttempts >= s.config.MaxLoginAttempts {
		s.lockoutUntil = time.Now().Add(time.Duration(s.config.LockoutDurationMinutes) * time.Minute)
	}
	return s.failedAttempts, s.lockoutUntil
}

// IsLockedOut checks if login is currently blocked due to excessive failed attempts.
func (s *SessionManager) IsLockedOut() (bool, time.Duration) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if time.Now().Before(s.lockoutUntil) {
		remaining := time.Until(s.lockoutUntil)
		return true, remaining
	}
	return false, 0
}

// Unlock sets the active master key, attaches current User, and marks the session as unlocked.
func (s *SessionManager) Unlock(key []byte, user *models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if time.Now().Before(s.lockoutUntil) {
		return fmt.Errorf("account is locked out. Try again in %v", time.Until(s.lockoutUntil).Round(time.Second))
	}

	if len(key) != 32 {
		return fmt.Errorf("invalid key length for session unlock")
	}

	// Make a defensive copy of the master key
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	if s.masterKey != nil {
		utils.WipeBytes(s.masterKey)
	}

	s.masterKey = keyCopy
	s.activeUser = user
	s.unlocked = true
	s.lastActivity = time.Now()
	s.failedAttempts = 0
	s.lockoutUntil = time.Time{}

	return nil
}

// Lock clears the master key from memory, detaches user state, and marks session as locked.
func (s *SessionManager) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.masterKey != nil {
		utils.WipeBytes(s.masterKey)
		s.masterKey = nil
	}
	s.activeUser = nil
	s.unlocked = false
}

// IsUnlocked returns true if an active, non-expired session is open.
func (s *SessionManager) IsUnlocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.unlocked {
		return false
	}

	// Check for session timeout inactivity
	timeout := time.Duration(s.config.SessionTimeoutMinutes) * time.Minute
	if time.Since(s.lastActivity) > timeout {
		if s.masterKey != nil {
			utils.WipeBytes(s.masterKey)
			s.masterKey = nil
		}
		s.activeUser = nil
		s.unlocked = false
		return false
	}

	s.lastActivity = time.Now() // Touch activity timestamp
	return true
}

// GetMasterKey retrieves a copy of the active master key or returns an error if locked.
func (s *SessionManager) GetMasterKey() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.unlocked || s.masterKey == nil {
		return nil, fmt.Errorf("vault is locked or session expired")
	}

	// Return a copy so caller doesn't mutate internal slice
	keyCopy := make([]byte, len(s.masterKey))
	copy(keyCopy, s.masterKey)
	return keyCopy, nil
}

// GetCurrentUser returns the currently authenticated user entity.
func (s *SessionManager) GetCurrentUser() *models.User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeUser
}

// GetActiveUserID returns active User ID or empty string.
func (s *SessionManager) GetActiveUserID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activeUser != nil {
		return s.activeUser.ID
	}
	return ""
}
