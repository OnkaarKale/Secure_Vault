package session

import (
	"testing"

	"securevault/internal/models"
)

func TestSessionManagerLockUnlock(t *testing.T) {
	cfg := &models.AppConfig{
		SessionTimeoutMinutes:  15,
		MaxLoginAttempts:       3,
		LockoutDurationMinutes: 5,
	}

	sm := NewSessionManager(cfg)

	if sm.IsUnlocked() {
		t.Error("new session manager should start locked")
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	user := &models.User{ID: "u-1", Email: "test@gmail.com"}

	if err := sm.Unlock(key, user); err != nil {
		t.Fatalf("failed unlocking session: %v", err)
	}

	if !sm.IsUnlocked() {
		t.Error("session should be unlocked")
	}

	gotKey, err := sm.GetMasterKey()
	if err != nil || len(gotKey) != 32 {
		t.Fatalf("failed retrieving key from unlocked session: %v", err)
	}

	sm.Lock()
	if sm.IsUnlocked() {
		t.Error("session should be locked after Lock()")
	}
}

func TestSessionManagerLockoutThrottling(t *testing.T) {
	cfg := &models.AppConfig{
		MaxLoginAttempts:       2,
		LockoutDurationMinutes: 10,
	}

	sm := NewSessionManager(cfg)

	sm.RecordFailedAttempt()
	locked, _ := sm.IsLockedOut()
	if locked {
		t.Error("should not be locked out on 1st attempt")
	}

	sm.RecordFailedAttempt()
	locked, _ = sm.IsLockedOut()
	if !locked {
		t.Error("should be locked out after reaching max attempts")
	}
}
