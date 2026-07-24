// Package clipboard provides secure system clipboard copying with automated background clearing.
package clipboard

import (
	"fmt"
	"sync"
	"time"

	atotto "github.com/atotto/clipboard"

	"securevault/internal/logger"
)

// ClipboardManager handles writing sensitive strings to system clipboard and clearing them after a timeout.
type ClipboardManager struct {
	mu            sync.Mutex
	clearTimer    *time.Timer
	lastCopyToken string
}

var defaultManager = &ClipboardManager{}

// WriteAndAutoClear writes text to clipboard and starts background goroutine to clear it after timeoutSec seconds.
func WriteAndAutoClear(text string, timeoutSec int) error {
	return defaultManager.WriteAndAutoClear(text, timeoutSec)
}

// WriteAndAutoClear writes text to clipboard and clears it after timeoutSec.
func (c *ClipboardManager) WriteAndAutoClear(text string, timeoutSec int) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if atotto.Unsupported {
		return fmt.Errorf("system clipboard utility (xclip/xsel) is not installed on this system")
	}

	if err := atotto.WriteAll(text); err != nil {
		return fmt.Errorf("failed writing to system clipboard: %w", err)
	}

	c.lastCopyToken = text

	if c.clearTimer != nil {
		c.clearTimer.Stop()
	}

	if timeoutSec <= 0 {
		timeoutSec = 30
	}

	c.clearTimer = time.AfterFunc(time.Duration(timeoutSec)*time.Second, func() {
		c.mu.Lock()
		defer c.mu.Unlock()

		currentText, err := atotto.ReadAll()
		if err == nil && currentText == c.lastCopyToken {
			_ = atotto.WriteAll("")
			logger.Info("Clipboard automatically cleared.")
		}
	})

	return nil
}

// Clear explicitly wipes the system clipboard contents immediately.
func Clear() error {
	return defaultManager.Clear()
}

// Clear wipes system clipboard.
func (c *ClipboardManager) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.clearTimer != nil {
		c.clearTimer.Stop()
		c.clearTimer = nil
	}

	if atotto.Unsupported {
		return nil
	}

	c.lastCopyToken = ""
	return atotto.WriteAll("")
}
