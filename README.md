# 🔐 SECURE VAULT

> ⚠️ **IMPORTANT ACKNOWLEDGEMENT & EXPERIMENT**  
> **This project was fully designed, created, and tested by AI as a hands-on experiment by Onkar Kale to explore how to vibe code effortlessly using Google Antigravity.**

---

## 📖 What Is SecureVault?

**SecureVault** is an offline, production-grade, multi-user encrypted CLI password manager written in Go 1.25+. It operates on a **zero-knowledge architecture**, ensuring that sensitive credentials (passwords, usernames, notes, and API keys) are **never stored in plaintext** on disk or in RAM.

### 🧠 Core Architectural Philosophy

1. **Multi-User Cryptographic Isolation ($N$ Users $\rightarrow$ $N$ Vaults)**:
   - Every user registers with their unique Email/Gmail username and Master Password.
   - Each account derives a unique 256-bit encryption key using **Argon2id** with an account-specific 32-byte salt.
   - User A's data can never be viewed, queried, or decrypted by User B.

2. **Authenticated Payload Encryption (AES-256-GCM)**:
   - Credentials are encrypted using AES-256-GCM.
   - Each payload contains a unique, cryptographically random 12-byte nonce and a 16-byte authentication tag (MAC).
   - Prevents unauthorized modification or database tampering.

3. **RAM Hygiene & Zero-Trace Key Management**:
   - Master encryption keys are stored exclusively in volatile memory during active sessions.
   - When signing out or exiting, keys are zeroed out using `utils.WipeBytes` to eliminate cold-boot RAM inspection risks.

4. **Automated Clipboard Security**:
   - Clipboard writes launch a background goroutine that automatically wipes system clipboard memory after 30 seconds.

---

## 📚 Complete Step-by-Step User Guide & Menu Walkthrough

### 1. 🔑 Account Registration & Login
When starting SecureVault (`./bin/securevault`), the application launches in locked session mode:
- **Sign Up / Register**: Select Option `2`. Enter your Email/Gmail address and Master Password (min 8 characters).
- **Log In**: Select Option `1`. Enter your credentials. Once verified, your session becomes **Active & Unlocked**.

### 2. 📋 Listing & Sequential Copying (Option 1)
- Displays all stored entries in an aligned terminal table (showing ID, Title, Category, Username, Masked Password `••••••••`, Favorite Star ★, and Timestamp).
- Enter an Entry `#` (e.g., `1`), short ID prefix (e.g., `5bc989ec`), or full UUID.
- **Sequential Copy Workflow**:
  - **Website URL**: Prompts to copy website URL to clipboard.
  - **Username**: Prompts to copy username (warns that previous clipboard content will be replaced).
  - **Password**: Prompts to copy password (warns that content will be replaced and automatically purged after 30 seconds).

### 3. ➕ Adding New Vault Entries (Option 2)
- Prompts for Title (required), Website, Username, Category (default: `General`), Notes, Tags (comma-separated), and Favorite Star ★.
- **Built-in CSPRNG Generator**: Option to generate a 20+ character random password with live entropy calculation.

### 4. 🔍 Searching Vault Entries & Filtering Favorites (Option 3)
- **Search All Entries**: Case-insensitive partial string matching across Title, Website, Username, Category, Tags, and Notes.
- **Filter Favorites Only ★**: Displays only starred favorite entries.
- Quick action prompt to inspect details or sequentially copy passwords directly from search results.

### 5. ✏️ Editing (Option 4) & 🗑️ Deleting Entries (Option 5)
- **Edit**: Select entry by number `#` or ID to update fields or generate a new password.
- **Delete**: Prompts for confirmation before permanently purging entry records.

### 6. ★ Toggling Favorite Star (Option 6)
- Easily star or unstar entries to keep frequently used credentials accessible.

### 7. 🎲 CSPRNG Password & Passphrase Generator (Option 7)
- **Secure Password Generator**: Configurable length, uppercase, lowercase, numbers, symbols, and ambiguous character exclusion.
- **Word Passphrase Generator**: Multi-word dictionary passphrases (e.g., `Surge-Breeze-Rocket-Crest-42`).
- **Random Username Generator**: Anonymous username builder.
- **Password Strength Analyzer**: Evaluates bit-entropy scores ($H = L \log_2 N$) and rate strength scores (0-4).

### 8. 🛡️ Security Audit & Payload MAC Scan (Option 8)
- Performs a real-time **AES-256-GCM authentication tag (MAC) integrity check** across database rows to verify payloads have not been corrupted or tampered with.
- Scans for weak passwords, duplicate passwords across accounts, and passwords older than 90 days.

### 9. 💾 Backup Snapshots & Restore (Option 9)
- **Create Encrypted Snapshot (.svb)**: Prompts for a target destination folder or file path (default: `./backups/`). Generates an encrypted archive stamped with a SHA-256 checksum.
- **Restore Vault from Snapshot**: Lists available snapshots and prompts for selection. **Header Inspection**: Decrypts and displays snapshot details (created timestamp, record count, version, filename) and requests confirmation before overwriting active entries.

### 10. 📤 Export & Import Data (Option 10)
- **Export**: Save vault entries to JSON or CSV files (supports specifying custom directory or file paths).
- **Import**: Import JSON or CSV files directly into your active vault.

### 11. 🔑 Change Master Password (Option 11)
- Re-derives new Argon2id key material and re-encrypts all vault entries under a new salt.

### 12. 📊 Vault Status (Option 12)
- Displays current session state, active user email, total registered user count, database location, and backup folder path.

### 13. 🔒 Sign Out (Option 13) & 🧹 Instant Clipboard Purge (Option 14)
- **Sign Out**: Clears session, wipes master key buffers from RAM, and locks vault.
- **Clear Clipboard**: Immediately wipes system clipboard contents.

---

## 🐧 How to Run on Linux (Ubuntu / Debian / Linux Mint)

### 1. Install Clipboard Dependency (Recommended)
On Linux desktop environments, install `xclip` to enable OS clipboard copying and automatic 30-second memory clearing:

```bash
sudo apt update && sudo apt install -y xclip
```

> *Note: If `xclip` is absent, SecureVault automatically falls back to secure on-screen password decryption without crashing.*

### 2. Build the Application
Ensure Go 1.25+ is installed, then build the binary:

```bash
make build
```

### 3. Launch Interactive Menu
```bash
./bin/securevault
```

---

## 🪟 How to Run on Windows (Windows 10 / 11)

SecureVault runs natively on Windows with **zero third-party clipboard tools required** (uses native Win32 Clipboard APIs).

### Option A: Build and Run directly on Windows (PowerShell / Command Prompt)

```powershell
# Build executable
go build -o bin\securevault.exe .\cmd\securevault

# Run application
.\bin\securevault.exe
```

### Option B: Cross-Compile for Windows from Linux / WSL

You can compile a standalone `.exe` binary from Linux to run on any Windows PC:

```bash
GOOS=windows GOARCH=amd64 go build -o bin/securevault.exe ./cmd/securevault
```

---

## 🧪 Testing & Verification

```bash
# Run unit and integration test suite
make test

# Run tests with Go race condition detector
make test-race

# Run benchmark suite
make bench
```

---

## 📜 Project Purpose & Vibe Coding

This repository serves as a real-world demonstration of **AI-driven Vibe Coding** powered by **Google Antigravity**. Designed and conducted by **Onkar Kale**, this experiment showcases how complex system architecture—ranging from low-level cryptographic key wiping and SQLite schema migrations to interactive terminal menus and cross-platform OS integrations—can be constructed rapidly and flawlessly through agentic pair programming.

---

## ⚖️ License
Licensed under the [MIT License](LICENSE). 100% Offline • Zero Remote Cloud Dependencies • Zero Telemetry.
