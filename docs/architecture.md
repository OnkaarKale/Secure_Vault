# SecureVault Architecture & Security Documentation

## Clean Architecture Layers

SecureVault adheres strictly to Clean Architecture principles:

1. **Presentation Layer (`cmd/securevault`, `internal/ui`)**:
   - Handles Cobra CLI command dispatch, flag parsing, ASCII banners, colored output, and interactive user prompts.
   - Strictly isolated from cryptographic key derivation and database storage logic.

2. **Application Layer (`internal/auth`, `internal/vault`, `internal/backup`, `internal/storage`, `internal/search`, `internal/generator`)**:
   - Contains high-level business rules, session unlocking workflows, backup creation, security audits, and import/export operations.

3. **Domain Layer (`internal/models`, `internal/utils`)**:
   - Defines pure data structures (`VaultEntry`, `VaultMetadata`, `AuditLog`, `Argon2Params`) and memory utility primitives (`WipeBytes`).

4. **Infrastructure Layer (`internal/crypto`, `internal/database`, `internal/repository`, `internal/session`, `internal/clipboard`, `internal/logger`)**:
   - Implements technical capabilities: Argon2id key derivation, AES-256-GCM authenticated cipher, SQLite database persistence, Logrus structured logging, and background clipboard timers.

---

## Cryptographic Security Model

- **Master Password Hashing & Key Derivation**: Argon2id with 64 MB memory, 3 iterations, 4 parallelism threads, 256-bit salt, and 256-bit derived key. Verified in constant time via `subtle.ConstantTimeCompare`.
- **Vault Payload Encryption**: AES-256-GCM with unique 12-byte random nonces per encryption operation.
- **Zero Plaintext Storage**: Plaintext passwords are never stored to disk.
- **Memory Hygiene**: Cryptographic keys and plaintext buffers are explicitly zeroed out using `utils.WipeBytes`.
- **Clipboard Protection**: Clipboard content copied from vault entries is automatically cleared in the background after 30 seconds.
