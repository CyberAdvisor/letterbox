# Changelog

All notable changes to Letterbox are documented here.

---

## [3.2.0] — 2026-05-09

### Added
- Passphrase strength enforcement on all passphrase set and change operations
  - Minimum 10 characters
  - At least one uppercase letter
  - At least one non-alphanumeric character (space does not count)
  - Failed requirements shown individually before retry prompt

---

## [3.1.0] — 2026-05-09 — Baseline Release

First stable release of the v3 architecture. All v3.0.x development changes consolidated.

### Architecture
- Three-module design: `credentials_ui.py`, `vault_ui.py`, `messages_ui.py` called from `main.py`
- `session_store.py` — module-level passphrase cache; passphrase entered once per session regardless of which module is entered first
- Dependency chain enforced: credentials → vault → messages; each module checks prerequisites

### Cryptography
- All v2 proven crypto preserved: PBKDF2-HMAC-SHA256, SHA256 counter-mode keystream, HMAC-SHA256
- **Subject token obfuscation** — `HMAC(subject_key, pad_id)[:8]` in subject line instead of raw pad ID
- **Pre-computed token lookup table** — 40KB table stored in vault; O(1) receive lookup (5µs)
- **Own-message filter** — sender's own messages left on server using token table; never accidentally deleted

### Vault
- Vault version 3: adds `subject_key` (32 bytes) and `token_table` (40KB) to plaintext
- 5,000 total pads per vault — 2,500 per correspondent
- Vault size: ~5MB

### Messaging
- Ephemeral only — no message history
- Send and receive sequence counters tracked independently in config
- Sequence counters reset when new vault generated or imported

### UI
- Version number and vault ID (`vX.Y.Z · bundle_id`) displayed in both main menu and messaging menu
- "Goodbye" displayed on all exit paths
- Session passphrase caching — no re-prompt within a session
- Vault generates without timing messages (removed "This may take 20-30 seconds")

### Bug fixes (v3.0.x series)
- Fixed: own messages being deleted from server when sender checks mail
- Fixed: Bob unable to receive messages (token table searched all 5000 pads including send pads)
- Fixed: sequence counters not reset when new vault generated/imported
- Fixed: messages posted to `Letterbox-Setup` instead of correct vault folder after session
- Fixed: `session_store` import missing in `credentials_ui.py`
- Fixed: `make_subject_token` import missing in `transport/posteo.py`

---

## [2.0.1] — 2026-05-08

Final v2 release. See v2 repository for full v2 changelog.

### Key features carried into v3
- Proven PBKDF2 + SHA256-keystream + HMAC vault encryption
- Physical vault transfer via `letterbox_transfer.txt`
- Rollback detection via sequence counter
- Failed login attempt tracking
- Posteo IMAP dead drop transport

---

## Version Numbering

- **X.Y.Z** format
- **Z** increments with each code change during development
- **Y** increments on stable release; Z resets to 0
- **X** reserved for major architectural changes
