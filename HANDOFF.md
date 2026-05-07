# Letterbox — New Conversation Handoff

## What This Is

Letterbox is a proof-of-concept private one-time-pad correspondence
application for iPad running Pythonista 3. It allows two people who
know each other to exchange encrypted messages with no central server,
no accounts beyond a shared Posteo email address, and no algorithms
that can be broken by future computing advances.

The complete codebase and documentation is in the attached zip:
letterbox_v1.2.11.zip

## How to Start

Extract the zip and read in this order:
1. DESIGN.md          -- every design decision and why
2. TECHNICAL_OVERVIEW.md -- how the code works at file level
3. CHANGELOG.md       -- what has been built and what is known

## Current State — v1.2.12

The application works end to end on Mac (two terminals simulating
Alice and Bob) and on iPad. All known bugs have been fixed.
The codebase is clean and fully tested.

v1.2.12 iCloud backup restore risk documented in THREAT_MODEL.md and INSTALL.md.
v1.2.11 UX overhaul: setup flow rewrite, compose flow, menu redesign,
        documentation cleanup, bug fixes, reset via Files app.
v1.2.10 Test suite: chi-squared entropy test, rollback tests, ephemeral replay tests.
v1.2.9  Three security fixes: rollback detection enforced, ephemeral replay false positive, warning level bug.
v1.2.8  THREAT_MODEL.md pad erasure correction.
v1.2.7  THREAT_MODEL.md transport corrections (iCloud → Posteo IMAP).
v1.2.6  INSTALL.md and README.md overhaul for new users.
v1.2.5  Remove unreliable iCloud detection; add vault storage threat model.
v1.2.4  Stamps/pads terminology documented.
v1.2.3  User-facing 'pads' renamed to 'stamps' in UI (reverted in v1.2.11).
v1.2.2  Fix iCloud detection.
v1.2.1  Type q to quit at passphrase prompts.
v1.2.0  Vault ID shown in menu status line.
v1.1.0  Ephemeral mode added.
v1.1.x  Platform warning, vault size reduction, pad erasure, in-app reset.
v1.0.x  Initial working implementation.

### What Works

- Vault generation with random pad assignment
- Vault ~5MB (5,000 pads × 1KB), upload/download via Posteo IMAP
- Two-phase design: setup exits on completion, relaunch goes to menu
- Setup retries on wrong credentials or wrong transfer phrase
- Vault stays on Posteo until Bob successfully decrypts and saves
- Non-Pythonista platform warning on every launch outside iOS
- Pad material erased after every send and receive (all modes)
- Ephemeral mode: no message history, delete prompt on receive
- One-time-pad message encryption and decryption
- Own-message filtering at transport and pad layers
- Check for messages (c), write message (w), history (h)
- History paged at 5 messages, most recent first
- Failed login attempt tracking with timestamps
- Disclaimer shown once, agreement stored in config
- Rollback detection: compromised vault blocked on login
- MIME encoding correct (7bit, no double base64)

### Development Environment

- Mac with Python 3.13 (installed from python.org)
- VS Code with Python extension
- Run with: `PYTHONPATH=. python3 main.py --data data/alice`
- Two terminals simulate Alice and Bob locally
- Reset by deleting data directory: `rm -rf data/alice`

### Known Issues

- Vault upload to Posteo takes 60-90 seconds with no progress indicator
- No progress shown during vault generation (20-30 seconds on iPad)
- Vault transfer is Posteo-only; file/AirDrop option was considered and removed
- Single contact only -- two-person correspondence by design

## Key Design Decisions (summary)

**Encryption:** One-time pad. XOR plaintext with truly random pad.
Information-theoretically secure. Quantum resistant.

**Wire format:** Every message is exactly 4104 bytes. Always.
8-byte plaintext header (bundle_id + pad_id) + 4096-byte
OTP-encrypted payload.

**Vault:** 5,000 pads of 1024 bytes each (~5MB). Randomly
assigned -- 2,500 pads to each party. Random assignment means
pad IDs reveal no directional metadata to an observer.

**Transport:** Shared Posteo account. Messages posted via IMAP
APPEND directly to folder -- no SMTP, no email sent, no routing
metadata. Messages deleted from server after collection.

**Storage:** Three encrypted files (vault, credentials, history)
plus one unencrypted config (salt, counters, disclaimer flag).
All encrypted with PBKDF2 + XOR keystream + HMAC. Three distinct
keys derived from same passphrase via purpose-string suffix.
In ephemeral mode the history database contains no messages;
used pad bytes are overwritten with random data after each use.

**Transfer vault:** Encrypted with 6-word passphrase and 2,000,000
KDF iterations (10x personal vault) because it sits on Posteo
during exchange and is subject to offline attack.

**Platform:** iPad with Pythonista 3 only. iOS sandbox isolation
is a security dependency. Other platforms not supported.

## File Structure

```
letterbox_code/
  main.py                 Entry point, complete CLI
  core/
    constants.py          All protocol constants
    exceptions.py         All exception types
    pad.py                Pad selection and lifecycle
    message.py            OTP encryption/decryption
  store/
    config.py             Unencrypted config (salt, counters)
    vault.py              Vault I/O, key derivation, pad storage
    history.py            Encrypted SQLite message history
    credentials.py        Encrypted Posteo credentials
  transport/
    posteo.py             IMAP dead drop send/receive
  util/
    random.py             All randomness (single entry point)
  README.md               Project overview, who it is for
  THREAT_MODEL.md         Honest security analysis
  INSTALL.md              Setup instructions
  SECURITY.md             Vulnerability reporting
  CONTRIBUTING.md         Contribution guidelines
  DESIGN.md               All design decisions with reasoning
  TECHNICAL_OVERVIEW.md   Code-level description of every file
  CHANGELOG.md            Version history
  LICENSE                 GPL v3
```

## Planned Features

None. Letterbox is intentionally scoped to private correspondence
between exactly two people. This constraint is a deliberate security
decision, not a limitation. More contacts means more vaults, more
credentials, and more ways for the security model to break down.

Each vault exchange uses a folder named Letterbox-[bundle_id_hex]
e.g. Letterbox-a3f8c291

## Testing Checklist

**Setup:**
Delete data directories to start clean:
```
rm -rf data/alice data/bob
```

Run Alice setup in left terminal:
```
PYTHONPATH=. python3 main.py --data data/alice
```

Choose: Generate vault → mode → passphrase → Posteo credentials →
upload → note the six-word transfer phrase → app exits.

Run Bob setup in right terminal:
```
PYTHONPATH=. python3 main.py --data data/bob
```

Choose: Import vault → same Posteo credentials → download →
enter the six words → passphrase → app exits.

Relaunch both terminals to begin messaging.

**Standard mode checks:**
- Sent count increments after each send
- Pads remaining decrements by 1 per message
- Bob does not see his own messages when checking
- Alice does not see her own messages when checking
- History shows correct paged navigation
- Disclaimer shown on first run only
- Vault IDs match in both menus

**Ephemeral mode checks (select during vault generation):**
- No message appears in history after send or receive
- Delete prompt appears after each received message
- Vault file size unchanged (erased pad replaced with random bytes)
