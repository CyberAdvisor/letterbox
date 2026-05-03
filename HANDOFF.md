# Letterbox — New Conversation Handoff

## What This Is

Letterbox is a proof-of-concept private one-time-pad correspondence
application for iPad running Pythonista 3. It allows two people who
know each other to exchange encrypted messages with no central server,
no accounts beyond a shared Posteo email address, and no algorithms
that can be broken by future computing advances.

The complete codebase and documentation is in the attached zip:
letterbox_final.zip

## How to Start

Extract the zip and read in this order:
1. DESIGN.md          -- every design decision and why
2. TECHNICAL_OVERVIEW.md -- how the code works at file level
3. CHANGELOG.md       -- what has been built and what is known

## Current State — v1.2.6

The application works end to end on Mac (two terminals simulating
Alice and Bob) and is ready for iPad testing. All known bugs have
been fixed. The codebase is clean and fully tested.

v1.2.6 INSTALL.md and README.md overhaul for new users.
v1.2.5 remove unreliable iCloud detection; add vault storage threat model.
v1.2.4 stamps/pads terminology documented in DESIGN and TECHNICAL_OVERVIEW.
v1.2.3 user-facing 'pads' renamed to 'stamps' in UI.
v1.2.2 fix iCloud detection using NSURLIsUbiquitousItemKey via objc_util.
v1.2.1 type q to quit at passphrase prompts.
v1.2.0 vault ID shown in menu status line.
v1.1.9 version number displayed on startup.
v1.1.8 fix ephemeral mode description text.
v1.1.7 --reset flag removed; in-app reset is the only reset path.
v1.1.6 in-app reset (all platforms), stale vault cleanup on upload.
v1.1.5 code review cleanup: dead code, stale comments, clarity fixes.
v1.1.4 ephemeral mode: n option removed, d/q only.
v1.1.3 adds iCloud check, compose char count, ephemeral d/q, scroll fix.
v1.1.2 reduces vault size to ~5MB and adds platform warning.
v1.1.1 added unconditional pad erasure and fixed setup flow.
v1.1.0 added ephemeral mode (see CHANGELOG.md and DESIGN.md).
Existing v1.0.x vaults continue to work without modification.

### What Works
- Vault generation with random pad assignment
- Vault ~5MB (5,000 pads × 1KB), upload/download in ~5-10 seconds
- Non-Pythonista platform warning on every launch outside iOS
- Pad key material erased after every send and receive (all modes)
- Ephemeral mode: no message history, "Ready to delete?" prompt on receive
- Vault exchange via Posteo IMAP dead drop (upload/download)
- One-time-pad message encryption and decryption
- Inbox model CLI: check shows new messages only
- History paged at 5 messages, most recent first
- Failed login attempt tracking with timestamps
- Disclaimer shown once, agreement stored in config
- Own-message filtering at transport and pad layers
- MIME encoding correct (7bit, no double base64)

### Development Environment
- Mac with Python 3.13 (installed from python.org)
- VS Code with Python extension
- Run with: PYTHONPATH=. python3 main.py --data data/alice
- Two terminals simulate Alice and Bob locally
- Reset with: PYTHONPATH=. python3 main.py --data data/alice --reset

### Known Issues to Address
- Vault upload to Posteo takes 60-90 seconds with no progress indicator
- No progress shown during vault generation (20-30 seconds on iPad)
- No physical vault transfer (AirDrop/USB) -- deferred to v2
- Single contact only -- multi-contact deferred to v2

## Key Design Decisions (summary)

**Encryption:** One-time pad. XOR plaintext with truly random pad.
Information-theoretically secure. Quantum resistant.

**Wire format:** Every message is exactly 4104 bytes. Always.
8-byte plaintext header (bundle_id + pad_id) + 4096-byte
OTP-encrypted payload.

**Vault:** 10,000 pads of 4096 bytes each (~39MB). Randomly
assigned -- 5,000 pads to each party. Random assignment means
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

## Planned v2 Features (in priority order)

1. Physical vault transfer -- AirDrop and save-to-file options
   Design is complete in DESIGN.md, just needs implementation
   in main.py setup flow

2. Progress indicator during vault generation and upload
   Vault generation: print dot every N pads
   Vault upload: no easy progress hook in imaplib APPEND

3. Multi-contact support -- data model is already ready
   contact_id column in history, vault per contact directory
   Only needs contact selection UI in main.py

4. Auto-check on startup -- check for new messages on launch
   before showing main menu, no background process needed

5. Resend flow -- Alice can resend a specific message by
   sequence number when Bob reports a gap

## Posteo Setup

Shared account: michaellines@posteo.com
IMAP host: posteo.de port 993
App passwords generated in Posteo account settings

Each vault exchange uses a folder named Letterbox-[bundle_id_hex]
e.g. Letterbox-a3f8c291

## Testing Checklist

Before each test run:
  PYTHONPATH=. python3 main.py --data data/alice --reset
  PYTHONPATH=. python3 main.py --data data/bob --reset

The RESET command requires typing RESET in full.

After reset, run Alice setup in left terminal, Bob setup in
right terminal using the transfer passphrase Alice displays.

Check that (standard mode):
- Sent count increments after each send
- Send pads remaining decrements by 1 per message
- Bob does not see his own messages when checking
- Alice does not see her own messages when checking
- History shows correct paged navigation
- Disclaimer shown on first run only

Check that (ephemeral mode -- select during Alice setup):
- No message appears in history after send or receive
- "Ready to delete?" prompt appears after each received message
- Answering "yes" saves the vault with randomised pad bytes
- Answering "no" shows message for the session only, no disk write
- Vault file size is unchanged (erased pad replaced with random bytes,
  not truncated)
