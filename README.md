# Letterbox

**Secure one-time-pad correspondence for iPad**

Letterbox is a proof-of-concept private messaging application built on information-theoretically secure one-time-pad encryption. Two parties share a vault of random pad material, exchange encrypted messages through a shared Posteo IMAP account, and achieve perfect forward secrecy with no reusable algorithms.

---

## Overview

- **Platform:** iPad / Pythonista 3
- **Encryption:** One-time pad (information-theoretically secure)
- **Transport:** Posteo IMAP dead drop — no SMTP, no routing, no third-party servers
- **Key exchange:** Physical vault transfer (USB, file, or Posteo upload)
- **Version:** 3.2.0

---

## Security Properties

| Property | Detail |
|---|---|
| Confidentiality | Information-theoretically secure — cannot be broken by any computation |
| Authentication | HMAC-SHA256 per message |
| Key derivation | PBKDF2-HMAC-SHA256, 200,000 iterations (personal), 2,000,000 (transfer) |
| Forward secrecy | Each pad used once and erased immediately after use |
| Subject obfuscation | HMAC-based token hides pad identity from transport observer |
| Replay protection | Pad bitmap — used pads cannot be reused |
| Rollback detection | Sequence counter compared to vault state on each launch |

---

## Architecture

```
main.py                 Entry point, UI helpers, top-level menu
credentials_ui.py       Module 1: Posteo credentials and passphrase
vault_ui.py             Module 2: Vault generation and import
messages_ui.py          Module 3: Send and receive messages
session_store.py        In-session passphrase cache

core/
  constants.py          Protocol constants
  exceptions.py         Exception hierarchy
  message.py            OTP encrypt / decrypt
  pad.py                Pad lifecycle, subject token functions

store/
  vault.py              Vault format, key derivation, pad data
  config.py             Sequence counters, session state
  credentials.py        Encrypted Posteo credentials

transport/
  posteo.py             IMAP dead drop transport

util/
  random.py             All randomness in one place
```

---

## Dependency Chain

```
[1] Enter / Update Posteo Credentials
        ↓
[2] Generate / Import OTP Vault
        ↓
[3] Send / Receive Messages
```

Options 2 and 3 require their prerequisites to be completed first. The app checks and redirects if prerequisites are missing.

---

## First Run

1. Launch Letterbox
2. Read and agree to the disclaimer
3. Select **[1] Enter / Update Posteo Credentials**
   - Enter your shared Posteo email address and app password
   - Set your passphrase — this protects your vault and credentials
4. Select **[2] Generate / Import OTP Vault**
   - **Alice:** Generate a new vault, transfer to Bob
   - **Bob:** Import vault using the protection phrase
5. Select **[3] Send / Receive Messages**

---

## Vault Exchange

**Alice (initiator):**
1. Select Generate → choose Posteo or Digital File
2. Vault uploads to Posteo or saves as `letterbox_transfer.txt`
3. Six-word protection phrase is displayed — write it down
4. Deliver the phrase to Bob through a separate channel

**Bob (recipient):**
1. Select Import → choose Posteo or Digital File
2. Place `letterbox_transfer.txt` in the Letterbox documents folder (if digital file)
3. Enter the six-word protection phrase
4. Vault is decrypted, Bob's personal copy saved, transfer file deleted

---

## Vault Format

```
File:      [SALT: 32][HMAC: 32][CIPHERTEXT: ~5MB]
Plaintext: [MAGIC][CHECKSUM][VERSION][COUNT][PAD_SIZE][BUNDLE_ID]
           [SEND_PADS][INDEX][FLAGS][SUBJECT_KEY][TOKEN_TABLE][PAD_DATA]
```

- 5,000 total pads — 2,500 per correspondent
- Each pad: 1,024 bytes
- Total pad data: ~5MB
- Token table: 40KB (pre-computed HMAC lookup for O(1) receive)
- Personal vault encrypted with PBKDF2 + SHA256-keystream + HMAC
- Transfer vault encrypted with 10× more PBKDF2 iterations

---

## Message Format

```
[BUNDLE_ID: 4][PAD_ID: 4][TYPE: 1][SEQUENCE: 4][CHECKSUM: 8]
[CONTENT_LEN: 2][CONTENT: N][PADDING: R]
```

- Fixed size: 1,032 bytes (8-byte outer header + 1,024-byte encrypted payload)
- Maximum message content: ~1,009 bytes (~1,009 characters)
- Entire frame XOR-encrypted with pad bytes
- Authenticated with HMAC-SHA256

---

## Subject Line Obfuscation

The email subject line carries an obfuscated pad identifier:

```
msg-[bundle_id_hex]-[subject_token_hex]
```

`subject_token = HMAC(subject_key, pad_id)[:8]` as hex (16 characters)

- `subject_key` is a 32-byte random key shared in the vault
- The token is pre-computed for all 5,000 pads at vault generation
- Stored as a lookup table `{token: pad_id}` for O(1) receive lookup
- Observers cannot infer pad identity or message count from the subject line

---

## Session Management

The passphrase is asked once per session — in whichever option is used first — then cached in memory via `session_store.py`. It is never written to disk. On exit, the session is discarded.

---

## Installation

See [INSTALL.md](INSTALL.md).

---

## Security Considerations

See [SECURITY.md](SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Disclaimer

This project is an experimental proof of concept provided "as is," without warranty of any kind. See [DISCLAIMER.md](DISCLAIMER.md) for the full text.

---

## License

See [LICENSE](LICENSE).
