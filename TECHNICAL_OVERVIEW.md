# Technical Overview

## Protocol

### Wire format

Every transmission is exactly `TRANSMISSION_SIZE` (1,032) bytes:

```
Outer frame (8 bytes, prepended unencrypted for routing):
  Byte offset  Size   Field
  -----------  -----  ----------------------------------------
  0            4      BUNDLE_ID       (big-endian uint32)
  4            4      PAD_ID          (big-endian uint32)

Inner payload (1,024 bytes, XOR-encrypted with pad):
  Byte offset  Size   Field
  -----------  -----  ----------------------------------------
  0            1      MESSAGE_TYPE    (0x01 = text/post)
  1            4      SEQUENCE        (big-endian uint32)
  5            8      CHECKSUM        (SHA256 of content[:8])
  13           2      CONTENT_LEN     (big-endian uint16)
  15           N      CONTENT         (UTF-8 text, max 1,009 bytes)
  15+N         R      PADDING         (random bytes)
```

Total: 8 (outer) + 1,024 (encrypted payload) = 1,032 bytes

Only the inner payload is XOR-encrypted with the pad bytes. The outer
8-byte header is in plaintext to allow routing without decryption.

---

### Subject line format

```
msg-[bundle_id_hex]-[subject_token_hex]
```

Example: `msg-a3f8c291-72018665ff40b120`

- `bundle_id_hex`: 8 hex characters (4 bytes)
- `subject_token_hex`: 16 hex characters (8 bytes)
- `subject_token = HMAC-SHA256(subject_key, pad_id_bytes)[:8]`

---

### Vault file format

```
Byte offset  Size     Field
-----------  -------  ----------------------------------------
0            32       SALT            (KDF salt)
32           32       HMAC            (HMAC-SHA256 of ciphertext)
64           N        CIPHERTEXT      (encrypted vault plaintext)
```

Vault plaintext layout (before encryption):

```
Field            Size       Description
---------------  ---------  ------------------------------------
MAGIC            8          b'LBVLT300' or b'LBXFR300'
CHECKSUM         32         SHA256 of pad data
VERSION          2          uint16, current = 3
PAD_COUNT        4          uint32, = 5000
PAD_SIZE         4          uint32, = 1024
BUNDLE_ID        4          uint32
SEND_PADS        5000       2500 x uint16 pad IDs
INDEX            625        PAD_COUNT bits (used/unused bitmap)
FLAGS            1          bit 0 = ephemeral
SUBJECT_KEY      32         HMAC key for subject obfuscation
TOKEN_TABLE      40000      5000 x 8-byte HMAC tokens
PAD_DATA         5120000    5000 x 1024 bytes of random pad data
TOTAL            5165713    ~4.9 MB plaintext
```

---

### Token table

Pre-computed at vault generation:

```python
for pad_id in range(PAD_COUNT):
    token = HMAC-SHA256(subject_key, pack('>I', pad_id))[:8]
    table[pad_id * 8 : pad_id * 8 + 8] = token
```

Deserialised into `{token_hex: pad_id}` dict at load time. On receive, looking up the subject token takes ~5 microseconds regardless of vault size.

---

### Config file format

```
Byte offset  Size   Field
-----------  -----  ----------------------------------------
0            2      VERSION         (uint16)
2            32     SALT            (KDF salt, public)
34           2      FAILED_ATTEMPTS (uint16)
36           8      LAST_FAILED_TS  (uint64, unix timestamp)
44           8      LAST_SUCCESS_TS (uint64, unix timestamp)
52           8      VAULT_SEQUENCE  (uint64, send sequence)
60           1      DISCLAIMER      (uint8, 0=not agreed, 1=agreed)
61           8      RECV_SEQUENCE   (uint64, receive sequence)
```

Total: 69 bytes. Not encrypted — contains no secrets.

---

### Key derivation

Three keys derived from passphrase + salt:

```python
vault_key = PBKDF2-HMAC-SHA256(passphrase, salt + b'letterbox-vault-v1', iterations)
creds_key = PBKDF2-HMAC-SHA256(passphrase, salt + b'letterbox-credentials-v1', iterations)
```

Iterations:
- Personal vault and credentials: 200,000
- Transfer vault: 2,000,000

Each key is 32 bytes. A SHA256-based keystream is generated from the key:

```python
for counter in range(...):
    block = SHA256(key + pack('>Q', counter))
    stream.extend(block)
```

The keystream is XOR'd with the plaintext. HMAC-SHA256 of the ciphertext is prepended.

---

## Module Responsibilities

### `core/constants.py`
All protocol constants. Single source of truth for sizes, versions, iteration counts.

### `core/exceptions.py`
Exception hierarchy. All Letterbox-specific exceptions inherit from `LetterboxError`.

### `core/message.py`
Frame construction, OTP encryption, decryption, authentication. Stateless.

### `core/pad.py`
Pad lifecycle (reserve, confirm used, lookup). Subject token generation and lookup. Stateless — all state is in VaultData.

### `store/vault.py`
VaultData class. Key derivation. Vault serialisation/deserialisation. Token table build/load. `generate_vault`, `save_vault`, `load_vault`, `reencrypt_vault`.

### `store/config.py`
Config file read/write. Sequence counters (send + receive). Failed attempt tracking. Lockout delay calculation. Disclaimer recording.

### `store/credentials.py`
CredentialsData class. Encrypted save/load of Posteo credentials.

### `store/wipe.py`
`wipe_all_data()` — 3-pass random overwrite and deletion of all data files. Called on 10th failed attempt and on duress passphrase entry. Silent — raises no exceptions.

### `transport/posteo.py`
IMAP connection and operations. `post_message`, `collect_messages`, `upload_vault`, `download_vault`. Own-message filtering via token table.

### `util/random.py`
All randomness. `os.urandom` only. `generate_salt`, `generate_bundle_id`, `generate_subject_key`, `generate_transfer_passphrase`, `generate_pad_data`.

### `session_store.py`
Module-level passphrase cache. Set once per session by whichever module first authenticates. Never written to disk. Cleared on exit.

### `main.py`
Entry point. `UI` helper class (box, menu, press_enter, etc.). Disclaimer. Top-level menu. Module dispatch.

### `credentials_ui.py`
Collect Posteo credentials, test connection, set passphrase, save encrypted credentials.

### `vault_ui.py`
Generate or import vault. Transfer vault via Posteo or file. Display protection phrase. Save personal vault.

### `messages_ui.py`
Unlock vault and credentials. Send and receive loop. Sequence tracking.

---

## Randomness

All randomness flows through `util/random.py` which uses `os.urandom` exclusively.

On iOS/iPadOS, `os.urandom` draws from the Secure Enclave hardware RNG via `SecRandomCopyBytes`. On macOS it uses the kernel CSPRNG (`/dev/urandom`). Python's `random` module is never used for security-sensitive operations.

---

## Pad assignment

At vault generation, `PAD_COUNT` (5,000) pad IDs are randomly shuffled. The first 2,500 become Alice's send pads. The remaining 2,500 are Alice's receive pads (Bob's send pads).

`reencrypt_vault` inverts the send pad assignment: Bob's send pads = all IDs not in Alice's send pads.

Pads are selected randomly (not sequentially) for each transmission. The subject token obfuscates which pad was used.
