# Technical Overview

This document describes how Letterbox works at the code level.
It is intended for developers auditing the codebase, contributors
making changes, or technically curious users who want to understand
exactly what the software does.

Read DESIGN.md first for the reasoning behind each decision.
This document describes the implementation of those decisions.

---

## Terminology: Stamps vs Pads

The word **pad** is used throughout the code, constants, and
technical documentation (e.g. `PAD_SIZE`, `PAD_COUNT`,
`reserve_send_pad`, `erase_pad`). This refers to the
one-time-pad key material stored in the vault.

The user-facing UI uses the word **stamp** instead. A stamp is
consumed once per message -- a more intuitive metaphor for
non-technical users. One stamp = one pad = one message.

Technical readers should treat "stamp" and "pad" as synonymous.
The distinction is purely presentational.

## Project Structure

```
letterbox/
  main.py              Entry point and complete CLI
  core/
    constants.py       All protocol constants
    exceptions.py      All exception types
    pad.py             Pad selection and lifecycle
    message.py         Message encryption and decryption
  store/
    config.py          Unencrypted config file (salt, counters)
    vault.py           Vault file I/O and pad storage
    history.py         Encrypted SQLite message history
    credentials.py     Encrypted Posteo credentials
  transport/
    posteo.py          IMAP dead drop send and receive
  util/
    random.py          All randomness (single entry point)
```

The dependency flow is strictly one-directional:

```
main.py
  → core/   (pure logic, no I/O)
  → store/  (file I/O)
  → transport/ (network I/O)
  → util/   (randomness)
```

No module imports from main.py. No circular dependencies.

---

## core/constants.py

The single source of truth for all protocol values. Every other
module imports from here. Nothing is hardcoded elsewhere.

**Key values:**

```python
PAD_SIZE        = 1024    # bytes per pad block
PAD_COUNT       = 5000   # pads per vault
PAD_ASSIGN_SIZE = 2500    # pads assigned to each party
TRANSMISSION_SIZE = 1032  # every message on the wire, always
MAX_CONTENT_BYTES = 1009  # usable bytes per message (~680 words)
```

**Wire format constants** describe the layout of every transmitted
message — an 8-byte plaintext header followed by 1024 bytes of
encrypted payload.

**Vault format constants** describe the layout of the encrypted
vault file on disk, including the sizes of each field in the
header block.

**Platform detection** via `is_pythonista()` — tries to import
the `console` module which exists only in Pythonista. Returns
True on iPad, False on Mac. Used only in main.py to set the
data directory path.

---

## core/exceptions.py

All application exceptions in one file organised by category.
The hierarchy is:

```
LetterboxError
  PassphraseError
    WrongPassphraseError
    PassphraseMismatchError
    TooManyAttemptsError
  VaultError
    VaultNotFoundError
    VaultCorruptError
    VaultVersionError
    VaultRollbackError
    VaultPersistError
    VaultSizeError
  PadError
    PadExhaustedError
    PadAlreadyUsedError
    PadReplayError
    UnknownBundleError
  MessageError
    TransmissionSizeError
    ChecksumError
    ContentTooLongError
    UnknownMessageTypeError
    PayloadCorruptError
  SequenceError
    DuplicateMessageError
    InvalidSequenceError
  TransportError
    ConnectionError
    SendError
    ReceiveError
    VaultUploadError
    VaultDownloadError
  StorageError
    DatabaseError
    DatabaseCorruptError
    CredentialsError
  SetupError
    AlreadySetupError
    SetupIncompleteError
```

Catch the most specific type possible. Never catch
LetterboxError unless you genuinely mean to handle all
error cases identically.

---

## core/pad.py

Pad selection and lifecycle management. Sits between the vault
(which stores pad data) and the message module (which encrypts).

**reserve_send_pad(vault)**
The send-side entry point. Randomly selects an unused pad from
vault.send_pads (the set of pad IDs assigned to this party),
marks it used immediately in the vault's in-memory index, and
returns (pad_id, pad_bytes). The caller must save the vault
to disk before attempting to send.

The critical invariant: **the pad is marked used before the
message is encrypted, never after.** If the app crashes after
marking but before sending, the pad is wasted. This is correct
and safe. Reusing a pad is catastrophic.

**lookup_receive_pad(bundle_id, pad_id, vault, history)**
The receive-side entry point. Three outcomes:

1. Pad not in vault.send_pads AND unused in vault.index:
   normal case — returns pad bytes for decryption.

2. Pad in vault.send_pads: this is our own sent message.
   Raises PadAlreadyUsedError with is_duplicate=True.
   (Second line of defence — transport layer filters these first.)

3. Pad already used AND in history: duplicate delivery.
   Raises PadAlreadyUsedError with is_duplicate=True.

4. Pad already used AND not in history: replay attack or
   vault corruption. Raises PadReplayError.

**confirm_pad_used(pad_id, vault)**
Called after successful decryption. Marks the receive-side pad
as used. The vault must be saved after this call.

**check_pad_warning(vault)**
Returns a warning string if send pads are running low (at
thresholds of 500, 200, 100, 50, 10), or None if plentiful.

---

## core/message.py

Message encryption and decryption. The cryptographic core.

**Payload layout (1024 bytes, always):**
```
[TYPE:        1 byte ]  0x01=post, 0x02=reply, 0x03=padding
[SEQUENCE:    4 bytes]  per-contact counter, starts at 1
[CHECKSUM:    8 bytes]  SHA256[:8] of content bytes
[CONTENT_LEN: 2 bytes]  actual content length
[CONTENT:     variable] UTF-8 encoded message text
[PADDING:     random  ] os.urandom fills to exactly 1024 bytes
```

**Wire format (1032 bytes, always):**
```
[BUNDLE_ID: 4 bytes] plaintext -- identifies which vault
[PAD_ID:    4 bytes] plaintext -- identifies pad within vault
[PAYLOAD:1024 bytes] XOR-encrypted payload
```

**encrypt_message(content, sequence, pad_id, pad_bytes, bundle_id)**
Builds the plaintext payload, XORs it with the pad, prepends
the plaintext header. The encryption is literally:

```python
encrypted = bytes(p ^ k for p, k in zip(plaintext, pad_bytes))
```

Random padding fills unused space so every message is exactly
1024 bytes. The same content encrypts to different ciphertext
each time due to random padding.

**decrypt_message(transmission, pad_bytes)**
Extracts the header, XORs the payload with the pad to recover
plaintext, parses fields, verifies the checksum. Returns a dict
with type, sequence, content, checksum.

**parse_header(transmission)**
Extracts bundle_id and pad_id from the plaintext header. Called
by the transport layer before decryption to identify which vault
and pad to use.

---

## util/random.py

The single point where randomness enters the system. All other
modules that need random bytes call functions from here. Nothing
else calls os.urandom directly.

**random_bytes(n)** — os.urandom(n). The foundation.

**generate_salt()** — 32 random bytes for PBKDF2.

**generate_bundle_id()** — random nonzero 4-byte integer.

**generate_transfer_passphrase()** — 4 words from WORDLIST
using secrets.choice. Designed for verbal communication.

**generate_pad_data(pad_count, pad_size)** — generates the
entire vault pad data in one call (~5MB for defaults).
This is the most important call in the system. The security
of every message depends on the randomness of these bytes.

---

## store/config.py

Manages the only unencrypted file on disk. The config file
stores no sensitive data — only the KDF salt and operational
counters. It must exist before any encrypted file can be opened
because the salt is required to derive the decryption key.

**File format (61 bytes, fixed):**
```
[VERSION:           2 bytes]
[SALT:             32 bytes]  random, generated once at setup
[FAILED_ATTEMPTS:   2 bytes]  reset on successful login
[LAST_FAILED_TS:    8 bytes]  unix timestamp, 0=never
[LAST_SUCCESS_TS:   8 bytes]  unix timestamp, 0=never
[VAULT_SEQUENCE:    8 bytes]  last known send sequence
[DISCLAIMER_AGREED: 1 byte]   0=not agreed, 1=agreed
```

All writes are atomic: write to .tmp file, then rename.
A crash during write cannot produce a corrupt config.

**Vault sequence tracking** detects backup rollback. The sequence
counter only ever increases in this file. If the vault file is
restored from a backup, its internal sequence will be lower than
this stored value, triggering VaultRollbackError.

**Disclaimer tracking** — agreement stored as a single byte.
Once set to 1 the disclaimer is never shown again.

---

## store/vault.py

The most security-critical file. Manages vault encryption,
decryption, and pad lifecycle.

**Key derivation:**
Three distinct keys are derived from the same passphrase and
salt using PBKDF2-HMAC-SHA256:

```python
vault_key       = PBKDF2(passphrase, salt + b'letterbox-vault-v1')
credentials_key = PBKDF2(passphrase, salt + b'letterbox-credentials-v1')
history_key     = PBKDF2(passphrase, salt + b'letterbox-history-v1')
```

The purpose string suffix ensures each key is distinct even
with the same passphrase and salt.

Personal vaults and credentials use 200,000 iterations.
Transfer vaults use 2,000,000 iterations -- 10x more expensive
per cracking attempt. The transfer vault sits on Posteo during
exchange and is subject to offline attack; the higher iteration
count compensates for the shorter transfer passphrase and the
exposure window. Bob's one-time import cost is ~10-15 seconds
on iPad -- acceptable for a single setup operation.

**Vault encryption (_encrypt / _decrypt):**
```
plaintext → XOR with keystream → ciphertext
HMAC-SHA256(key, ciphertext) → MAC (32 bytes)
file = MAC + ciphertext
```

The keystream is generated by hashing key + counter repeatedly.
On decryption, HMAC is verified first (before any XOR). This
detects tampering and wrong passphrases with a single check.

**Vault file layout:**
```
[SALT:      32 bytes]  unencrypted
[ENCRYPTED BLOCK:]
  [MAC:      32 bytes]  HMAC-SHA256 of ciphertext
  [CIPHERTEXT:]
    [MAGIC:    8 bytes]  b'LBVAULT2' or b'LBTRANS2'
    [CHECKSUM: 32 bytes] SHA256 of pad data
    [VERSION:   2 bytes]  v2 adds FLAGS field
    [PAD_COUNT: 4 bytes]
    [PAD_SIZE:  4 bytes]
    [BUNDLE_ID: 4 bytes]
    [ASSIGNMENT:10000 bytes] PAD_ASSIGN_SIZE uint16 values
    [INDEX:  1250 bytes] used/unused bitmap
    [FLAGS:    2 bytes]  feature flags (bit 0 = EPHEMERAL)
    [PAD_DATA: ~5MB]
```

**Verification checks on load:**
1. HMAC verification (fast) — catches wrong passphrase first
2. Magic bytes check — confirms passphrase and vault type
3. SHA256 checksum of pad data — confirms integrity
4. Version check — accepts v1 (no flags field) and v2 (with flags).
   A v1 vault loads with ephemeral=False by default.

**Random pad assignment:**
At generate_vault() time, all PAD_COUNT pad IDs are randomly
shuffled. The first PAD_ASSIGN_SIZE go to the initiator (stored
in vault.send_pads). The assignment is stored in the vault header
as a sorted list of uint16 values. When Bob imports via
reencrypt_vault(), his send_pads is set to the complement of
Alice's — the remaining PAD_ASSIGN_SIZE IDs.

This means pad IDs from either party appear randomly distributed
across the full 0-9999 range. An observer cannot determine
message direction from pad IDs in message headers.

**VaultData class:**
In-memory vault representation.
- pads: bytearray, PAD_COUNT * PAD_SIZE (mutable for in-place erasure)
- index: list of PAD_COUNT booleans (True = used)
- bundle_id: 4-byte int for message header identification
- send_pads: set of pad IDs this party sends with
- is_transfer: True if this is a temporary transfer vault
- ephemeral: True if vault operates in ephemeral mode

**erase_pad(pad_id):**
Overwrites one pad slot in the in-memory bytearray with
os.urandom(PAD_SIZE). The vault must be saved after calling
this to commit the erasure to disk. Called in ephemeral mode
after a message is sent or after the user confirms deletion
of a received message. The overwrite replaces original key
material with random bytes, making the message content
unrecoverable from the vault file even if an attacker
subsequently obtains it.

---

## store/history.py

Manages the encrypted local message history database.

**Encryption model:**
The database file on disk is always encrypted. During a session:
1. Decrypt history.db to history.tmp.db using history_key
2. Open SQLite connection to history.tmp.db
3. Use normally throughout the session
4. On close: re-encrypt history.tmp.db back to history.db
5. Delete history.tmp.db (always, even if re-encryption fails)

This approach uses only stdlib sqlite3 with no encryption
extensions.

**Schema (messages table):**
```sql
id          INTEGER PRIMARY KEY AUTOINCREMENT
contact_id  TEXT     -- '001' in v1, multi-contact ready
direction   TEXT     -- 'sent' or 'received'
sequence    INTEGER  -- message sequence number
pad_id      INTEGER  -- pad used (for duplicate detection)
type        INTEGER  -- message type byte
content     TEXT     -- decrypted message text
checksum    BLOB     -- 8-byte checksum
timestamp   INTEGER  -- unix timestamp
displayed   INTEGER  -- 0=unread, 1=read
```

The contact_id column exists in v1 even though only one contact
is supported. Adding multi-contact in v2 requires no schema
changes.

**Duplicate detection:**
get_by_pad_id(pad_id) looks up a received message by its pad ID.
Used by core/pad.py to distinguish duplicate delivery (pad used,
message in history) from replay attack (pad used, no history).

**Sequence tracking:**
get_received_sequences() returns a set of all received sequence
numbers. The caller computes gaps by comparing this set against
the range 1..highest_received.

get_next_send_sequence() returns max(sent sequence) + 1, or 1
if nothing has been sent.

---

## store/credentials.py

Stores Posteo shared account credentials encrypted at rest.

**Encryption:** Same scheme as vault file — PBKDF2 key derivation
with credentials-specific purpose string, XOR keystream + HMAC.
Reads and writes atomically via temp file + rename.

**CredentialsData fields:**
```python
username:     str   # e.g. shared@posteo.de
password:     str   # Posteo app password
folder:       str   # e.g. 'Letterbox-a3f8c291'
is_initiator: bool  # True=Alice, False=Bob
imap_host:    str   # 'posteo.de'
imap_port:    int   # 993
```

is_initiator determines which pads to skip when collecting
messages (own-message filtering in transport layer).

**make_folder_name(bundle_id):**
Returns a folder name derived from the bundle ID:
'Letterbox-a3f8c291'. Both parties use the same folder name.
The folder is a shared inbox — both post to it and read from it.
Own-message filtering prevents each party from processing their
own messages.

---

## transport/posteo.py

IMAP dead drop transport. Messages never travel as email.

**Dead drop model:**
Sending: connect to shared Posteo account, use IMAP APPEND to
write message directly to the shared folder. No SMTP. No email
is sent. No routing metadata.

Receiving: connect to same account, search folder for messages
matching the bundle ID in the subject line, download, delete.

**Message format on server:**
```
Subject: msg-[bundle_id_hex]-[pad_id_hex]
Body:    MSG1:[base64 of 1032-byte transmission]
```

The subject carries bundle_id and pad_id in plaintext — these
are already in the plaintext header of the transmission, so no
new information is exposed.

**Own-message filtering:**
collect_messages accepts skip_pad_set (the caller's send_pads).
Before downloading a message, the subject line is fetched to
extract pad_id. If pad_id is in skip_pad_set, the message was
sent by us — it is deleted from the server and skipped without
downloading.

This is the primary filter. core/pad.py provides a secondary
filter at the pad layer for any that slip through.

**Vault transfer:**
upload_vault and download_vault use a separate folder
(Letterbox-Setup) and a different subject prefix (letterbox-
vault-transfer). The vault is base64-encoded with a VAULT1:
prefix. The vault is deleted from the server after successful
download.

**SSL:**
All connections use ssl.create_default_context() which verifies
server certificates. Requires the OS certificate store to be
populated (on Mac: run Install Certificates.command from the
Python installation).

---

## main.py

Entry point and complete CLI. All user interaction is here.
All other modules are pure logic with no print() or input() calls.

**Startup sequence:**
1. Version check (Python 3.10+)
2. Determine data directory (iPad: fixed path, Mac: --data arg)
3. Show disclaimer if not previously agreed
4. Run first-time setup if no config.dat
5. Login (passphrase entry, vault unlock, warning if prior failures)
6. Load credentials
7. Open history database
8. Main menu loop

**Setup flow (v2.0):**
_run_setup() presents two choices in sequence:

- Role: Generate vault (Alice) or Import vault (Bob)
- Transfer method: Posteo (IMAP upload/download) or File (AirDrop/Files)

These four combinations drive the branching in _setup_as_alice() and
_setup_as_bob(). Both functions accept a use_file_transfer bool.

Alice (file path): generates vault -> passphrase -> saves
letterbox_transfer.vault -> displays transfer phrase -> Press Enter ->
setup complete. Posteo credentials collected by _setup_message_transport.

Alice (Posteo path): generates vault -> passphrase -> Posteo credentials
-> upload -> displays all three items to provide to Bob -> Press Enter ->
setup complete. Credentials already saved; no second step.

Bob (file path): locates file -> transfer phrase -> decrypt -> passphrase
-> _setup_message_transport() collects Posteo credentials -> setup complete.
Transfer vault file deleted after successful import.

Bob (Posteo path): Posteo credentials + transfer phrase -> download ->
decrypt -> passphrase -> credentials already saved -> setup complete.

**Ephemeral mode selection (setup only):**
During Alice's setup flow, before vault generation, the user chooses
between Standard (1) and Ephemeral (2) mode. The choice is passed to
generate_vault() and stored in the vault flags. Bob's setup flow
is unchanged; he receives the flag automatically in the transfer
vault and it is preserved through reencrypt_vault().

**New helpers (v2.0):**
- _save_transfer_vault_to_file(): writes encrypted transfer vault to
  letterbox_transfer.vault in data_dir. Returns the path.
- _load_transfer_vault_from_file(): prompts for file path with
  default, validates, returns (path, bytes).
- _setup_message_transport(): collects Posteo credentials and saves
  them. Used by both parties on the file transfer path.

**UI model (inbox):**
Main menu shows status only: sent count, received count, unread
count, send pads remaining, any pad warning.

- c: compose — multi-line input, blank line to send
- r: check — downloads new messages, shows only this session's
     new arrivals
- u: read unread — shows all unread, marks all displayed
- h: history — paged at HISTORY_PAGE_SIZE (5), most recent first,
     n/p to navigate, oldest-first within each page
- q: quit

**Send flow:**
1. reserve_send_pad(vault) — marks pad used, returns bytes
2. save_vault() — persists updated index immediately
3. get_next_send_sequence() — from history database
4. encrypt_message() — builds and encrypts payload
5. post_message() — IMAP APPEND to Posteo folder
6. vault.erase_pad() — overwrite pad bytes with os.urandom (always)
   save_vault() — commit erasure to disk
7. Standard mode only: history.save_sent() — save to local history
8. update_vault_sequence() — update rollback detection counter

If step 5 fails, the pad is already used and the message is not
saved to history. The user is informed. A retry will use a new
pad. In ephemeral mode the pad erasure does not occur on send
failure, since the pad was never used to deliver a message.

**Receive flow:**
1. collect_messages() — download from Posteo, skip own messages
2. For each transmission:
   a. parse_header() — extract bundle_id and pad_id
   b. lookup_receive_pad() — get pad bytes or detect errors
   c. decrypt_message() — XOR decrypt, verify checksum
   d. confirm_pad_used() — mark pad used in vault index
   e. vault.erase_pad() — overwrite pad bytes with os.urandom (always)
   f. Standard mode: history.save_received() — save to local history
      Ephemeral mode: message added to session display list only
3. save_vault() — persist updated index and erased pad bytes once
4. Standard mode: display new messages
   Ephemeral mode: display each message with d/q prompt;
   d=delete and advance to next, q=quit (last message only);
   pad is already erased regardless of choice

**Passphrase entry:**
Passphrase is visible as typed (input() not getpass()). This
is intentional: on iPad, autocorrect can silently alter hidden
input causing lockouts. Users should enter their passphrase when
no one else can see their screen. This is stated at the prompt.

---

## Security-Critical Code Locations

For auditors, the security-critical code is concentrated in four
files totalling approximately 600 lines:

```
util/random.py     ~50 lines   All randomness
store/vault.py     ~280 lines  Key derivation, encryption,
                               pad assignment, vault I/O,
                               ephemeral pad erasure
core/pad.py        ~150 lines  Pad lifecycle, replay detection
core/message.py    ~180 lines  OTP encryption, payload layout
```

Everything else — config, history, credentials, transport, UI —
is plumbing. Correct but not cryptographically sensitive.

The complete encryption operation is one line:

```python
encrypted = bytes(p ^ k for p, k in zip(plaintext, pad_bytes))
```

Decryption is identical — XOR is its own inverse.

---

## Data Flow Summary

```
SEND:
  User types message
      → _compose_message() in main.py
      → reserve_send_pad() in core/pad.py
          → pick_unused_send_pad() in store/vault.py
          → mark_used() in store/vault.py
      → save_vault() in store/vault.py  [persist before send]
      → encrypt_message() in core/message.py
          → _build_payload()  [assemble 1024-byte plaintext]
          → XOR with pad      [one-time pad encryption]
          → prepend header    [bundle_id + pad_id plaintext]
      → post_message() in transport/posteo.py
          → base64 encode transmission
          → IMAP APPEND to shared Posteo folder
      → history.save_sent() in store/history.py  [standard mode only]
          [ephemeral mode: vault.erase_pad() instead, vault saved again]

RECEIVE:
  User requests check
      → _check_and_show_new() in main.py
      → collect_messages() in transport/posteo.py
          → IMAP SEARCH for bundle_id prefix in subjects
          → skip messages with pad_id in send_pads (our own)
          → IMAP FETCH remaining messages
          → IMAP STORE +FLAGS \Deleted after download
          → IMAP EXPUNGE
      → For each transmission:
          → parse_header() in core/message.py
              → extract bundle_id, pad_id from plaintext header
          → lookup_receive_pad() in core/pad.py
              → check pad not in send_pads (own message)
              → check pad not already used (replay/duplicate)
              → return pad bytes
          → decrypt_message() in core/message.py
              → XOR with pad  [one-time pad decryption]
              → parse payload fields
              → verify SHA256 checksum
          → confirm_pad_used() in core/pad.py
              → mark_used() in store/vault.py
      → vault.erase_pad() for each received pad  [always, all modes]
      → save_vault() in store/vault.py  [persist index + erasures]
      → history.save_received() in store/history.py  [standard mode only]
      → display new messages to user
          [ephemeral mode: prompt d/n/q per message]
          [yes/no controls session visibility only -- pad already erased]
          [on no: message shown this session only, never written to disk]
```

---

## Known Limitations

These are architectural limitations acknowledged at design time,
not bugs. See DESIGN.md for full reasoning.

**No push notifications.** Checking is always manual. The app
must be open and the user must press r.

**Single contact.** v1 supports one contact relationship. The
data model (contact_id column, vault per contact) is designed
for multi-contact in v2 without schema changes.

**Vault upload is slow.** Uploading 5MB via IMAP APPEND takes
60-90 seconds. This is a one-time cost per vault exchange.

**Text only.** No media, no file attachments.

**iPad and Pythonista 3 only.** The security properties described
in this documentation depend on iOS sandbox isolation. Other
platforms are not supported and their security properties are
not analysed or guaranteed.
