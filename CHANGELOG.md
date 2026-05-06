# Changelog

---

## How to Read This Changelog

Updates are categorised as:

  SECURITY — apply before your next send
  BUGFIX   — apply when convenient
  FEATURE  — apply at your discretion

A SECURITY update must be applied before sending any further
messages. A FEATURE update can wait until convenient.

---

## Version Compatibility

The protocol version is embedded in every message. Clients of
different versions can communicate as long as the protocol
version matches.

When a vault format change is required, both parties must
generate and exchange a new vault before resuming correspondence.

Protocol and vault format changes will be announced with
significant advance notice in the GitHub issues.

---

## 1.0.0 — Initial Release — 2 May 2026

Proof of concept release.

Core features:
- One-time-pad vault generation with random pad assignment
- Vault encrypted at rest with PBKDF2 + XOR + HMAC
- Transfer vault exchange via Posteo IMAP dead drop
- Message encryption: XOR with OTP, SHA256 checksum,
  sequence numbers, fixed 4104-byte wire format
- Encrypted message history (SQLite)
- Encrypted credentials storage
- Failed login attempt tracking with absolute timestamps
- Vault rollback detection via sequence counter
- Disclaimer shown once, agreement stored in config
- Inbox model CLI: check shows new messages only
- History paged at 5 messages, most recent first
- Own-message filtering at transport and pad layers
- Random pad assignment: no directional metadata leak

Known limitations:
- No push notifications -- manual check required
- Vault transfer uses Posteo upload/download only
  Vault exchange currently requires Posteo upload only
- Single contact only (two-person correspondence by design)
- Text only -- no media
- iPad and Pythonista 3 only
- Vault upload to Posteo can take 60-90 seconds (39MB)

---

## 1.1.1 — Pad Erasure and Setup Flow — 3 May 2026

FEATURE — apply at your discretion.

**Pad key material is now always erased after use, in both modes.**

Previously, pad bytes were only overwritten in ephemeral mode. In
standard mode, used pad bytes remained on disk after a message was
sent or received. The pad was marked used (preventing reuse) but
the original key material survived in the vault file.

Now, pad bytes are overwritten with os.urandom(PAD_SIZE) immediately
after every send and every receive, regardless of mode. Ephemeral
mode continues to control whether message text is saved to history
and whether the "Ready to delete?" prompt is shown. Pad erasure is
no longer tied to mode — it is unconditional.

The practical effect: even if an attacker later obtains the vault
file and a copy of a transmitted message (e.g. from network capture
before Posteo deletes it), they cannot reconstruct the plaintext
because the key material is gone from the vault.

**"Ready to delete?" in ephemeral mode now controls message text
only, not pad erasure.** Answering "no" keeps the message visible
in session memory until the app closes. The pad bytes are already
gone regardless of the answer.

**Setup no longer re-prompts for passphrase after first run.**

After completing setup (vault generation or vault import), the app
now proceeds directly to the main menu without asking for the
passphrase again. The passphrase was already entered and verified
during setup; asking for it immediately a third time served no
security purpose and was confusing.

**Alice's setup no longer shows a meaningless wait prompt.**

The "Press Enter when your contact has imported the vault" prompt
has been removed. Alice has no way to know when Bob has imported,
and the prompt implied she was blocking on something she cannot
observe. The setup now proceeds directly to the "Setup Complete"
screen after displaying the credentials for Bob.

## 1.1.2 — Size Reduction and Platform Warning — 3 May 2026

FEATURE — apply at your discretion.
NOTE: Requires generating a new vault. Existing vaults are
incompatible with the new pad size and count.

**Vault size reduced from ~39MB to ~5MB.**

PAD_SIZE reduced from 4096 to 1024 bytes.
PAD_COUNT reduced from 10,000 to 5,000 pads.
PAD_ASSIGN_SIZE reduced from 5,000 to 2,500 pads per party.

Maximum message content reduced from 4,081 to 1,009 bytes
(approximately 170 words — sufficient for correspondence).
Wire format reduced from 4,104 to 1,032 bytes per message.

This reduces vault upload and download time from 60-90 seconds
to approximately 5-10 seconds on a typical connection.

**Non-Pythonista platform warning added.**

Running Letterbox outside Pythonista 3 on iPad now triggers a
prominent warning on every launch. The user must type TEST to
continue. The warning cannot be silenced.

The warning lists the specific vulnerabilities present on desktop
operating systems that are not present on iOS/Pythonista, drawn
directly from THREAT_MODEL.md:
- No iOS encryption at rest (iOS Data Protection absent)
- No app sandbox (any process can read vault/history files)
- Swap and memory exposure (desktop OSes may page process
  memory including decrypted content to unencrypted swap)
- No Secure Enclave passphrase protection
- Weaker screen observation protections

## 1.1.3 — UX and Security Improvements — 3 May 2026

FEATURE — apply at your discretion.

**Ephemeral mode message options changed to d/n/q.**
After displaying a received message in ephemeral mode, the user
is now offered: d (delete from memory), n (keep in memory for
this session, advance to next message), q (quit, offered only
after the last message). The previous yes/no prompt has been
removed.

**iCloud sync detection added.**
When running in Pythonista, the app now checks whether the data
directory is iCloud-synced. If it is, a warning is shown on every
launch and the user must type CONTINUE to proceed. iCloud sync
means the vault, history, and credentials files are being uploaded
to Apple's servers, which is inconsistent with the threat model.
Fix: Settings > [your name] > iCloud > Pythonista > disable sync.

**Running character count in compose.**
The compose screen now shows a running character count after each
line is entered, showing characters remaining from the 1009-byte
limit. Lines that would exceed the limit are rejected with the
count of excess characters, and the user can shorten the line or
type END to send what they have.

**Pythonista console scroll fix.**
After output is displayed, blank lines are printed to push content
up in the Pythonista console so the next prompt is visible without
the user needing to scroll down manually.

**Platform warning shortened.**
The non-Pythonista warning now shows a concise summary and
references THREAT_MODEL.md for full details, rather than
reproducing the threat model content inline.

**Transfer passphrase confirmation.**
After displaying the Posteo address, app password, and transfer
passphrase, the user must confirm they have copied the details
before the setup completes. The transfer passphrase is not shown
again after this point.

**APP_VERSION corrected to 1.1.3.**
The menu header was showing v1.1.0 due to APP_VERSION not being
updated in previous releases.

## 1.1.4 — Ephemeral Mode Options — 3 May 2026

FEATURE — apply at your discretion.

**Removed the n (next/keep) option from ephemeral message display.**

The n option implied a message would be retained in session memory
for later re-reading, but there was no mechanism to redisplay it.
Once past a message it was effectively gone regardless of the choice
made. The honest options are d (delete, acknowledge and advance) and
q (quit, offered after the last message). All messages must be
explicitly deleted before the menu is returned to.

## 1.1.5 — Code Review Cleanup — 3 May 2026

MAINTENANCE — no functional changes to security or features.

**Removed dead code and stale comments:**
- Dead `_pad_id` key removed from `new_messages` list in receive flow
  (pad erasure moved earlier; key was appended but never read)
- `TYPE_REPLY` import removed from `main.py` (reply feature not yet built)
- `credentials_exist` import removed from `main.py` (never called)
- Duplicate `PAD_ASSIGN_SIZE` import removed from `store/vault.py`
- Duplicate change control block removed from `core/constants.py`

**Stale comment corrections:**
- `MAX_CONTENT_BYTES` comment updated: ~680 words → ~170 words
- Wire format layout comment updated: 4096/4104 → 1024/1032 bytes
- Vault layout comment updated: 1250-byte index → 625-byte index
- `generate_pad_data` docstring updated: ~39MB → ~5MB
- `_build_plaintext` docstring updated: ~39MB → ~5MB

**Code clarity:**
- `_check_platform()` rewritten as two explicit early-return checks
  instead of a `pass` + fall-through structure
- `hashlib` moved to top-level imports (was inside `_compose_message`)

**Known gap documented:**
- `VaultRollbackError` is defined but never raised; TODO comments
  added in both `core/exceptions.py` and `main._login()` to make
  this explicit and prevent it being overlooked.

**Transport fix:**
- `collect_messages()` now expunges own-message deletions
  unconditionally, not only when foreign messages were also collected.

## 1.1.6 — In-App Reset and Vault Cleanup — 3 May 2026

FEATURE — apply before iPad testing.

**In-app reset available on all platforms including iPad.**

A reset option is now offered at the start of the login flow,
before the passphrase prompt. The user sees:

  "RESET or press Enter to continue:"

Typing RESET triggers _reset_app(), which shows a summary of
what will be deleted and requires typing RESET a second time
to confirm. Any other input cancels cleanly and proceeds to
the passphrase prompt. On confirmation, the entire data
directory is deleted and the app exits. The next launch runs
setup from scratch.

This replaces the Mac-only --reset command-line flag for
interactive use. The --reset flag continues to work on Mac.

**Alice deletes stale vaults before uploading a new one.**

Previously, multiple reset-and-setup cycles left orphaned
transfer vaults on the Posteo server. Bob's client picked
one arbitrarily (the last in IMAP search results, which is
server-ordering dependent). With multiple stale vaults Bob
could import the wrong one, producing a mismatched vault pair
that would fail silently -- messages would not decrypt.

upload_vault() now calls _delete_stale_vaults() before
appending the new vault. Any existing vault transfers in
the Letterbox-Setup folder are deleted first. Bob always
finds exactly one vault -- the most recently generated one.
Deletion is best-effort: if cleanup fails, the upload
proceeds anyway and the stale vault remains (the existing
behaviour, now only in degraded network conditions).

## 1.1.7 — Remove --reset Command-Line Flag — 3 May 2026

MAINTENANCE — no functional change to reset behaviour.

The --reset command-line flag and _reset_data_dir() function have
been removed. Reset is now handled exclusively through the in-app
prompt introduced in v1.1.6, which works on all platforms including
iPad. The --data flag for selecting the data directory on Mac is
retained.

## 1.1.8 — Ephemeral Mode Description Fix — 3 May 2026

MAINTENANCE — no functional change.

The ephemeral mode setup screen incorrectly stated that the pad
is overwritten after the delete confirmation. Since v1.1.1 pads
are erased unconditionally after every send and receive in both
modes, before any prompt is shown. The incorrect text has been
removed from the mode description and the post-selection
confirmation messages. Standard mode confirmation is also
simplified — the pad erasure detail is an implementation
concern, not something the user needs to be told about in setup.

## 1.1.9 — Version Display on Startup — 3 May 2026

MAINTENANCE — no functional change.

The version number is now printed at the very start of every
launch, before platform checks or disclaimer, so the user can
confirm they are running the correct version.

## 1.2.0 — Vault ID in Menu — 3 May 2026

FEATURE — minor.

The vault bundle ID is now shown in the main menu status line
as an 8-character hex value (e.g. Vault: a3f8c291). This allows
both parties to confirm at a glance they are using the same vault
without needing to inspect files or logs.

## 1.2.1 — Quit from Passphrase Prompt — 3 May 2026

FEATURE — minor.

Typing q (or Q) alone at any passphrase prompt now exits the app
cleanly. Previously the only way to exit from a passphrase prompt
was Ctrl+C, which behaves unpredictably on Pythonista. The quit
option is shown in the prompt hint. This applies to both the login
prompt and the passphrase confirmation prompt during setup.

## 1.2.2 — Reliable iCloud Detection — 3 May 2026

BUGFIX — apply before iPad testing.

The iCloud sync detection was failing on Pythonista because iOS
syncs the app Documents directory transparently at the VFS layer
-- the filesystem path itself contains no iCloud markers when
accessed via ~/Documents, so the previous path-string heuristics
never matched.

Fixed by using NSURLIsUbiquitousItemKey via Pythonista's
objc_util module, which is the authoritative iOS API for
determining whether a path is iCloud-managed. objc_util is
a Pythonista built-in and requires no external dependencies.
The path-string heuristics are retained as a fallback in case
the objc_util call fails for any reason.

## 1.2.3 — Stamps Terminology in UI — 3 May 2026

FEATURE — minor UX change.

User-facing references to "pads" in the UI have been replaced
with "stamps". A stamp is consumed once per message -- a more
intuitive metaphor for non-technical users. The word "pads"
is retained in all code, variable names, constants, technical
documentation, and developer-facing content.

Specifically changed:
- Menu status lines: "Pads" -> "Stamps"
- Post-send confirmation: "send pads remaining" -> "stamps remaining"
- Vault reset screen: "pad data" -> "stamp data"
- Pad exhaustion warnings in PAD_WARNING_LEVELS

## 1.2.4 — Stamps/Pads Terminology Documentation — 3 May 2026

MAINTENANCE — documentation only, no code changes.

Added a Terminology section to both DESIGN.md and
TECHNICAL_OVERVIEW.md explaining that "stamp" (used in the UI)
and "pad" (used in code and technical docs) refer to the same
thing. One stamp = one pad = one message. This prevents
confusion for technical users reading the code alongside the
documentation.

## 1.2.5 — Remove iCloud Detection, Add Vault Storage Threat — 3 May 2026

MAINTENANCE + DOCUMENTATION.

**Removed iCloud detection code.**
The _is_icloud_path() function and the iCloud sync check in
_check_platform() have been removed. The detection was unreliable
because iOS syncs the Pythonista Documents folder transparently
at the VFS layer -- the path contains no iCloud markers and
NSURLIsUbiquitousItemKey returns False for the directory even
when its contents are being synced. The script files themselves
may safely live in iCloud Drive; only the four data files
(vault.dat, credentials.dat, history.db, config.dat) must
remain local, and these are always written to Pythonista's
local sandbox by get_data_dir().

**Added vault storage threat model section.**
THREAT_MODEL.md now has a "Vault Files Outside the Device"
section explaining that vault files must not be copied to
iCloud Drive, cloud storage, or email. The threat is addressed
through documentation rather than unreliable runtime detection.

## 1.2.11 — Documentation Clarifications — 5 May 2026

DOCUMENTATION — no code changes.

**Pad consumption timing (DESIGN.md)**
Clarified that pads are consumed at send attempt, not on confirmed
delivery. If an IMAP send fails the pad is already marked used and
a retry consumes a fresh pad. This behaviour was already documented
inline in the send failure message shown to the user; it is now
also stated explicitly in the Send Flow section of DESIGN.md.

**History encryption model (DESIGN.md)**
Clarified that message history is protected by conventional
AES/PBKDF2 encryption keyed from the user's passphrase, not by
OTP. The OTP guarantee applies to messages in transit. Once
decrypted and stored, history has the same security properties
as any encrypted database. This distinction was implicit in the
design but not stated.

## 1.2.10 — Test Suite: Entropy, Rollback, Ephemeral Replay — 3 May 2026

MAINTENANCE — test suite improvements only, no production code changes.

**Section 21 — Pad entropy tests strengthened**
The existing pad data quality tests (21.1-21.3) were replaced with
a proper statistical test suite running against the full production
vault (~5MB), not a 10-block sample.

- 21.1: No all-zero blocks — unchanged in scope, now checks all PAD_COUNT blocks
- 21.2: Chi-squared byte frequency test across full vault. Threshold of 310
  (255 df, p=0.001). A biased generator producing non-uniform byte
  frequencies will fail this; genuine os.urandom scores ~245-265.
- 21.3: Bit balance within 0.5% of 50% across ~40M bits.
- 21.4: No duplicate pad blocks — any collision across 5000 blocks
  indicates catastrophic RNG failure.
- 21.5: Consecutive random_bytes calls differ (was 21.3).

**Section 13 — Rollback detection tests added (13.9-13.11)**
The stale NOTE documenting the rollback detection gap has been replaced
with real tests. 13.9 verifies clean state (sequence == used pads).
13.10 verifies the rollback condition is detected (sequence > used pads).
13.11 verifies no false positive (fresh vault, sequence matches used pads).

**Section 8 — Ephemeral replay false positive tests added (8.6-8.7)**
New tests verify that in ephemeral mode, a used pad with no history
record raises PadAlreadyUsedError with is_duplicate=True rather than
PadReplayError. This is the v1.2.9 fix; these tests confirm it.

Total tests: 147 → 152 (+5 net after replacing stale NOTE with 3 new
tests and adding 2 ephemeral tests).

## 1.2.9 — Security Fixes: Rollback Detection, Replay False Positive, Warning Level Bug — 3 May 2026

SECURITY — apply before your next send.

**Vault rollback detection enforced (Issue 1 — high severity)**
`_login()` now compares the send sequence counter stored in
`config.dat` against the number of used send pads in the vault
index after every successful passphrase entry. If `config.dat`
records more sends than the vault has used send pads, the vault
has been restored from a backup that predates those sends —
pad reuse is possible.

On detection the app shows a COMPROMISED VAULT warning and
blocks all access. The user must either type RESET to wipe all
data and start over, or exit. There is no path to the main menu.
The vault cannot be used.

The infrastructure (`get_vault_sequence`, `update_vault_sequence`,
`VaultRollbackError`) was already complete. Only the enforcement
check in `_login()` was missing. The TODO comments in
`core/exceptions.py` and `main._login()` have been removed.

**Ephemeral mode false positive fixed (Issue 2 — medium severity)**
`lookup_receive_pad()` in `core/pad.py` raised `PadReplayError`
("possible replay attack") when a used pad had no history record.
In ephemeral mode history is never written, so duplicate delivery
of any message always triggered this false alarm.

Fixed: if `vault.ephemeral` is True, a used pad with no history
record is treated as duplicate delivery (`PadAlreadyUsedError`
with `is_duplicate=True`) rather than a replay. The genuine
replay path (`PadReplayError`) is unchanged in standard mode.

**Pad warning level bug fixed (Issue 3 — low severity)**
`PAD_WARNING_LEVELS` in `core/pad.py` was ordered least-severe
to most-severe (500, 200, 100, 50, 10). The loop returned on
first match, so 9 remaining stamps produced the mild 500-level
warning instead of the CRITICAL warning. The list is now ordered
most-severe first (10, 50, 100, 200, 500). The loop logic is
unchanged — it still returns on first match, which is now always
the most severe applicable threshold.

## 1.2.8 — Threat Model Pad Erasure Correction — 3 May 2026

DOCUMENTATION — no code changes.

**THREAT_MODEL.md correction:**
The "Post-Session Device Forensics (Ephemeral Mode Only)" section
incorrectly implied that pad key material is overwritten with random
data only in ephemeral mode, and only after the "Ready to delete?"
confirmation. This is wrong. Pad erasure is unconditional — it
occurs in both standard and ephemeral modes, on both send and
receive, immediately after use. DESIGN.md and TECHNICAL_OVERVIEW.md
already described this correctly.

Corrected to: state clearly that pad key material is always
overwritten with random data after use in both modes, then describe
what ephemeral mode adds on top of that (no history database write).

## 1.2.7 — Threat Model Transport Corrections — 3 May 2026

DOCUMENTATION — no code changes.

**THREAT_MODEL.md corrections:**
Four sections contained stale references to iCloud Drive shared
folders as the message transport mechanism. The transport has
always been Posteo IMAP. The documentation did not match the
implementation.

Sections corrected:

- "Content Interception in Transit": rewritten to describe IMAP
  dead drop via Posteo over TLS. Removed incorrect references to
  iCloud Advanced Data Protection as a message transport layer.
- "Platform Data Breaches": updated from "iCloud is breached" to
  "Posteo is breached". Added note that Posteo holds no key
  material.
- "Communication Metadata": updated from iCloud/Apple ID framing
  to Posteo account access framing.
- "iCloud Account Compromise": renamed to "Posteo Account
  Compromise" and rewritten to describe the actual threat
  (shared Posteo credentials compromised) and correct mitigations.

The iCloud references that remain in THREAT_MODEL.md are correct:
they describe vault file storage (not message transport) and the
recommendation to not back vault files up to iCloud Drive.

No other documentation files required changes. DESIGN.md's iCloud
Drive reference is in the "rejected alternatives" section and is
accurate. INSTALL.md's iCloud references describe script file
storage and ADP setup, both of which are correct.

## 1.2.6 — Installation and README Overhaul — 3 May 2026

DOCUMENTATION — no code changes.

**INSTALL.md rewritten:**
- Added Quick Start section listing the three prerequisites
- Added Posteo account setup instructions (account creation,
  app password generation)
- Added iCloud Drive enablement step for Pythonista
- Corrected install steps to reflect actual iPad workflow:
  Files app, iCloud Drive → Pythonista 3 folder, create
  letterbox subfolder, copy extracted files into it
- Added Step 7: confirm both parties ready, vault IDs match,
  same version running
- Fixed "four words" -> "six-word transfer passphrase"
- Fixed vault size reference (~39MB -> ~5MB)
- Expanded troubleshooting section

**README.md updated:**
- Added "What You Need to Get Started" section at the top:
  two iPads, Pythonista 3, one shared Posteo account,
  ability to speak to contact in person or by video call
- Clarified Mac is for development/testing only, not production
- Minor wording improvements throughout

## Responsible Disclosure Hall of Fame

No disclosures yet.

Researchers who responsibly disclose vulnerabilities will be
listed here with their permission.

---

## 1.0.1 — Transfer Vault Security — 2 May 2026

SECURITY — apply before next vault exchange.

**Transfer passphrase increased from 4 to 6 words.**
Four words provided ~38 bits of entropy. Six words provides
~57 bits. The transfer vault sits on Posteo during exchange
and is subject to offline cracking attacks. Longer passphrase
makes this significantly harder.

**Transfer vault KDF iterations increased 10x.**
Personal and credentials vaults use 200,000 PBKDF2 iterations.
Transfer vaults now use 2,000,000 iterations. Each offline
cracking attempt takes ~10x longer. The one-time import cost
on iPad is approximately 10-15 seconds -- acceptable for a
single operation.

Both changes apply only to vault transfer. Ongoing message
encryption is unaffected.

---

## 1.0.2 — MIME Encoding Fix — 2 May 2026

BUGFIX — apply when convenient.

**Fixed double base64 encoding in IMAP transport.**

Using utf-8 charset in MIMEText caused the MIME library to apply
an additional base64 encoding on top of content that was already
base64 encoded. This expanded the vault from ~52MB to ~71MB on
Posteo and added ~25% overhead to every message.

Fixed by using us-ascii charset with explicit 7bit Content-Transfer-
Encoding. Pure ASCII base64 content now passes through the MIME
library without additional encoding.

Impact:
- Vault on Posteo: ~71MB reduced to ~53MB
- Per message: ~25% smaller on wire
- Content and security unaffected

---

## 1.1.0 — Ephemeral Mode — 3 May 2026

FEATURE — apply at your discretion.
NOTE: Requires generating a new vault. Existing vaults
continue to operate in standard mode without any change.

**Ephemeral mode: no message history, pad material destroyed
after use.**

Standard mode saves decrypted messages to an encrypted local
history database. For some threat models this is undesirable:
even encrypted history is a stored record that exists on the
device. Ephemeral mode eliminates this entirely.

**How it works:**

Ephemeral mode is chosen by the vault initiator (Alice) at
vault generation time. The choice is encoded as a flag bit in
the vault file and propagates automatically to the importer
(Bob) during vault exchange. Both parties operate in the same
mode without any additional coordination.

On send (ephemeral mode):
- Message is encrypted and transmitted normally
- The message is NOT saved to local history
- The pad bytes used for encryption are immediately overwritten
  with fresh random data (os.urandom) in memory and on disk

On receive (ephemeral mode):
- Message is decrypted and displayed normally
- The message is NOT saved to local history
- After reading, the user is prompted: "Ready to delete? (yes/no)"
- On "yes": pad bytes overwritten with random data, vault saved
- On "no": message remains visible for the current session only
  and is never written to disk in any form

**What ephemeral mode protects against:**

An adversary with access to the device after a session finds:
- No message history file containing readable correspondence
- No pad material that could be used to re-derive message content
  (the pad bytes are overwritten, not merely marked used)
- The vault file with used pad slots randomised

**What ephemeral mode does not protect against:**

- Observation of the screen during a session
- Memory forensics immediately after a session (decrypted message
  content exists in process memory during display)
- Compelled disclosure of the vault passphrase (the vault
  structure and used-pad index remain on disk)
- The sequence counter in the vault index (an adversary can
  determine how many messages were exchanged, but not their
  content or timing)

**Technical changes:**

Vault format version advances from 1 to 2. Magic bytes change
from LBVAULT1/LBTRANS1 to LBVAULT2/LBTRANS2. A 2-byte FLAGS
field is appended to the vault header. Bit 0 (VAULT_FLAG_EPHEMERAL
= 0x0001) carries the ephemeral mode setting. Version 2 clients
read version 1 vaults correctly; version 1 clients cannot open
version 2 vaults and will report a version mismatch.

VaultData.pads is now stored as a bytearray (previously bytes)
to allow in-place overwrite by erase_pad() without copying the
full 39MB pad data. VaultData.erase_pad(pad_id) overwrites one
pad slot with os.urandom(PAD_SIZE).

Both parties must be running v1.1.0 or later to use ephemeral
vaults. Parties running v1.0.x will fail to open a v2 vault
with a version mismatch error. Standard (non-ephemeral) v2
vaults are forward-compatible: a v1.1.0 client generates a
non-ephemeral v2 vault by default and it opens correctly on
both versions.

**Choosing a mode:**

Use standard mode (default) if:
- You want a searchable, navigable history of your correspondence
- Your device security (passphrase strength, iOS encryption,
  Physical security) is sufficient to protect the history database
- You may need to refer back to earlier messages

Use ephemeral mode if:
- Your threat model includes adversarial physical access to
  your device after sessions
- You do not need a persistent record of correspondence
- You prefer that no message content ever touches the
  filesystem in any form
