# Design Decisions

This document records the significant design choices made during 
the development of Letterbox v1.0, and the reasoning behind each.
It exists so that future contributors, reviewers, and users 
understand not just what was built but why.

---

## Terminology: Stamps vs Pads

The underlying cryptographic primitive is a one-time pad (OTP).
Throughout the codebase, constants, and technical documentation
the word **pad** is used: `PAD_SIZE`, `PAD_COUNT`, `reserve_send_pad`,
`erase_pad`, `VaultData.send_pads`, and so on.

The application UI presents these to the user as **stamps**.
The stamp metaphor was chosen because it is concrete and
self-explanatory to non-technical users: a stamp is used once,
leaves a mark, and you have a finite supply. It carries none of
the cryptographic baggage of "pad" and avoids confusion with
writing pads or notepads.

The choice to use different terminology in the UI versus the code
was deliberate: technical accuracy matters in code and
documentation that developers read; clarity matters in the
interface that users see.

**One stamp = one pad = one message.** They are the same thing.

## What Letterbox Is

Private one-time-pad correspondence between two people who know 
each other personally. Not a messenger. Not anonymous. Not a 
replacement for Signal or iMessage for ordinary use.

Letterbox exists for a specific and narrow set of situations:

- You cannot trust any company with your communications long-term
- Your correspondence needs to remain private for decades
- You want to fully understand and verify your own security
- You need no metadata linking you to your correspondent
- You want encryption that remains secure against future 
  computing advances including quantum computers

For everyone else, Signal is the right choice.

---

## Cryptographic Model

### One-Time Pad

**Chosen because:** OTP is the only encryption system that is 
information-theoretically secure. Given a truly random pad used 
only once, message content cannot be recovered by any attacker 
regardless of computing resources — including quantum computers. 
There are no mathematical assumptions that can be invalidated 
by future advances.

**The tradeoff:** OTP requires secure physical exchange of pad 
material and careful pad lifecycle management. This is acceptable 
given the use case — people who know each other personally and 
meet or communicate by video.

**What was rejected:** Asymmetric cryptography (RSA, elliptic 
curve) is computationally secure but rests on mathematical 
hardness assumptions. A sufficiently powerful quantum computer 
running Shor's algorithm could break elliptic curve cryptography. 
For correspondence whose sensitivity extends decades, this is a 
real concern. Signal uses Curve25519 — excellent for most uses 
but not information-theoretically secure.

### Fixed Block Size — 4096 bytes

**Chosen because:** Fixed size eliminates metadata leakage 
through message length. Every message on the wire is exactly 
4104 bytes (8-byte header + 4096-byte payload). An observer 
cannot distinguish a short note from a long letter. Random 
padding fills unused space within the encrypted payload.

**4096 specifically:** Comfortably fits most correspondence 
(4081 bytes of content after internal headers — approximately 
680 words). Long messages are split across multiple messages 
naturally, which encourages deliberate correspondence rather 
than stream-of-consciousness chat.

**What was rejected:** Variable length messages leak content 
length as metadata. Large fixed blocks (64KB) waste pad 
material for short messages and produce unnecessarily large 
transmissions.

### 10,000 Pads Per Vault

**Chosen because:** Split evenly, each party gets 5,000 send 
pads. At one message per day this is approximately 13 years 
before exhaustion. Sufficient for long-term correspondence 
without requiring frequent re-exchange. Total vault size is 
approximately 39MB — trivially small on any modern device.

### Bundle ID and Pad ID in Plaintext Header

**Chosen because:** The bundle ID identifies which vault to 
use for decryption — essential when a contact has multiple 
vaults across re-exchanges over time. The pad ID identifies 
which specific pad within the vault. Neither reveals anything 
about message content. An observer learns only that two parties 
using this system communicated — which they likely already knew.

### Checksum — SHA256 truncated to 8 bytes

**Chosen because:** Provides tamper detection. An attacker 
who flips bits in the ciphertext in transit will corrupt the 
checksum, and the recipient knows the message was tampered 
with. 8 bytes provides 64 bits of collision resistance — 
adequate for detecting accidental corruption or simple 
tampering. Full 32 bytes would be stronger but 8 bytes is 
sufficient for the threat model and conserves payload space.

### Sequence Numbers

**Chosen because:** Allow detection of missing messages. When 
Bob receives message 4 then message 6, he knows message 5 is 
missing and can ask Alice to resend. Without sequence numbers 
a lost message is invisible — the conversation simply has a 
gap neither party notices.

Sequence numbers live inside the encrypted payload — not 
visible to an observer.

---

## Platform

### iPad with Pythonista 3

**Chosen because:** iOS provides specific security properties 
this application depends on:

- **App sandbox isolation:** Other apps cannot read 
  Pythonista's files. Vault files are structurally 
  inaccessible to malware running in other apps. This 
  protection does not exist on desktop operating systems 
  where any process running as the same user can read 
  any file that user owns.

- **Filesystem encryption by default:** iOS encrypts the 
  entire filesystem using the device passcode. Vault files 
  are encrypted at rest by iOS before Letterbox's own 
  encryption is even considered.

- **No keyloggers possible:** iOS prevents apps from 
  intercepting keyboard input from other apps. The vault 
  passphrase cannot be captured by a keylogger — a 
  realistic attack vector on all desktop platforms.

- **iCloud Advanced Data Protection:** With ADP enabled, 
  iCloud storage is end-to-end encrypted. Apple cannot 
  read files even in response to legal requests.

- **Controlled runtime via Pythonista:** A known, vetted 
  environment with no arbitrary code execution outside 
  the sandbox.

**Pythonista specifically:** Provides Python 3.10 on iPad 
with access to the full standard library. No compilation 
required. Code is visible and auditable directly on device. 
Available on the App Store from Omz:Software, maintained 
since 2012.

**What was rejected:**

- **Android:** Reduced sandbox isolation. Apps with storage 
  permissions can read other apps' files. No equivalent to 
  iOS sandbox protection. os.urandom() entropy quality 
  historically less reliable.

- **Desktop (Mac, Windows, Linux):** No sandbox isolation. 
  Vault files accessible to any process running as the 
  same user. Keyloggers possible on all desktop platforms. 
  No equivalent to iOS filesystem encryption by default.

**These platforms are explicitly not supported.** Running 
Letterbox on any platform other than iPad with Pythonista 3 
invalidates every security claim in this documentation.

### Command Line Interface

**Chosen because:**

- Zero Pythonista-specific dependencies. The `ui` module 
  is Pythonista-only and not available on Mac for testing. 
  A CLI runs identically in Pythonista's console and a 
  Mac terminal.

- Fully testable on Mac. Every line of code can be 
  developed and tested before touching the iPad.

- More auditable. No UI layer to read through. A security 
  reviewer reads fewer files to understand the complete 
  system.

- Appropriate for the audience. Someone who understands 
  the threat model well enough to use this system correctly 
  is comfortable with a text interface.

- Future proof against Pythonista changes. If Pythonista 
  updates break its UI module, or Pythonista becomes 
  unavailable, the code continues to work in any Python 
  environment.

**What was rejected:** Pythonista's native `ui` module 
creates iOS-native UI but is Pythonista-specific, cannot 
be tested on Mac, and creates a dependency on Pythonista's 
specific implementation of iOS APIs.

---

## Transport

### Dead Drop Model — Shared Mailbox

**Chosen because:** Messages never traverse the email 
network as sent mail. A message is written directly to 
a folder in a shared IMAP account using IMAP APPEND. 
The other party reads it by connecting to the same 
account. This means:

- No SMTP logs at either party's email provider
- No sender-recipient linkage in email headers
- No routing metadata
- No spam filter exposure
- The message never moves — it sits in one place 
  until collected

**What was rejected:**

- **Sending email normally:** Creates SMTP logs at both 
  providers. Directly links Alice and Bob via email 
  headers. Exposes messages to spam filters and content 
  scanners.

- **iCloud Drive shared folders:** Pythonista's filesystem 
  access is sandboxed to its own documents directory. 
  Accessing iCloud Drive shared folders belonging to 
  other Apple IDs via filesystem paths is not reliably 
  supported.

- **Dropbox and similar:** External dependency requiring 
  API tokens and third-party accounts. Adds supply chain 
  risk and account management complexity.

### Posteo as Mail Provider

**Chosen because:**

- **Standard IMAP:** Clean conventional IMAP behavior 
  with no non-standard folder naming or label mapping. 
  Gmail maps labels to folders in non-standard ways that 
  complicate folder creation and message management. 
  Posteo follows the IMAP specification.

- **Anonymous signup:** No name, no phone number, no 
  recovery email required. The shared account has no 
  personal information attached to it at creation.

- **No IP logging:** Posteo does not log IP addresses 
  for IMAP, POP3, or SMTP connections. Independently 
  audited and confirmed by the German Federal 
  Commissioner for Data Protection. Even if compelled, 
  there is nothing to hand over about who accessed 
  the account.

- **App-specific passwords:** Supports app passwords 
  so the credential stored in Letterbox is not the 
  main account password.

- **German jurisdiction:** Strong GDPR protections. 
  Transparency reports published. Limited, lawful 
  responses to government requests.

- **Cost:** €1 per month. Negligible for a dedicated 
  correspondence transport account.

- **Reliability:** Commercial service, not volunteer-run. 
  In operation since 2009.

**What was rejected:**

- **Gmail:** Non-standard folder behavior. Labels mapped 
  to folders create complexity. Google mines metadata 
  aggressively. Phone number increasingly required for 
  new accounts.

- **iCloud Mail:** Phone number required at Apple ID 
  creation. Folder behavior moderately non-standard. 
  Account linked to real identity.

- **Disroot:** Free but volunteer-run with uncertain 
  longevity. No audited IP logging policy. Requires 
  recovery email for account creation.

- **Fastmail:** Clean IMAP but more expensive than 
  Posteo for equivalent functionality.

- **Proton Mail / Tuta:** Do not support standard 
  IMAP on free accounts. Letterbox uses imaplib from 
  Python stdlib — proprietary bridge software is not 
  acceptable.

### Message Format — Base64 in Email Body

**Chosen because:** The 4104-byte encrypted transmission 
is base64-encoded to 5476 printable ASCII characters and 
stored as the email body. No attachments. Attachments 
attract extra scrutiny from spam filters and security 
gateways. A consistent base64 body is less distinctive 
than a consistent binary attachment.

The `MSG1:` prefix identifies the message as a Letterbox 
transmission and embeds a protocol version for future 
compatibility.

---

## Storage

### SQLite for Message History

**Chosen because:** SQLite is in Python's standard library. 
No external dependencies. Reliable, well-tested, handles 
concurrent access correctly. A contact_id column is present 
from day one to support multiple contacts in future versions 
without schema changes.

### Single Passphrase Protecting Everything

**Chosen because:** One passphrase protects three things — 
the vault file, the credentials file, and the message 
history database. One key derived from it via PBKDF2 
encrypts all three.

This gives the user one thing to remember and one mental 
model: the passphrase protects everything. No partial 
protection, no split model.

**The tradeoff:** If the passphrase is lost, everything 
is gone — vault, credentials, and history. There is no 
recovery. This is stated clearly to users at setup. It 
is a feature not a bug — a recovery mechanism would 
require a second secret or a trusted party, both of 
which introduce new attack surfaces.

### Decrypted Messages Stored in History

**Chosen because:** Messages are decrypted on receipt 
and stored in plaintext in the encrypted SQLite database. 
The pad is consumed once and gone.

**What was rejected:** Storing ciphertext for re-decryption 
later is architecturally awkward with OTP. The pad is 
marked used after first decryption — re-decrypting later 
would require bypassing the replay detection or storing 
the pad alongside the ciphertext, both of which 
compromise the pad lifecycle design.

### PBKDF2 with 200,000 Iterations

**Chosen because:** Makes brute-force attacks against 
the passphrase computationally expensive. 200,000 
iterations of SHA-256 via PBKDF2 is within Python's 
standard hashlib library — no external dependencies. 
Standard, audited, and well-understood.

---

## Security Model

### Physical Vault Exchange

**Chosen because:** In-person or video call exchange is 
the strongest possible identity verification. The person 
handing you the vault is demonstrably the person you 
think they are. No PKI, no certificate authorities, no 
key signing — just a face and a voice you recognize.

**Video call as acceptable alternative:** For people 
who know each other well enough to recognize face and 
voice, a video call exchange provides adequate identity 
verification without requiring physical proximity. 
The passphrase travels by voice only — never written 
or transmitted digitally.

### Separate Passphrases Per Person

**Chosen because:** After the vault exchange, Alice 
encrypts her copy with her own passphrase and Bob 
encrypts his copy with his own. Neither party needs 
to know the other's passphrase after the exchange. 
A passphrase compromise affects only one party's copy.

**The exchange passphrase** is temporary — used only 
to protect the vault file during transfer, then 
discarded. Each party immediately re-encrypts with 
their personal passphrase after import.

### No Forwarding

**Chosen because:** Per-recipient encryption means 
Bob receives a version of Alice's message encrypted 
to his specific pad. He can decrypt it but cannot 
forward a cryptographically authentic version. 
Copy-pasting the plaintext is possible but removes 
all authenticity — it is just text, not a verifiable 
signed message.

The client has no forward or reshare function. 
Forwarding is a violation of the social contract 
of this system, not just a missing feature.

### Visible Passphrase Entry

**Chosen because:** Pythonista's console on iPad is 
subject to autocorrect and autocapitalize. An invisible 
passphrase entry combined with iOS autocorrect could 
silently alter what the user types, locking them out 
with no explanation. Visible entry lets the user see 
exactly what was entered and catch autocorrect 
interference before it causes a lockout.

The security tradeoff — someone nearby can see the 
passphrase — is mitigated by the instruction to enter 
the passphrase when alone. This is a behavioral 
control appropriate for the target audience.

### 10 Failed Attempt Limit Per Session

**Chosen because:** Provides mild friction against 
casual brute-force attempts on an unattended device. 
After 10 failures the app exits — the user relaunches 
to try again. This is not a hard lockout. The real 
protection is the passphrase strength and iOS sandbox, 
not the attempt counter.

The counter resets on relaunch. A determined attacker 
with physical access can relaunch repeatedly. The 
counter protects against opportunistic casual guessing, 
not a determined adversary. This is consistent with 
the stated threat model.

### Failed Attempt Warning

**Chosen because:** If someone attempted to access the 
vault between the user's sessions, the user should know. 
The failed attempt count and last attempt timestamp are 
stored in the unencrypted config file — the only thing 
that can be written before the vault is unlocked. On 
successful login after failures, the user sees a warning 
with the count and absolute timestamp.

---

## Development Decisions

### Pure Python Standard Library

**Chosen because:** Zero external dependencies means 
zero supply chain attack surface from third-party 
packages. A compromised pip package cannot exfiltrate 
vault data if there are no pip packages. The entire 
dependency surface is Python 3.10's standard library — 
stable, audited, and version-controlled by the Python 
Software Foundation.

### Python 3.10 Target

**Chosen because:** Pythonista 3.4 runs Python 3.10 
exactly. Writing for 3.10 ensures identical behavior 
on Mac during development and on iPad during use. 
No syntax features from 3.11 or later are used.

### AI-Assisted Development

**Acknowledged because:** This application was 
developed using AI-assisted tools by an experienced 
information security professional who is not a 
professional cryptographer or Python developer. 
The implementation has not been independently audited.

AI tools can produce code that appears correct but 
contains subtle implementation errors. Security-critical 
operations — random number generation, pad lifecycle 
management, vault encryption — may have edge cases 
that have not been identified.

The cryptographic primitive — XOR with a truly random 
one-time pad — is sound. The surrounding implementation 
may not be. Independent review is strongly encouraged. 
See SECURITY.md for how to report vulnerabilities.

### GPL v3 License

**Chosen because:** Any distribution of this software, 
modified or unmodified, must remain open source. A 
closed-source fork of a security tool cannot be 
audited. Forks must remain open. This protects users 
from a malicious actor taking the code, adding 
surveillance features, and distributing a closed 
binary that users cannot verify.

---

## Deliberate Limitations

### No Push Notifications

Letterbox has no background processes and no push 
notifications. The user checks for messages by 
opening the app and tapping Check. This is a 
deliberate choice — correspondence does not require 
instant notification. It also removes the need for 
any always-on network connection or background 
process, both of which expand the attack surface.

### Text Only

Version 1.0 supports text correspondence only. 
No images, no file attachments, no media. 
4096-byte blocks are sufficient for substantive 
text messages. Media sharing would require either 
much larger blocks wasting pad material, or a 
separate file transfer mechanism adding complexity. 
This may be revisited in a future version.

### Two People Only

Version 1.0 supports correspondence between exactly 
two people. The data structures are designed to 
support multiple contacts in future versions — 
contact ID columns are present in the database, 
vault files are stored in contact-specific directories 
— but the v1 interface exposes only one conversation. 
Adding multi-contact support in v2 requires no 
architectural changes, only additional UI and 
contact management logic.

### No Anonymity

Letterbox is not an anonymity tool. Your contact 
knows who you are. Your Posteo account, while created 
without personal information, is accessible from your 
IP address. The system hides message content. It does 
not hide that you are communicating or with whom.

---

## What This System Does Not Protect Against

Recorded here as a design acknowledgment, not just 
documentation. These are not oversights — they are 
accepted limitations consistent with the threat model.

**Physical coercion:** No encryption protects against 
someone who can threaten or harm you until you provide 
your passphrase. This system does not protect you from 
people who can physically or legally threaten you 
in order to access your messages.

**Participant betrayal:** Your contact can show your 
messages to anyone. The system prevents automated 
forwarding. It cannot prevent a participant who 
chooses to share your correspondence.

**Legal compulsion:** A court order can compel you 
to provide your passphrase. This system does not 
protect against lawful legal process directed at 
you personally.

**Compromised device:** A state-level adversary 
with a zero-day iOS exploit can escape the sandbox. 
No consumer software protects against this. If you 
are actively targeted by a nation-state, this 
application is not suitable for your needs.

**Communication metadata:** Posteo knows two accounts 
regularly access a shared folder. Timing and frequency 
of correspondence is observable. Content is not.

---

## Ephemeral Mode

### No Message History Option (added v1.1.0)

**Problem identified:** Standard mode saves decrypted messages
to an encrypted local history database. For some threat models
this is undesirable. Even encrypted, history is a persistent
record of correspondence on the device. An adversary with physical
access and the passphrase -- or a future computing advance that
breaks the storage encryption -- can read it. An adversary with
physical access without the passphrase knows that correspondence
occurred (the history file exists) even if they cannot read it.

**Solution:** Ephemeral mode. When Alice generates the vault she
is asked whether to enable it. The choice is stored as a flag
bit in the vault file itself and propagates automatically to
Bob during vault exchange. No separate coordination is required;
both parties operate in the same mode.

**Design decisions:**

The flag lives in the vault rather than in config or credentials
because:
- It is a property of the correspondence relationship, not of
  the individual party or account
- It must be identical on both sides without explicit coordination
- The vault is already the authoritative shared state
- Config is unencrypted and inappropriate for security settings

The flag is immutable after vault generation. Changing the mode
mid-correspondence would create an inconsistent history: some
messages recorded, some not. The correct path for a mode change
is generating a new vault.

**Pad erasure is unconditional — both modes, send and receive:**
After every successful send and every successful receive, the pad
bytes are overwritten with os.urandom(PAD_SIZE) in memory and the
vault is saved to disk. This applies in both standard and ephemeral
modes. The original key material is not recoverable from the vault
file after a message is exchanged, regardless of mode.

This means that even if an attacker obtains the vault file after
the fact and also has a copy of the ciphertext (from network
capture or Posteo logs before deletion), they cannot reconstruct
the plaintext because the key is gone.

**Send flow:**
Pad erased immediately after successful transmission. In standard
mode the message is also saved to history. In ephemeral mode it
is not.

**Receive flow:**
Pad erased immediately after successful decryption, before the
message is displayed. In ephemeral mode the user is then prompted
"Ready to delete? (yes/no)". This prompt controls whether the
message text remains visible in session memory — the pad is
already gone either way. On "no" the message text stays in memory
for the current session and is discarded when the app closes; it
is never written to disk in any form.

**Pad erasure design:**
Marking a pad used (setting vault.index[pad_id] = True) prevents
reuse. Erasing the pad (overwriting vault.pads[start:end] with
os.urandom) prevents key material recovery from the vault file.
Both operations are required for complete forward security of
the specific message. The erasure writes genuinely random bytes,
not zeros, so the vault file structure is preserved and the
erased slot is indistinguishable from an unused pad.

**What ephemeral mode does not eliminate:**
- The vault file itself (its existence is observable)
- The used-pad index (an observer can count how many messages
  were exchanged, but not their content)
- Memory contents during the session (the decrypted message
  exists in Python process memory while displayed)
- Screen observation during reading

**What was rejected:**
- Storing the ephemeral choice in config: config is unencrypted
  and should not contain security policy
- Storing it in credentials: credentials are per-party, not
  per-relationship, and Bob would need to independently set the
  same value
- Allowing mode change after setup: creates inconsistent history
  and adds complexity for minimal benefit

## Post-Initial-Design Decisions

### Random Pad Assignment (added during development)

**Problem discovered:** The original design used a fixed split —
pads 0-4999 for the initiator, 5000-9999 for the importer. This
meant an observer watching the shared Posteo folder could determine
message direction from the pad ID in the plaintext header. Messages
with pad IDs below 5000 came from Alice; above 5000 from Bob.

**Solution:** At vault generation time, all 10,000 pad IDs are
randomly shuffled. The first 5000 are assigned to the initiator,
the remaining 5000 to the importer. The assignment is stored in
the vault file header (as a sorted list of uint16 values, 10000
bytes). When Bob imports the transfer vault, reencrypt_vault
automatically swaps his send_pads to the complement.

From outside, pad IDs now appear random across the full 0-9999
range. An observer cannot determine direction from pad ID values.

**Own-message filtering:** With a shared folder, both parties post
to and read from the same location. Own-message filtering uses
the send_pads set: any message whose pad ID is in the receiver's
send_pads set was sent by them, not their contact. Filtering
happens at two layers:
  1. Transport layer: subject line checked before download
  2. Pad layer: lookup_receive_pad rejects own-pad IDs

### Disclaimer and Inbox UI (added during development)

**Disclaimer:** Shown once ever. Agreement stored in config.dat
as a single byte. Existing installs without the byte (60-byte
config) default to not agreed and see it once on next startup.

**Inbox model:** The original design showed the full conversation
on every menu display. Replaced with inbox model: main menu shows
status only, checking shows only new messages received this
session, history is separately paged at 5 messages per page
starting from most recent.

### Transfer Vault Security Hardening (added during development)

**Problem identified:** The transfer vault sits on the Posteo server
during the exchange window — potentially minutes to hours or longer.
An attacker who obtains this file has unlimited time for offline
cracking. The original four-word passphrase provided approximately
38 bits of entropy, which is insufficient for a file exposed to
offline attack on a third-party server.

**Change 1: Transfer passphrase increased from 4 to 6 words.**

Four words from a 696-word list:
  696^4 = ~234 billion combinations = ~38 bits of entropy

Six words from the same list:
  696^6 = ~113 trillion combinations = ~57 bits of entropy

Six words provides ~500,000x more combinations. The tradeoff is
a slightly longer verbal exchange -- six words instead of four.
This remains practical for in-person or video call communication.

**Change 2: Transfer vault KDF iterations increased 10x.**

Personal vaults and credentials use 200,000 PBKDF2-SHA256
iterations. Transfer vaults now use 2,000,000 iterations.

Each offline cracking attempt against the transfer vault now
requires approximately 10x more computation. Measured on Mac:
personal vault KDF takes 0.116s, transfer vault KDF takes 1.163s.

The one-time cost to Bob importing the vault is ~10-15 seconds
on iPad -- acceptable for a single setup operation.

**Combined effect:**
The two changes together make the transfer vault approximately
5,000,000x harder to crack by brute force than the original
design. The attack remains theoretically possible but the
resources required are now serious rather than trivial.

**Residual risk acknowledged:**
Physical exchange (AirDrop or USB) eliminates this risk entirely
because the vault never touches any server. For users whose
threat model includes well-resourced adversaries with access to
Posteo, physical exchange is the recommended path and is
documented in INSTALL.md.

**Implementation:**
derive_vault_key() in store/vault.py accepts an is_transfer
parameter. When True it uses KDF_TRANSFER_ITERATIONS instead of
KDF_ITERATIONS. save_vault() and load_vault() pass vault.is_transfer
and the is_transfer parameter respectively to derive_vault_key().
generate_transfer_passphrase() in util/random.py generates 6 words
instead of 4.


### Physical Vault Transfer (implemented v2.0)

**Decision:** Both Posteo and file-based vault transfer are supported.
During setup Alice and Bob each choose their transfer method
independently at the start of the setup flow.

**Implementation:**
- Setup screen presents two transfer choices immediately after role
  selection: Posteo (upload/download over IMAP) or File (AirDrop or
  Files app).
- Alice (file path): generates vault, saves encrypted transfer vault
  to `letterbox_transfer.vault` in the data directory, displays the
  transfer phrase. She shares the file manually via AirDrop or the
  Files app and provides the transfer phrase to Bob.
- Bob (file path): locates the file in his data directory (or enters
  the path), enters the transfer phrase, and the vault decrypts and
  re-encrypts with his passphrase. The transfer vault file is deleted
  after successful import.
- Posteo credentials for ongoing message exchange are collected as a
  separate step after vault exchange in all paths. For the Posteo
  transfer path, Alice's credentials are collected before upload and
  reused for messaging. For the file transfer path, both parties
  enter credentials after the vault exchange.
- The transfer vault file is always encrypted with the 2,000,000-
  iteration KDF and the 6-word transfer phrase regardless of how it
  is transmitted. File transfer eliminates the Posteo server exposure
  window; the encryption protects it regardless.

**Security advantage of file transfer:**
Physical transfer eliminates the Posteo exposure window entirely.
With Posteo upload, the encrypted vault exists on a third-party
server between Alice uploading and Bob downloading -- potentially
hours or longer. With file transfer the vault moves directly between
devices with no server involvement. This is the preferred path for
users whose threat model includes well-resourced adversaries with
access to Posteo infrastructure.

**AirDrop note:**
AirDrop is not triggered programmatically. Alice saves the file to
the Letterbox data directory and then uses the iOS Files app or
AirDrop manually. This avoids a dependency on Pythonista's ui module
and keeps the transport layer in plain Python stdlib.
