# Security

## Cryptographic Design

### Encryption

Letterbox uses the **one-time pad** — the only provably information-theoretically secure cipher. A message encrypted with a truly random pad of the same length reveals nothing about the plaintext to an adversary with unlimited computational resources.

Each message consumes exactly one pad. Pads are never reused. After use, pad bytes are immediately overwritten with zeros in the vault file.

### Key Derivation

The vault and credentials files are encrypted at rest using:

1. **PBKDF2-HMAC-SHA256** to derive a key from the passphrase and a random salt
   - Personal vault: 200,000 iterations
   - Transfer vault: 2,000,000 iterations (one-time cost for vault exchange)
2. **SHA256 counter-mode keystream** XOR'd with the plaintext
3. **HMAC-SHA256** of the ciphertext prepended to the file (authenticated encryption)

The salt is stored in plaintext at the beginning of each encrypted file. This is standard practice — the salt's purpose is to prevent precomputation attacks, not to be secret.

### Message Authentication

Every transmission includes a truncated HMAC tag derived from the pad material. This authenticates the message and detects tampering. A message that fails authentication is discarded without decryption.

### Subject Line Obfuscation

The email subject line carries `HMAC(subject_key, pad_id)[:8]` as hex rather than the pad ID directly. This prevents a transport observer from inferring:

- How many messages have been exchanged
- The order of messages
- Which pad was used for a given message

The subject key is a 32-byte random value shared in the vault, unknown to any party who does not have the vault.

### Replay Protection

The vault maintains a bitmap of used pads. A pad marked used cannot be used again — attempting to receive with a used pad raises an error and the message is discarded.

### Rollback Detection

The config file maintains a send sequence counter. On each launch, the counter is compared to the number of used send pads in the vault. If the vault appears to have been restored from a backup (counter exceeds used pads), the app locks and requires data reset.

---

## Threat Model Summary

| Threat | Mitigation |
|---|---|
| Passive interception of messages | OTP — mathematically unbreakable |
| Active tampering with messages | HMAC authentication — tampered messages discarded |
| Replay of old messages | Pad bitmap — replayed messages rejected |
| Vault file theft | PBKDF2 + HMAC — requires passphrase to decrypt |
| Transfer vault interception | 2M PBKDF2 iterations + six-word phrase required |
| Pad reuse | Pad erased immediately after use |
| Vault restore from backup | Rollback detection via sequence counter |
| Subject line metadata | HMAC obfuscation of pad ID |

For the full threat model see [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Known Limitations

### This is a proof of concept

Letterbox has not been audited by an independent security professional. It may contain implementation errors, design flaws, or vulnerabilities not identified during development.

### Passphrase security

The passphrase is the only key protecting your vault and credentials at rest. A weak passphrase significantly weakens all security guarantees. Use a long, random passphrase and store it securely offline.

### Physical device security

If an adversary has physical access to an unlocked iPad, or to an iPad where the data directory is unencrypted, vault and credential files may be accessible. Enable a strong iPad passcode and ensure the device auto-locks.

### iCloud backup

If iCloud backup is enabled, vault and credentials files may be backed up and accessible to Apple or to anyone who gains access to the iCloud account. Consider disabling iCloud backup for the Pythonista app, or be aware of this risk.

### Transfer vault

The transfer vault (`letterbox_transfer.txt`) contains all pad material for both correspondents. It must be deleted from all devices and transfer media immediately after import. If intercepted along with the protection phrase, it gives full access to the vault.

### Transport metadata

Posteo can see that two parties are exchanging messages (the IMAP folder exists), the approximate time of each message, and the message size (fixed at 1,024 bytes). The subject line and content are protected. Use a Posteo account that cannot be linked to your real identity if this is a concern.

### No anonymity

Letterbox does not provide anonymity. It protects the content of communications, not the identities of the parties.

---

## Responsible Disclosure

This is a personal proof-of-concept project. If you identify a security issue, please open a GitHub issue or contact the maintainer directly.
