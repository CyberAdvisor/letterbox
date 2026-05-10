# Threat Model

## Assumptions

### What we assume about the adversary

- The adversary can observe all network traffic between the iPad and Posteo
- The adversary can read all email subject lines, headers, and metadata
- The adversary cannot read message bodies (encrypted OTP)
- The adversary cannot modify messages in transit without detection (HMAC)
- The adversary does not have access to the vault, passphrase, or device
- The adversary may have access to one or both Posteo accounts (if credentials are compromised)

### What we assume about the environment

- The iPad is physically secure and not compromised by malware
- iOS filesystem encryption is active (device has a passcode)
- Pythonista 3 is running genuine code from the App Store
- The random number generator (`os.urandom`) is cryptographically secure
- The shared Posteo account credentials are known only to Alice and Bob

---

## Threats and Mitigations

### T1 — Passive interception of message content

**Threat:** Adversary reads message bodies from the IMAP folder or network traffic.

**Mitigation:** Messages are encrypted with a one-time pad. The ciphertext reveals zero information about the plaintext to an adversary without the pad material. This is information-theoretically secure — no computational power can break it.

**Residual risk:** None, provided pads are truly random and never reused.

---

### T2 — Active tampering with messages

**Threat:** Adversary modifies a message in transit.

**Mitigation:** Every message includes HMAC-SHA256 authentication derived from the pad material. A tampered message will fail authentication and be discarded. The adversary cannot forge a valid HMAC without the pad.

**Residual risk:** The adversary can delete messages (denial of service) but cannot forge or modify them undetected.

---

### T3 — Replay attack

**Threat:** Adversary captures and re-delivers an old message.

**Mitigation:** Each pad is marked used after a single use. A replayed message uses the same pad ID, which is already marked used in the bitmap. The message is rejected as a duplicate.

**Residual risk:** An adversary can cause a duplicate detection warning but cannot successfully deliver the replayed content.

---

### T4 — Pad reuse

**Threat:** The same pad is used twice, revealing the XOR of two plaintexts.

**Mitigation:** Pads are marked used before transmission. After use, pad bytes are immediately overwritten with zeros. The vault bitmap prevents any pad from being selected twice.

**Residual risk:** None in normal operation. An adversary with access to a vault backup predating the use of a pad could theoretically obtain the pad bytes — see T9.

---

### T5 — Vault file theft

**Threat:** Adversary obtains `vault.dat` from the device.

**Mitigation:** The vault is encrypted with PBKDF2-HMAC-SHA256 (200,000 iterations) using the passphrase and a random salt. Without the passphrase, the vault is computationally infeasible to decrypt with a strong passphrase.

**Residual risk:** A weak passphrase significantly reduces resistance to offline brute force. Use a strong passphrase.

---

### T6 — Transfer vault interception

**Threat:** Adversary intercepts `letterbox_transfer.txt` during delivery to Bob.

**Mitigation:** The transfer vault is encrypted with PBKDF2-HMAC-SHA256 using 2,000,000 iterations and a six-word protection phrase (~57 bits of entropy). The adversary also needs the protection phrase, which must be delivered separately.

**Residual risk:** If both the file and the phrase are intercepted, the adversary has full vault access. Deliver them through separate channels.

---

### T7 — Credentials compromise

**Threat:** Adversary obtains Posteo credentials.

**Mitigation:** Credentials are encrypted at rest with PBKDF2 + HMAC using the same passphrase as the vault. An adversary with the credentials file but not the passphrase cannot read them.

If the plaintext credentials are compromised (e.g. observed during entry), the adversary can access the Posteo account. They can read message subject lines and metadata, and delete messages (denial of service). They cannot read message content without the vault and passphrase.

**Residual risk:** Use a Posteo app password (not the main account password) so that credential compromise is limited to IMAP access.

---

### T8 — Subject line metadata analysis

**Threat:** Adversary infers information from subject line patterns.

**Mitigation:** Subject tokens are `HMAC(subject_key, pad_id)[:8]` — pseudorandom values that reveal nothing about the pad ID, sequence, or message count to an observer without the subject key.

**Residual risk:** The adversary can count messages and observe timing. They cannot determine pad identity or message order.

---

### T9 — Vault restore from backup (rollback)

**Threat:** Alice restores her vault from an old backup, causing pad reuse.

**Mitigation:** The config file maintains a send sequence counter that is compared to the vault's used pad bitmap on each launch. If the vault appears older than the counter (restored from backup), the app locks and refuses to send.

**Residual risk:** If both the vault and config are restored from backup simultaneously, rollback detection fails. Do not restore from backup.

---

### T10 — Physical device compromise

**Threat:** Adversary has physical access to an unlocked iPad.

**Mitigation:** Letterbox does not store the passphrase on disk. The vault and credentials are encrypted at rest. An adversary with physical access to a locked device cannot access vault content.

**Residual risk:** If the device is unlocked and Letterbox is running, the passphrase is in memory (session_store). An adversary with a memory dump of a running process could theoretically extract it.

---

### T11 — iCloud backup

**Threat:** Vault and credential files are backed up to iCloud and accessed by Apple or an adversary who gains iCloud access.

**Mitigation:** Files are encrypted at rest. iCloud backup adds another attack surface for the encrypted files, but the content cannot be read without the passphrase.

**Residual risk:** If iCloud is compromised and the passphrase is weak, files could be brute-forced offline. Consider disabling iCloud backup for Pythonista.

---

### T12 — Brute force passphrase attempts

**Threat:** Adversary repeatedly tries passphrases against the vault, either at the device or against a copy of `vault.dat`.

**Mitigation:** Each attempt costs ~0.5 seconds (200,000 PBKDF2 iterations). In addition, the app enforces escalating delays after failed attempts (30s, 1m, 5m, 30m) stored in `config.dat` — these survive quit-and-restart. After 10 consecutive failures all data files are wiped with a 3-pass random overwrite before deletion.

**Residual risk:** An adversary with a copy of `vault.dat` can attempt offline brute force without delay enforcement. The KDF cost (200,000 iterations, ~0.5s/attempt) and passphrase entropy (~57+ bits for a strong passphrase) make exhaustive search computationally infeasible.

---

### T13 — Coerced unlock

**Threat:** Adversary compels the user to unlock the vault under duress.

**Mitigation:** An optional duress passphrase can be configured in `core/constants.py`. Entering it at any unlock prompt silently wipes all data (3-pass random overwrite of all data files) and returns "Wrong passphrase." — indistinguishable from a normal failed entry. The check fires instantly before any delay or KDF work.

**Residual risk:** The duress passphrase is stored in plaintext in `constants.py`. An adversary with access to the source files can read it. The duress feature is most effective against an adversary who does not have prior access to the device.

---

## Out of Scope

The following threats are outside the scope of this proof of concept:

- **Compromised iOS / Pythonista** — if the platform is compromised, all bets are off
- **Side channel attacks** — timing, power analysis, etc.
- **Social engineering** — adversary tricks Alice or Bob into revealing passphrase or pads
- **Denial of service** — adversary floods or deletes messages from Posteo
- **Anonymity** — Letterbox protects content, not identity
- **Key escrow** — there is no recovery if the passphrase is forgotten
