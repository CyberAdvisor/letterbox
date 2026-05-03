# Security Policy

## Supported Versions

Only the current release receives 
security attention.

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes       |

---

## Reporting a Vulnerability

Report security vulnerabilities privately 
before public disclosure.

Do not open a public GitHub issue for 
a security vulnerability. Public 
disclosure before a fix is available 
puts users at risk.

Contact: [your email address]

I will acknowledge receipt within 48 hours.

I will work toward a fix and coordinated 
disclosure. I will credit you in the 
changelog unless you prefer otherwise.

---

## Scope

Security reports are accepted only for 
the iPad and Pythonista 3 implementation.

Reports concerning other platforms will 
not be addressed. No security claims 
are made for other platforms.

---

## What I Am Most Concerned About

In rough priority order:

**Pad reuse vulnerabilities**
Any code path that could result in the 
same pad being used to encrypt two 
different messages. This is the most 
serious possible failure — it 
catastrophically weakens the encryption.

Scenarios of concern:
- Backup restoration causing index rollback
- Race conditions in multi-device scenarios
- Error handling that retries with the 
  same pad after a failure
- Any state inconsistency between the 
  in-memory vault and the on-disk vault

**Random number generation weaknesses**
Any condition under which os.urandom() 
produces predictable output during 
vault generation. Platform-specific 
entropy pool issues. Conditions at 
first boot or after restore that 
reduce randomness.

**Vault at-rest encryption weaknesses**
Errors in the PBKDF2 key derivation, 
keystream generation, or integrity 
checking that would allow an attacker 
with the vault file to recover contents 
without the passphrase, or to tamper 
with the vault undetected.

**Pad lifecycle errors**
Any sequence of operations — normal 
use, error conditions, or edge cases — 
that results in a pad being marked 
unused when it has already been used.

**Checksum bypass**
Any way to modify message content that 
produces a valid checksum, allowing 
undetected tampering.

---

## What I Am Less Concerned About

- Metadata analysis — acknowledged in 
  the threat model as an accepted 
  limitation
- Attacks requiring physical device 
  access — acknowledged in the 
  threat model
- Platform attacks against iOS itself 
  — outside scope
- Social engineering — outside scope

---

## Disclosure Timeline

I will aim for:

- 48 hours: acknowledgment of report
- 7 days: initial assessment and 
  estimated timeline
- 90 days: fix or public disclosure 
  with your agreement

If a fix requires more than 90 days, 
I will discuss timeline with you.

---

## Recognition

I maintain a hall of fame in CHANGELOG.md 
for responsible disclosures. 

Thank you for taking the time to review 
this code and report issues responsibly.
