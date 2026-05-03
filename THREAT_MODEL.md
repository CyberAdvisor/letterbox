# Threat Model

Read this before using the application for 
anything you consider sensitive.

Not as a formality. Actually read it.

---

## What This Application Is

Private correspondence between two people 
who know each other, using one-time-pad 
encryption. The encryption is 
information-theoretically secure — given 
a properly generated pad, message content 
cannot be recovered by any attacker 
regardless of computing resources.

---

## What This Protects Against

### Content Interception in Transit

Messages travel as encrypted blobs via 
IMAP to a shared Posteo account used as 
a dead drop. An attacker who intercepts 
this traffic sees random-looking data 
they cannot decrypt. This includes your 
internet provider, Posteo, governments 
requesting data from Posteo, and anyone 
monitoring network traffic.

The connection to Posteo uses TLS. 
The content is protected by both the 
TLS transport layer and your one-time-pad 
encryption independently.

### Bulk Passive Surveillance

Messages contain no identifying plaintext 
content. Automated surveillance systems 
cannot extract meaning from the traffic.

### Platform Data Breaches

If Posteo is breached, attackers obtain 
encrypted blobs they cannot read without 
your vault. The vault lives only on 
your device. Posteo holds no key 
material and cannot decrypt messages.

### Future Computing Advances

One-time-pad encryption has no mathematical 
hardness assumptions. There is no equation 
to solve, no key to factor, no discrete 
logarithm to compute. A quantum computer 
provides zero advantage to an attacker. 
A message encrypted today will be equally 
secure in 50 years.

### Post-Session Device Forensics (Ephemeral Mode Only)

Pad key material is always overwritten 
with random data after use, in both 
standard and ephemeral modes. A used pad 
slot contains random bytes, not the 
original key material.

Ephemeral mode goes further: messages 
are never written to the history database. 
After a "Ready to delete?" confirmation, 
the message is discarded without being 
written to disk.

An adversary who obtains the device after 
a session in ephemeral mode and knows or 
compels the passphrase finds:
- No message history
- No recoverable pad material for 
  messages already deleted
- Only the vault file with used slots 
  containing random data

This protection applies only to messages 
that have been deleted. Messages kept 
in session (answered "no" to delete) 
are not written to disk but exist in 
process memory while the app is running.

### Email Provider Surveillance

This application does not use email to 
transmit messages. Email providers cannot 
read your correspondence.

---

## What This Does Not Protect Against

### Physical Device Access

Anyone with access to your unlocked iPad 
can read your decrypted message history 
(standard mode) or observe messages on 
screen during a session (both modes).

In standard mode the vault passphrase 
protects vault files at rest, but 
decrypted messages in the history 
database are a persistent record.

In ephemeral mode no message history 
is stored. An adversary with the 
passphrase after a session cannot 
recover deleted messages. Messages 
not yet deleted are visible during 
the session only.

Mitigations (all modes):
- Use a strong iPad passcode — not a 
  4-digit PIN
- Enable Face ID or Touch ID
- Set auto-lock to the shortest 
  comfortable interval
- Never leave your iPad unlocked 
  and unattended
- In ephemeral mode: confirm deletion
  promptly after reading

### Your Contact

If your contact chooses to show your 
messages to someone else — by handing 
over their device, screenshotting, 
or retyping content — nothing in this 
system prevents that.

You are trusting your contacts personally. 
This system protects your correspondence 
from outsiders. It does not protect you 
from the people you are corresponding with.

### Legal Compulsion Directed at You

A court order can compel you to provide 
your vault passphrase or decrypt your 
messages. This system does not protect 
against lawful legal process directed 
at you personally.

### Communication Metadata

Posteo knows that a shared account is 
accessed from two locations and that 
messages are created and deleted in it. 
A sophisticated observer can infer:

- That two people are in communication
- Approximately how often they communicate
- Roughly when communication occurs

This system hides what you say. 
It does not hide that you are 
saying something.

### Vault Exchange Impersonation

If you exchange a vault with someone 
impersonating your intended contact, 
that person can read everything you 
subsequently send.

In-person exchange is the strongest 
protection against this. Video call 
exchange is adequate for people whose 
face and voice you know well. Do not 
exchange vaults with people you cannot 
positively identify.

### Posteo Account Compromise

If the shared Posteo account credentials 
are compromised, an attacker can access 
the message dead drop. They receive 
encrypted files they cannot read without 
your vault. However they can delete 
incoming messages before you collect 
them, creating gaps in your 
correspondence.

Protect the Posteo app password. Use a 
strong unique password for the Posteo 
account itself and enable two-factor 
authentication on the Posteo account 
if available.

### Vault Files Outside the Device

The vault file must only exist on the device it was 
created for. It must not be copied to iCloud Drive,
emailed, placed in a shared folder, or stored in any
cloud service as a backup or convenience measure.

The vault is encrypted and requires your passphrase 
to open. However, a copy stored in iCloud, Google 
Drive, or any other cloud service is:

- Accessible to that service provider
- Subject to legal requests directed at that provider
- Exposed if your cloud account is compromised
- Available to anyone who gains access to your account
  on any of your devices

The correct mental model is: the vault is bound to 
the physical device. If the device is lost or damaged 
the vault is lost. This is intentional. A vault that 
can be restored from a backup can also be stolen from 
a backup.

If you need to replace your device, generate a new 
vault on the new device and exchange it with your 
contact. Do not transfer the old vault.

The script files (main.py and the letterbox_code 
folder) may be stored in iCloud Drive -- they are 
code, not secrets. Only the data files must remain 
local: vault.dat, credentials.dat, history.db, and 
config.dat. These are stored in Pythonista's local 
Documents folder (~/Documents/letterbox) and are 
not synced to iCloud unless you have explicitly 
enabled iCloud sync for Pythonista in iOS Settings.

### Device Compromise by Sophisticated Attackers

If your iPad is compromised by malware 
capable of escaping iOS's sandbox, your 
vault and messages could be exposed. 
iOS sandboxing is strong. Defeating it 
requires sophisticated attacks typically 
only available to state-level adversaries 
with significant resources.

If you believe you are a target of a 
state-level adversary, read the next 
section carefully.

---

## Physical Coercion

No encryption protects you against 
someone who can threaten or harm you 
or people you care about until you 
hand over your passphrase.

This includes:

- Government agencies with detention powers
- Law enforcement with legal compulsion
- Criminals willing to use violence
- Anyone with leverage over you personally

If someone can get you alone, your vault 
passphrase will be provided. Your message 
history will be readable. There is no 
technical solution to this.

This is not a weakness of this application 
specifically. It is a weakness of every 
encryption system ever built.

See xkcd.com/538.

It does not protect you from people who 
can put you in a dark room and beat you 
with a $5 wrench.

If you are in a situation where 
nation-state actors or dangerous criminals 
have reason to target you personally:

Stop.

This application is not for you.
No consumer application is for you.
You need professional operational security 
advice from people who specialize in 
exactly your situation.

Using this application — or Signal, or 
any other consumer tool — while believing 
it protects you against a determined 
adversary willing to use physical or 
legal coercion is dangerous overconfidence 
that could get you or people you care 
about seriously hurt.

---

## Suitable Use Cases

- Private family correspondence
- Sensitive personal communications 
  between trusted individuals
- Business correspondence requiring 
  long-term confidentiality
- Communications where you need certainty 
  that no company can ever access content
- Correspondence whose sensitivity 
  extends decades into the future

## Unsuitable Use Cases

- Communicating with people you haven't 
  verified in person or by video
- Situations requiring anonymity
- Real-time or emergency communication
- Any situation where you believe you 
  are being actively targeted by a 
  nation-state or criminal organization

---

## Other Platforms

This threat model applies only to iPad 
running Pythonista 3.

Running this application on any other 
platform invalidates every security 
claim made in this document.

No security claims whatsoever are made 
for any other platform.
