# Letterbox

Private correspondence between people
who know each other.

---

## Version 1.2.5 — Proof of Concept

This is a proof of concept. Not a finished
product. Not a professionally audited
security tool. Not production ready.

It works. The cryptographic model is
correct. The iPad implementation
functions as described.

It has not been:
- Independently audited by a professional
  cryptographer
- Penetration tested
- Reviewed for edge cases in production
  use across diverse devices and
  iOS versions

Anyone using this version should read
all documentation — particularly
THREAT_MODEL.md and the disclaimer
section of this README — and make
an informed decision about whether
the limitations are acceptable for
their specific situation.

---

## What You Need to Get Started

- Two iPads (one per person)
- Pythonista 3 on each iPad (~$10, App Store)
- One shared Posteo email account
  (https://posteo.de, ~€1/month)
- A way to provide your contact with
  the six-word transfer phrase

That is the complete list. No other
accounts, services, or subscriptions
are required. The vault exchange can
be done via Posteo or via direct file
transfer (AirDrop). After setup,
Letterbox uses only the shared Posteo
account for ongoing correspondence.

See INSTALL.md for step-by-step setup.

---

## I Welcome Constructive Critique

This project benefits from scrutiny.
Security tools that resist criticism
are tools that hide their weaknesses.

I actively welcome:

**Cryptographic review**
Is the one-time-pad implementation
correct? Are there edge cases in pad
generation, selection, or lifecycle
management that create reuse risks?
Is the vault at-rest encryption sound?
Is the ephemeral pad erasure (erase_pad)
sufficient to prevent key material
recovery from the vault file?

**Python implementation review**
Are there bugs, edge cases, or failure
modes in the code that could compromise
security or correctness? Does the error
handling cover all realistic failure
conditions?

**Threat model critique**
Are there attack vectors not considered
or underestimated? Are the security
claims accurate? Are they overstated
or understated?

**iOS and Pythonista specific issues**
Are there behaviours specific to
Pythonista, iOS versions, or iCloud
Drive that affect the security or
correctness of the implementation?

**Documentation clarity**
Is anything unclear, misleading,
or inaccurate in the documentation?
Does the threat model accurately
reflect the implementation?

### How to Contribute

**Security vulnerabilities:**
Report privately before public
disclosure. See SECURITY.md.
Do not open public issues for
vulnerabilities.

**Code review and bug reports:**
Open a GitHub issue. Be specific.
Include the relevant code section,
the observed behaviour, the expected
behaviour, and why it matters
for security or correctness.

**Threat model critique:**
Open a GitHub issue or discussion.
Reasoned disagreement with the
security claims is exactly what
this project needs.

**General feedback:**
Open a GitHub discussion.
Everything gets read.

### What I Am Not Looking For

- Pull requests adding support for
  Android, Windows, macOS, or Linux
- Feature requests for real-time
  messaging, group chats, or
  voice and video
- Complaints that this is harder
  to use than Signal

Signal is easier to use than this.
That is intentional and correct.
See the section below on who
this application is and is not for.

---

## This Application Is Not For Most People

If you want private messaging, use Signal.
https://signal.org

If you want encrypted messaging with
other Apple users, use iMessage with
iCloud Advanced Data Protection enabled.

Both are free, professionally maintained,
work on every device, send push
notifications, and are used by millions
of people. They are almost certainly
the right choice for you.

Stop here and use one of those unless
you have read the rest of this section
and recognised yourself in it.

---

## Who This Is For

This application exists for a specific
and narrow set of situations where
Signal and iMessage are genuinely
insufficient.

You may be in that situation if:

**You cannot trust any company with
your communications.**
Signal is run by a nonprofit foundation
with an excellent track record. But it
is still a company with servers,
employees, legal obligations, and the
possibility of future compromise or
pressure. iMessage is run by Apple,
a corporation with business interests.
After the vault exchange, this
application involves no company,
no server, no organisation of any kind.
There is nothing to subpoena,
compromise, or shut down.

**Your communications need to remain
private for decades.**
Signal may not exist in 20 years.
iMessage may change. Encryption
standards considered secure today
may be broken by future computing
advances. One-time-pad encryption
has no mathematical assumptions that
can be invalidated by any advance
in computing, including quantum
computers. A message encrypted with
this application today will be
equally secure in 50 years given a
properly generated pad.

**You want to fully understand and
verify your own security.**
The entire encryption operation
in this application is:

  encrypted = bytes(p ^ k
    for p, k in zip(plaintext, pad))

One line. Any person with basic
programming knowledge can verify
this does exactly what it claims.
There are no black boxes.

**You need minimal metadata linking
you to your correspondent.**
After the vault exchange, this application
creates only the metadata that two accounts
accessed a shared Posteo folder. Nothing
links the message contents to either party.
With file-based vault transfer, the exchange
itself leaves no server metadata at all.
In ephemeral mode, no message content
is ever written to disk on either device.

---

## Who This Is Not For

**People who need push notifications.**
This application has none. You check
for messages by opening the app.
If you need to know immediately when
someone messages you, use Signal.

**People who want to message strangers.**
This application only works between
people who have met in person or by
video call to exchange a vault.
This is a feature, not a limitation.

**People who need to communicate
quickly in an emergency.**
Use Signal. Use iMessage. Call them.
This is correspondence, not messaging.

**People who are targets of nation-states
or dangerous criminals.**

Read this carefully.

This application does not protect you
from people who can put you in a dark
room and beat you with a $5 wrench.

No encryption does. No consumer
application does. If you are in a
situation where nation-state actors
or dangerous criminals have reason
to target you personally, stop reading
this and seek professional operational
security advice from people who
specialise in exactly your situation.

Using any consumer application while
believing it protects you against a
determined adversary willing to use
physical or legal coercion is dangerous
overconfidence that could get you or
people you care about seriously hurt.

See xkcd.com/538.

**People who want to run this on
Android, Windows, macOS, or Linux.**
This application is designed and
tested for iPad running Pythonista 3.
The security properties described
in this documentation depend
specifically on iOS sandbox isolation,
iCloud Advanced Data Protection,
and Pythonista's controlled runtime.

These properties do not exist on
other platforms. Running on Mac is
supported for development and testing
only — a warning is shown on every
launch outside Pythonista.

---

## Important Disclaimer

This application was designed and
developed by an experienced information
security professional. It was not
developed by a professional
cryptographer or a professional
Python developer.

The implementation was built using
AI-assisted development tools.
While the underlying cryptographic
concept — one-time-pad encryption —
is mathematically proven and well
understood, the specific implementation
has not been independently audited
by a professional cryptographer
or security researcher.

AI-assisted code development carries
specific risks:

- AI tools can produce code that
  appears correct but contains subtle
  implementation errors
- AI tools can introduce vulnerabilities
  that are not obvious on inspection
- AI tools do not guarantee correctness
  of security-critical operations
- This code has not been subjected to
  professional penetration testing or
  formal security verification

My information security background
informed the overall design, threat
model, and security decisions. It does
not substitute for professional
cryptographic implementation review.

The cryptographic primitive — XOR of
plaintext with a truly random one-time
pad — is sound. The mathematics
cannot be wrong.

What could be wrong is the surrounding
implementation. Pad generation, vault
storage, lifecycle management, and
error handling may contain errors
that have not been identified.

If you have the expertise to review
Python code, please read:

  core/pad.py
  core/message.py
  store/vault.py
  util/random.py

These four files contain the complete
security-critical implementation.
Approximately 200 lines of
straightforward Python with no
external dependencies.

If you find a vulnerability,
see SECURITY.md.

---

## Before You Continue

Read THREAT_MODEL.md.

Not as a formality. Actually read it.

It describes precisely what this
application protects and what it
does not. If anything in that document
describes your situation, take it
seriously.

If after reading it you still believe
this application is right for your
needs, proceed to INSTALL.md.

---

*I welcome review, critique, and
responsible disclosure of vulnerabilities
from anyone with relevant expertise.
The goal is a trustworthy tool.
Honest criticism serves that goal
better than false confidence.*
