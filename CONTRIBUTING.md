# Contributing

Thank you for your interest in 
improving Letterbox.

---

## What I Welcome

**Security review**
Read the four core security files:

  core/pad.py
  core/message.py
  store/vault.py
  util/random.py

These contain the complete 
security-critical implementation. 
Report vulnerabilities privately 
via SECURITY.md before opening 
any public issue.

**Bug reports**
Open a GitHub issue. Include:
- What you did
- What you expected to happen
- What actually happened
- Your iOS version
- Your Pythonista version

Confirm you are on iPad with 
Pythonista 3 before reporting. 
Issues from other platforms 
will be closed without response.

**Threat model critique**
Open a GitHub discussion. 
Reasoned disagreement with 
the security claims in 
THREAT_MODEL.md is valuable. 
Be specific about what is 
wrong and why.

**Documentation improvements**
Clarity matters for a security 
tool. If something is unclear, 
misleading, or inaccurate, 
open an issue or pull request.

---

## What I Will Not Accept

**Support for other platforms**
This application is iPad and 
Pythonista 3 only. Pull requests 
adding Android, Windows, macOS, 
Linux, or any other platform 
support will be closed without 
discussion.

This is not negotiable.

**Real-time messaging features**
This is correspondence, not 
a messenger. Pull requests 
adding push notifications, 
presence indicators, typing 
indicators, read receipts, 
or real-time features are 
outside scope and will be closed.

**Media sharing**
This is text correspondence. 
Image, video, or file sharing 
is outside scope for v1.

**Dependency additions**
The zero external dependency 
design is intentional. Pull 
requests adding pip dependencies 
will be closed.

---

## Code Standards

If submitting a pull request:

- Match the existing code style
- Add comments explaining 
  security-relevant decisions
- Update documentation if behavior 
  changes
- Note any security implications 
  in the pull request description

Security-critical code — anything 
in core/ or store/ — requires 
careful explanation of why changes 
are safe. Do not assume reviewers 
will infer your reasoning.

---

## A Note on AI-Generated Code

This project was developed with 
AI assistance. I am aware of the 
implications and have disclosed 
them in the README.

Pull requests that include 
AI-generated code are accepted 
on the same basis as any other 
contribution — the code will 
be reviewed on its merits. 
Disclose AI assistance in your 
pull request description. 
Security-critical AI-generated 
code will receive extra scrutiny.
