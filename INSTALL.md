# Installation and Setup

---

## Quick Start

You need three things before you begin:

1. **An iPad** with Pythonista 3 installed
2. **A shared Posteo email account** that
   both you and your contact can access
3. **A contact** who also has an iPad with
   Pythonista 3, and a way to provide
   them with a six-word phrase securely

If you are missing any of these, read the
relevant section below before proceeding.

---

## How Letterbox Works

Letterbox has two distinct phases:

**Phase 1 — Vault exchange (once only)**
One person generates the vault and the
other imports it. This is done once.
The app exits when complete.

**Phase 2 — Messaging (every session)**
Both parties relaunch Letterbox, enter
their passphrase, and the main menu
appears. From here you write and check
for messages.

The two phases are separate by design.
Setup is atomic and complete before
any messaging begins.

---

## What You Need

### iPad and Pythonista 3

Letterbox runs exclusively on iPad using
Pythonista 3. It does not run on iPhone,
Mac, Windows, Linux, or Android.

Purchase Pythonista 3 from the App Store
(search "Pythonista 3" by Omz:Software).
It costs approximately $10 and has been
available since 2012. It is not affiliated
with this project.

Both you and your contact need Pythonista
3 on your respective iPads before setup
can begin.

### A Shared Posteo Account

Letterbox uses a shared Posteo email
account as a message dead drop. Messages
are never sent as email — they are
deposited directly into a shared folder
using IMAP and collected from there.

You need one shared Posteo account that
both you and your contact will use. This
is not your personal email — it is a
dedicated account for Letterbox only.

**Setting up a Posteo account:**

1. Go to https://posteo.de on a browser
2. Click Sign Up
3. Choose a username and password
4. Complete the signup (Posteo charges
   a small annual fee — approximately
   €1/month)
5. Generate an app password:
   - Log in to posteo.de
   - Settings → Security → App passwords
   - Generate a new app password for
     Letterbox
   - Copy it — you will need it during
     setup

Use the app password, not your main
Posteo password, in Letterbox. This
limits exposure if the credentials
are ever compromised.

You only need ONE Posteo account shared
between both parties. You do not each
need your own.

### A Contact You Can Identify

You must be able to speak to your contact
in person or by video call to exchange
setup credentials. If you cannot verify
who you are talking to, do not proceed.
See THREAT_MODEL.md — Vault Exchange
Impersonation.

---

## Step 1 — Read the Documentation

Before installing, read:

- README.md — what this is and is not for
- THREAT_MODEL.md — what is and is not
  protected

If you have not read both, go back and
read them now.

---

## Step 2 — Enable Advanced Data Protection

This step is not optional if you care
about the privacy of your communications.

On your iPad:

  Settings
  → [Your Name]
  → iCloud
  → Advanced Data Protection
  → Turn On

Apple will walk you through setting up
account recovery. Do this carefully.
If you lose your Apple ID with no recovery
method, Apple cannot help you.

With ADP enabled, files in iCloud Drive
are end-to-end encrypted. Apple cannot
read them. This adds a second independent
layer of protection on top of Letterbox's
own encryption.

---

## Step 3 — Enable iCloud Drive for Pythonista

Letterbox script files are stored in
Pythonista's iCloud Drive folder so they
are accessible from the Files app.

On your iPad:

  Settings
  → [Your Name]
  → Saved to iCloud
  → See All
  → Pythonista 3 → enable

If Pythonista 3 does not appear in the
list, open Pythonista once and return
to this screen.

Note: this enables iCloud sync for
Pythonista's script files only. The
Letterbox data files (vault, history,
credentials) are stored in Pythonista's
local documents folder and are NOT
synced to iCloud.

---

## Step 4 — Install Letterbox

1. On your iPad, go to the Letterbox
   GitHub releases page and download
   the latest zip file
   (e.g. letterbox_v1.2.11.zip)

2. Open the Files app

3. Locate the downloaded zip
   (usually in Downloads)

4. Tap the zip to extract it

5. Navigate to:
   iCloud Drive → Pythonista 3

6. Create a new folder called
   letterbox inside the Pythonista 3
   folder (tap the three-dot menu
   → New Folder)

7. Open the extracted letterbox_code
   folder and select all files and
   folders inside it

8. Copy them into the letterbox folder
   you just created in Pythonista 3

9. Open Pythonista

10. In the file browser, navigate to
    the letterbox folder

11. Tap main.py

The app will start and display the
version number.

---

## Step 5 — First Run

On first run the app will:

1. Show a disclaimer — read it, then
   type AGREE to continue
2. Ask whether you are generating
   or importing a vault

Decide who goes first before you begin.
It does not matter which role each
person takes.

---

## Step 6 — Vault Exchange

One person generates the vault and the
other imports it. Both must complete
this step before either can send a
message. Setup exits when complete —
relaunch to begin corresponding.

### The person generating the vault

1. Run Letterbox
2. Choose: Generate vault
3. Choose correspondence mode
   (standard or ephemeral — see below)
4. Wait for vault generation
   (20–30 seconds)
5. Choose your personal passphrase
   — write it down. No recovery option.
6. Enter the shared Posteo address
   and app password
7. Wait for vault upload
8. Letterbox displays a six-word
   transfer phrase and the Posteo
   details
9. Provide all three to your contact
   securely

### The person importing the vault

1. Run Letterbox
2. Choose: Import vault
3. Enter the shared Posteo address
   and app password your contact
   provided
4. Enter the six-word transfer phrase
5. Wait for download and decrypt
6. Choose your own personal passphrase
   — write it down. No recovery option.
7. Setup is complete — relaunch to
   begin corresponding

### Identity Verification

The person you exchange a vault with
is the only person you can correspond
with using that vault. Verify their
identity before exchanging.

Do not exchange vaults with anyone you
cannot positively identify.

### Protecting the Transfer Phrase

The six-word transfer phrase protects
the vault during upload. Provide it
securely to your contact. Do not send
it by unencrypted text or email.

---

## Step 7 — Confirm Both Parties Are Ready

Before sending your first message,
confirm with your contact that:

- They have completed setup
- Their vault ID (shown in the menu)
  matches yours
- They are running the same version
  of Letterbox (shown at startup)

If the vault IDs do not match, one of
you has imported the wrong vault. See
the Reset section below to start over.

---

## Ephemeral Mode

The vault generator is asked whether
to enable ephemeral mode.

**Standard mode (default):**
Messages are saved to an encrypted
history database on your device.
You can review past messages at
any time using the History menu.

**Ephemeral mode:**
No messages are saved to disk. After
reading a received message you confirm
deletion. The message is never written
to disk in any form.

The mode choice is stored in the vault
and applies automatically to both
parties. The importer does not make
a separate choice. The mode cannot
be changed after setup without
generating a new vault.

See DESIGN.md for guidance on choosing
a mode.

---

## Vault Passphrase

Your vault passphrase is the key to
your correspondence.

- Write it down and store it somewhere
  physically secure
- Do not store it digitally
- Do not share it with anyone
- There is no recovery option if
  you forget it

Your contact has their own passphrase
for their copy of the vault. You do
not need to know theirs.

---

## Updating Letterbox

When a new version is available:

1. Download the new zip from GitHub
   Releases
2. Extract it
3. Copy the new files into your
   letterbox folder in Pythonista,
   replacing the existing files
4. Your vault, history, and credentials
   are stored separately and are not
   affected

Before updating, read the release notes
on GitHub. Pay attention to any update
marked SECURITY — apply these before
your next send.

Both you and your contact should update
to the same version before resuming
correspondence after a version change.

---

## If Something Goes Wrong

**Wrong passphrase:**
Type q at the passphrase prompt to exit.
Relaunch and try again. After 10 failed
attempts the app will exit and you must
relaunch.

**Need to start over:**
Delete the data folder as described in
the Reset section below. Relaunch to
run setup again. You will need to
generate a new vault and exchange
it with your contact again.

**Vault mismatch:**
If messages are not decrypting, confirm
the vault ID shown in both menus matches.
If not, one party needs to reset and
re-import the current vault.

**Reporting bugs:**
Open a GitHub issue with your Letterbox
version, iOS version, Pythonista version,
and a description of what happened.
Only iPad/Pythonista issues will be
addressed.

**Reporting security vulnerabilities:**
See SECURITY.md. Do not open public
GitHub issues for vulnerabilities.

---

## Resetting Letterbox

Resetting deletes your vault, credentials,
history, and configuration. Your scripts
are not affected. You will need to run
setup again and exchange a new vault
with your contact.

**On iPad:**

1. Open the Files app
2. Tap "On My iPad" (not iCloud Drive)
3. Open Pythonista 3
4. Press and hold the letterbox folder
5. Tap Delete
6. Relaunch Letterbox

**On Mac (development only):**

```bash
rm -rf data/alice
# or
rm -rf data/bob
```

Relaunch to run setup again.
