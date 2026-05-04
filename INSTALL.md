# Installation and Setup

---

## Quick Start

You need the following before you begin:

1. **An iPad** with Pythonista 3 installed
2. **A shared Posteo email account** that
   both you and your contact can access
   (required for sending and receiving
   messages; also used for vault exchange
   unless you use the file transfer option)
3. **A contact** who also has an iPad with
   Pythonista 3
4. **A way to provide your contact with
   the transfer phrase** — in person,
   by video call, or any channel you trust

If you are missing any of these, read the
relevant section below before proceeding.

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
  → iCloud
  → iCloud Drive
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
   (e.g. letterbox_v1.2.5.zip)

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

1. Display the version number
2. Show a disclaimer — read it, then
   type AGREE to continue
3. Ask your role: Generate vault (you
   go first) or Import vault (your
   contact went first)
4. Ask your transfer method: Posteo
   (upload/download) or File (AirDrop
   or Files app)

Decide who generates and who imports
before you begin. It does not matter
which role each person takes.

---

## Step 6 — Vault Exchange

One person (Alice) generates the vault
and the other (Bob) imports it. Both must
complete this step before either can send
a message. There are two ways to transfer
the vault: via Posteo, or via file.

### Choosing a Transfer Method

**Posteo transfer** — Alice uploads the
encrypted vault to your shared Posteo
account. Bob downloads it from there.
Requires Posteo credentials at setup.
The vault is encrypted and protected
by the transfer phrase, but it exists
on Posteo's servers briefly.

**File transfer** — Alice saves the
encrypted vault to a file and shares
it directly with Bob via AirDrop or
the Files app. The vault never touches
any server. Recommended if either
party has a serious threat model.

Both methods produce the same result.
The vault is always encrypted with
2,000,000 KDF iterations and a
six-word transfer phrase regardless
of how it travels.

---

### Alice — Posteo Transfer

1. Run Letterbox
2. Choose: Generate vault
3. Choose: Posteo
4. Choose encryption mode (standard
   or ephemeral)
5. Wait for vault generation
   (20–30 seconds)
6. Choose your personal passphrase —
   write it down. No recovery option.
7. Enter the shared Posteo address
   and app password
8. Wait for vault upload (5–10 seconds)
9. Letterbox displays:
   - Posteo address
   - App password
   - Six-word transfer phrase
10. Provide all three to Bob

### Bob — Posteo Transfer

1. Run Letterbox
2. Choose: Import vault
3. Choose: Posteo
4. Enter the Posteo address, app
   password, and transfer phrase
   your contact provided
5. Wait for download and decrypt
   (5–10 seconds)
6. Choose your own personal passphrase
   — write it down. No recovery option.
7. Setup is complete

---

### Alice — File Transfer

1. Run Letterbox
2. Choose: Generate vault
3. Choose: File
4. Choose encryption mode (standard
   or ephemeral)
5. Wait for vault generation
   (20–30 seconds)
6. Choose your personal passphrase —
   write it down. No recovery option.
7. Letterbox saves the transfer vault
   to the letterbox folder and displays:
   - The file path
   - The six-word transfer phrase
8. Share the vault file with Bob via
   AirDrop or the Files app
9. Provide the transfer phrase to Bob
10. Enter Posteo credentials for
    ongoing message exchange

### Bob — File Transfer

1. Receive the vault file from Alice
   (via AirDrop or Files app) and
   save it to your letterbox folder
2. Run Letterbox
3. Choose: Import vault
4. Choose: File
5. Enter the file path (or press
   Enter if the file is in the
   default location)
6. Enter the six-word transfer phrase
7. Wait for decryption
8. Choose your own personal passphrase
   — write it down. No recovery option.
9. Enter Posteo credentials for
   ongoing message exchange
10. Setup is complete

---

### Identity Verification

The person you exchange a vault with
is the only person you can correspond
with using that vault. Verify their
identity before accepting.

Do not exchange vaults with anyone you
cannot positively identify.

### Protecting the Transfer Phrase

The six-word transfer phrase must be
provided securely. Do not send it by
unencrypted text or email. In-person
or video call is strongest. The phrase
protects the vault file with 2,000,000
KDF iterations — it is hard to crack
but should not be exposed unnecessarily.

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
you has imported the wrong vault. Reset
and start the vault exchange again.

---

## Ephemeral Mode

When Alice generates a vault she is
asked whether to enable ephemeral mode.

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
parties. Bob does not need to make
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
At the passphrase prompt, enter RESET
when asked "RESET or press Enter to
continue". Confirm with RESET again.
All data will be deleted. You will need
to generate a new vault and exchange
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
