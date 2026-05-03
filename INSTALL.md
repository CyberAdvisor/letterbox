# Installation

## Requirements

- iPad
- iOS 13.4 or later
- Pythonista 3 from the App Store
- iCloud Drive enabled
- iCloud Advanced Data Protection 
  enabled — strongly recommended
- An Apple ID

This application does not run on iPhone. 
The screen is too small for comfortable 
correspondence.

This application does not run on Mac, 
Windows, Linux, or Android. 
See README.md for why.

---

## Step 1 — Read the Documentation

Before installing, read:

- README.md — what this is and is not for
- THREAT_MODEL.md — what is and is not 
  protected

If you have not read both of these, 
go back and read them now.

---

## Step 2 — Install Pythonista

Purchase and install Pythonista 3 from 
the App Store.

Search for "Pythonista 3" by Omz:Software.

This is a one-time cost of approximately 
$10. Pythonista has been available on the 
App Store since 2012. It is not affiliated 
with this project.

Letterbox cannot run without Pythonista. 
There is no workaround for this.

---

## Step 3 — Enable Advanced Data Protection

This step is not optional if you care 
about the privacy of your communications.

On your iPad:

  Settings
  → [Your Name]
  → iCloud
  → Advanced Data Protection
  → Turn On

Apple will walk you through setting up 
account recovery before enabling ADP. 
This is required by Apple. Do it carefully. 
If you lose access to your Apple ID and 
have no recovery method, Apple cannot 
help you recover your data.

With ADP enabled, files in your iCloud 
Drive — including messages in transit — 
are end-to-end encrypted. Apple cannot 
read them. This combines with Letterbox's 
own encryption to provide two independent 
layers of protection.

Without ADP, Apple can read files in 
your iCloud Drive in response to legal 
requests or account access.

---

## Step 4 — Install Letterbox

Tap this link on your iPad to install 
directly into Pythonista:

  [pythonista3://install link]

Alternatively:

1. Download the zip file from GitHub
2. Open the Files app on your iPad
3. Locate the downloaded zip
4. Extract it
5. Open Pythonista
6. Use Pythonista's file browser to 
   navigate to the extracted folder
7. The application is ready to run

---

## Step 5 — First Run

Open Pythonista.
Navigate to the Letterbox folder.
Tap main.py to run it.

On first run the application will:

1. Check your Python version
2. Show a disclaimer — read it, then
   type AGREE to continue
3. Ask whether you are generating
   or importing a vault (Alice or Bob)
4. Walk you through vault generation
   or import (see Step 6)
5. Ask you to set your personal
   vault passphrase — choose something
   strong and write it down

After setup you will see the main menu.
You are ready to correspond.

---

## Step 6 — Vault Exchange

To correspond with someone, you need 
to exchange a vault with them.

They must also have Letterbox installed 
and running on their iPad, and you must 
both have access to the same shared 
Posteo account.

### Who Does What

One person acts as Alice (generates the 
vault) and one acts as Bob (imports it). 
It does not matter who is who.

**Alice (vault generator):**

1. Open Letterbox and follow the setup
   prompts for the first-time run
2. When asked about ephemeral mode,
   choose standard or ephemeral
   (see DESIGN.md for guidance)
3. Letterbox generates the vault
   (20–30 seconds) and asks for your
   personal passphrase
4. Enter the Posteo shared account
   address and app password when prompted
5. Letterbox uploads an encrypted copy
   of the vault to Posteo
   (5–10 seconds — the vault is ~39MB)
6. Letterbox displays a six-word
   transfer passphrase on screen
7. Tell Bob ALL of the following verbally
   — in person or by video call only:
     - The Posteo address
     - The Posteo app password
     - The six-word transfer passphrase

**Bob (vault importer):**

1. Open Letterbox and follow the setup
   prompts for the first-time run
2. Choose "Import vault" when asked
3. Enter the Posteo address and app
   password Alice told you
4. Enter the six-word transfer passphrase
5. Letterbox downloads and decrypts the
   vault (5–10 seconds)
6. Choose your own personal passphrase
   (different from the transfer phrase)
7. Setup is complete

### Identity Verification

The person handing you a vault is the 
person you will be corresponding with.
Verify their identity before accepting:

- In person is strongest: you can see
  and hear the person directly
- Video call is adequate for people
  whose face and voice you know well
- Voice call only is adequate for
  people whose voice you can identify
  with certainty

Do not exchange vaults with anyone you 
cannot positively identify.

### What Must Travel by Voice Only

The six-word transfer passphrase must 
never be written down or sent digitally. 
Tell it verbally only.

The Posteo address and app password are 
also sensitive but less critical — they 
protect the transport channel, not the 
message content. The vault passphrase 
Alice uses for her own vault never 
leaves her device.

---

## Updating Letterbox

When a new version is available, 
download it from GitHub and replace 
the Letterbox files in Pythonista.

Your vault files and message history 
are stored in a separate data directory 
and are not affected by updates.

Before updating, check the GitHub 
releases page to understand what 
has changed. Pay attention to any 
updates marked SECURITY — apply 
these before your next send.

Do not update Pythonista or iOS 
without first checking the GitHub 
issues page to confirm the update 
does not affect Letterbox.

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
reading a received message you are 
asked "Ready to delete?" Answering 
yes destroys the message and overwrites 
the pad key material with random data. 
Answering no keeps the message visible 
for the current session only; it is 
never written to disk.

The mode choice is stored in the vault 
and applies automatically to both 
parties. Bob does not need to make 
a separate choice.

You cannot change the mode after setup 
without generating a new vault.

---

## Vault Passphrase

Your vault passphrase is the key to 
your correspondence history.

- Write it down and store it somewhere 
  physically secure
- Do not store it in any digital system
- Do not share it with anyone except 
  your contact, verbally, at vault 
  exchange time
- There is no recovery option if 
  you forget it

Your contact has their own passphrase 
for their copy of the vault. You do 
not need to know their passphrase 
and they do not need to know yours 
after the initial exchange.

---

## If Something Goes Wrong

See SECURITY.md for reporting 
security vulnerabilities.

Open a GitHub issue for bugs, 
with as much detail as possible 
about what happened, what you 
expected, and what iOS and 
Pythonista versions you are running.

Before reporting, confirm you are 
running on iPad with Pythonista 3. 
Issues from other platforms will 
be closed without response.
