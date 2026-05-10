# Installation

## Requirements

- iPad running iOS 16 or later
- [Pythonista 3](https://apps.apple.com/app/pythonista-3/id1085978097) (App Store)
- A shared [Posteo](https://posteo.de) email account

Letterbox is designed exclusively for iPad and Pythonista 3. Running on other platforms (macOS, Windows, Linux) is possible for development and testing but reduces security guarantees — the iOS sandbox, filesystem encryption, and Secure Enclave are not available on other platforms.

---

## Installing on iPad

### Step 1 — Install Pythonista 3

Purchase and install Pythonista 3 from the App Store. No additional packages are required — Letterbox uses only Python standard library modules.

### Step 2 — Transfer files via iCloud Drive

iCloud Drive is needed to get the files onto the iPad. You will move them to local storage in Step 4.

1. Enable iCloud Drive for Pythonista: **Settings → [your name] → iCloud → iCloud Drive** → enable Pythonista
2. Download the latest release zip (`letterbox_vX.Y.Z.zip`) and extract it
3. Copy the extracted `letterbox_vX.Y.Z` folder into `iCloud Drive / Pythonista 3 /` using the Files app or Finder
4. On iPad, open Pythonista 3, navigate to the `letterbox_vX.Y.Z` folder in the iCloud location, and confirm `main.py` is visible

### Step 3 — Confirm the app runs from iCloud

Tap `main.py` to run it once and confirm Letterbox launches. You do not need to complete setup yet — just confirm it starts.

### Step 4 — Move files to local storage

Keeping script files in iCloud means they are backed up to Apple's servers. If you set a duress passphrase in `constants.py`, it would be readable in iCloud. Move the files to local storage:

1. In the Files app, navigate to `iCloud Drive / Pythonista 3 /`
2. Long-press the `letterbox_vX.Y.Z` folder → **Move**
3. Navigate to **This iPad / Pythonista 3 /** and place it there
4. In Pythonista 3, open `main.py` from the new local location and confirm it still runs
5. Navigate back to `iCloud Drive / Pythonista 3 /` and confirm the folder is no longer there

### Step 5 — Disable iCloud backup for Pythonista

1. Go to **Settings → [your name] → iCloud → iCloud Drive**
2. Turn off Pythonista

This prevents future script files from being backed up to iCloud. It does not affect the data directory.

### Step 6 — Complete setup in Letterbox

1. Select **[1] Enter / Update Posteo Credentials** — enter your shared Posteo email and app password, set your passphrase
2. Select **[2] Generate / Import OTP Vault** — generate or import a vault with your correspondent
3. Select **[3] Send / Receive Messages**

---

## Data directory

Letterbox stores all data in:

```
This iPad / Pythonista 3 / Documents / letterbox /
```

This directory contains:
- `vault.dat` — your encrypted vault
- `credentials.dat` — your encrypted Posteo credentials
- `config.dat` — sequence counters and session state

This location is local to the device and is not affected by enabling or disabling iCloud Drive for Pythonista. Do not modify or delete these files manually. Be aware that restoring from a device backup can trigger rollback detection.

---

## Optional: Duress passphrase

To enable a duress passphrase, edit `constants.py` (line 38):

```python
DURESS_PASSPHRASE = "your duress phrase here"
```

Entering this passphrase at any unlock prompt silently wipes all data and returns "Wrong passphrase." — indistinguishable from a normal failed entry. See `constants.py` for full instructions and rules.

**Important:** complete Step 4 (move to local storage) and Step 5 (disable iCloud) before setting a duress passphrase. If iCloud backup is still enabled, `constants.py` containing the duress passphrase will be backed up to iCloud.

---

## Updating

To update to a new version:

1. Download the new release zip and extract it
2. In the Files app, move the new folder to `This iPad / Pythonista 3 /`
3. Copy all `.py` files from the new folder over the existing files — or replace the folder entirely
4. Do **not** delete `vault.dat`, `credentials.dat`, or `config.dat` in `Documents / letterbox /`

Your vault and credentials are preserved across updates as long as the data files are not deleted.

---

## Mac / Development

For development or testing on macOS:

```bash
cd letterbox_vX.Y.Z
python3 main.py --data data/alice    # Alice's data directory
python3 main.py --data data/bob      # Bob's data directory
```

Python 3.10 or later is required.

---

## Posteo Setup

Letterbox requires a shared Posteo account. Both correspondents use the same account — messages are posted to a private IMAP folder that only they access.

1. Create a Posteo account at [posteo.de](https://posteo.de)
2. In Posteo settings, create an **app password** (Settings → Security → App passwords)
3. Use the app password (not your main Posteo password) in Letterbox

The IMAP folder used for messaging is named `Letterbox-[bundle_id_hex]` and is created automatically when the vault is generated.
