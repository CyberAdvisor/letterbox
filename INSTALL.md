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

### Step 2 — Copy Letterbox files

Download the latest release zip (`letterbox_vX.Y.Z.zip`) and extract it. You will find a folder called `letterbox_code` containing all source files.

Copy the contents of `letterbox_code` to your iPad using one of:

- **iCloud Drive** → copy to `On My iPad / Pythonista 3 / letterbox/`
- **AirDrop** → send files to iPad, open with Pythonista
- **USB** → use Finder (macOS) or iTunes (Windows) file sharing

The target location on iPad is:

```
On My iPad / Pythonista 3 / letterbox/
```

All `.py` files and subdirectories (`core/`, `store/`, `transport/`, `util/`) must be present at the same level as `main.py`.

### Step 3 — Launch

Open Pythonista 3, navigate to the `letterbox` folder, and tap `main.py` to run.

---

## Data directory

Letterbox stores all data in:

```
On My iPad / Pythonista 3 / Documents / letterbox /
```

This directory contains:
- `vault.dat` — your encrypted vault
- `credentials.dat` — your encrypted Posteo credentials
- `config.dat` — sequence counters and session state

Do not modify or delete these files manually. Use the Files app if you need to back them up, but be aware that restoring from a backup can trigger rollback detection.

---

## Updating

To update to a new version:

1. Download the new release zip
2. Extract `letterbox_code`
3. Copy all `.py` files over the existing files on iPad
4. Do **not** delete `vault.dat`, `credentials.dat`, or `config.dat`

Your vault and credentials are preserved across updates as long as the data files are not deleted.

---

## Mac / Development

For development or testing on macOS:

```bash
cd letterbox_code
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
