# ---------------------------------------------------------------------------
# Letterbox v3.1.0
# vault_ui.py -- Module 2: vault generate and import
# ---------------------------------------------------------------------------
#
# Change Control
# 2026-05-09  M.Lines   v3.1.0  Initial release. See README.md and CHANGELOG.md.
import sys
from pathlib import Path

import session_store
from store.credentials import (
    CredentialsData,
    save_credentials,
    load_credentials,
    credentials_exist,
    make_folder_name,
)
from store.config import (
    read_config,
    write_config,
    config_exists,
    record_disclaimer_agreed,
)


def _reset_sequences(config_path):
    """Zero send and receive sequence counters for a new vault."""
    config = read_config(config_path)
    config.vault_sequence = 0
    config.recv_sequence  = 0
    write_config(config_path, config)
from store.vault import (
    generate_vault,
    save_vault,
    load_vault,
    reencrypt_vault,
    VaultData,
)
from transport.posteo import (
    upload_vault,
    download_vault,
    delete_transfer_vault,
    test_connection,
)
from util.random import (
    generate_bundle_id,
    generate_salt,
    generate_transfer_passphrase,
)
from core.exceptions import WrongPassphraseError

TRANSFER_FILE = "letterbox_transfer.txt"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(data_dir: Path, ui) -> None:
    """
    Generate or import vault.

    Args:
        data_dir: letterbox data directory
        ui:       UI helpers object
    """
    creds_path  = data_dir / "credentials.dat"
    config_path = data_dir / "config.dat"
    vault_path  = data_dir / "vault.dat"

    # --- Prerequisite check ---
    if not credentials_exist(creds_path):
        print()
        print("  No credentials found.")
        print("  Please set up Posteo credentials first (option 1).")
        ui.press_enter()
        return

    # --- Unlock credentials ---
    passphrase, salt, credentials = _unlock(creds_path, config_path, ui)
    if passphrase is None:
        return

    # --- Vault already exists? ---
    if vault_path.exists():
        ui.box("VAULT")
        print()
        print("  A vault already exists.")
        print()
        ui.divider()
        print()
        choice = ui.menu([
            "Generate new vault (replaces existing)",
            "Import vault from correspondent",
            "Back",
        ])
        if choice == "3":
            return
        if choice == "1":
            _generate(data_dir, vault_path, config_path, creds_path,
                      credentials, passphrase, salt, ui)
        elif choice == "2":
            _import(data_dir, vault_path, config_path, creds_path,
                    credentials, passphrase, salt, ui)
    else:
        ui.box("VAULT")
        print()
        print("  No vault found.")
        print()
        ui.divider()
        print()
        choice = ui.menu([
            "Generate new vault",
            "Import vault from correspondent",
            "Back",
        ])
        if choice == "3":
            return
        if choice == "1":
            _generate(data_dir, vault_path, config_path, creds_path,
                      credentials, passphrase, salt, ui)
        elif choice == "2":
            _import(data_dir, vault_path, config_path, creds_path,
                    credentials, passphrase, salt, ui)


# ---------------------------------------------------------------------------
# Unlock credentials
# ---------------------------------------------------------------------------

def _unlock(creds_path, config_path, ui):
    """
    Load credentials using session passphrase if available, else prompt.
    Returns (passphrase, salt, credentials) or (None, None, None).
    """
    config = read_config(config_path)
    salt   = config.salt

    # Use session passphrase if already set
    if session_store.is_set():
        try:
            credentials = load_credentials(creds_path, session_store.get_passphrase(), salt)
            return session_store.get_passphrase(), salt, credentials
        except Exception:
            session_store.clear()

    while True:
        passphrase = ui.enter_passphrase("Enter passphrase")

        try:
            credentials = load_credentials(creds_path, passphrase, salt)
            session_store.set(passphrase, salt, credentials)
            return passphrase, salt, credentials
        except WrongPassphraseError:
            print()
            print("  Incorrect passphrase.")
            print("  Press Enter to retry, or type q to quit.")
            if input("  > ").strip().lower() == "q":
                return None, None, None
        except Exception as e:
            print(f"\n  ERROR: {e}")
            return None, None, None


# ---------------------------------------------------------------------------
# Generate vault
# ---------------------------------------------------------------------------

def _generate(data_dir, vault_path, config_path, creds_path,
              credentials, passphrase, salt, ui):

    ui.box("GENERATE NEW VAULT")
    print()
    print(f"  Pads per correspondent: 2,500")
    print(f"  Messages per person:    2,500")
    print()
    ui.divider()
    print()
    choice = ui.menu(["Posteo Exchange", "Digital File Exchange", "Cancel"])
    if choice == "3":
        return

    use_posteo = (choice == "1")

    # --- Generate ---
    ui.box("GENERATING VAULT")
    print()
    print("  Generating vault...")
    print()

    bundle_id       = generate_bundle_id()
    vault           = generate_vault(bundle_id, ephemeral=True)
    transfer_phrase = generate_transfer_passphrase()
    transfer_salt   = generate_salt()

    # --- Transfer vault ---
    if use_posteo:
        credentials.folder = make_folder_name(bundle_id)
        vault.is_transfer  = True
        print()
        print("  Uploading encrypted vault transfer package...")
        tmp_path = data_dir / "transfer_vault.tmp"
        save_vault(vault, tmp_path, transfer_phrase, transfer_salt)
        vault_bytes = tmp_path.read_bytes()
        tmp_path.unlink()
        vault.is_transfer = False
        try:
            upload_vault(vault_bytes, credentials)
            print("  Uploaded.")
        except Exception as e:
            print(f"\n  ERROR: Could not upload vault: {e}")
            print("  Your contact can try importing later.")
    else:
        transfer_path     = data_dir / TRANSFER_FILE
        vault.is_transfer = True
        save_vault(vault, transfer_path, transfer_phrase, transfer_salt)
        vault.is_transfer = False
        print()
        print("  Transfer file saved:")
        print(f"  {TRANSFER_FILE}")
        print()
        print("  Copy this file to your contact by any")
        print("  physical means — USB drive, SD card, etc.")
        print("  The file and phrase must travel separately.")
        print()
        print("  Once transferred, delete the file from")
        print("  this device and from the transfer medium.")

    # --- Display protection phrase ---
    print()
    ui.divider()
    print()
    print("  Export protection phrase:")
    print(f"  {transfer_phrase}")
    print()
    print("  Write this phrase down exactly.")
    print("  Give it to your contact separately from the file.")
    ui.press_enter()

    # --- Save personal vault ---
    credentials.folder = make_folder_name(bundle_id)
    save_vault(vault, vault_path, passphrase, salt)
    _reset_sequences(config_path)

    # Update credentials with correct folder
    save_credentials(creds_path, credentials, passphrase, salt)
    session_store.set(passphrase, salt, credentials)

    print()
    print("  ✦ Vault generated and saved.")
    print("  Your contact can now import it.")
    ui.press_enter()


# ---------------------------------------------------------------------------
# Import vault
# ---------------------------------------------------------------------------

def _import(data_dir, vault_path, config_path, creds_path,
            credentials, passphrase, salt, ui):

    ui.box("IMPORT VAULT")
    print()
    ui.divider()
    print()
    choice = ui.menu(["Posteo Exchange", "Digital File Exchange", "Cancel"])
    if choice == "3":
        return

    use_posteo = (choice == "1")

    if use_posteo:
        print()
        print("  Downloading vault...")
        print("  This may take a minute.")
        try:
            vault_bytes = download_vault(credentials)
        except Exception as e:
            print(f"\n  ERROR: {e}")
            ui.press_enter()
            return
        print("  Downloaded.")
        vault = _decrypt_bytes(vault_bytes, data_dir, ui)

    else:
        transfer_path = data_dir / TRANSFER_FILE
        if not transfer_path.exists():
            ui.box("IMPORT VAULT")
            print()
            print("  Place:")
            print(f"  {TRANSFER_FILE}")
            print()
            print("  into the Letterbox documents folder,")
            print("  then select Continue.")
            print()
            ui.divider()
            print()
            choice2 = ui.menu(["Continue", "Cancel"])
            if choice2 == "2":
                return
            if not transfer_path.exists():
                print()
                print("  ERROR: File not found.")
                print(f"  Expected: {TRANSFER_FILE}")
                ui.press_enter()
                return
        vault = _decrypt_file(transfer_path, ui)

    if vault is None:
        return

    bundle_id = vault.bundle_id

    # --- Save personal vault ---
    reencrypt_vault(vault, vault_path, passphrase, salt)
    _reset_sequences(config_path)

    # Update credentials folder to match vault
    credentials.folder       = make_folder_name(bundle_id)
    credentials.is_initiator = False
    save_credentials(creds_path, credentials, passphrase, salt)
    session_store.set(passphrase, salt, credentials)

    if use_posteo:
        print()
        print("  Removing vault from server...")
        try:
            dl_creds = CredentialsData(
                username     = credentials.username,
                password     = credentials.password,
                folder       = "Letterbox-Setup",
                is_initiator = False,
            )
            delete_transfer_vault(dl_creds)
        except Exception:
            pass
    else:
        try:
            (data_dir / TRANSFER_FILE).unlink()
            print()
            print(f"  {TRANSFER_FILE} deleted from this device.")
            print("  Also delete it from the transfer medium.")
        except Exception:
            pass

    print()
    print("  ✦ Vault imported and saved.")
    ui.press_enter()


# ---------------------------------------------------------------------------
# Decrypt helpers
# ---------------------------------------------------------------------------

def _decrypt_bytes(vault_bytes, data_dir, ui):
    """Write to tmp and decrypt."""
    tmp = data_dir / "transfer_incoming.tmp"
    tmp.write_bytes(vault_bytes)
    vault = _decrypt_file(tmp, ui, is_tmp=True)
    return vault


def _decrypt_file(path, ui, is_tmp=False):
    """Prompt for phrase and decrypt vault file. Returns VaultData or None."""
    while True:
        print()
        print("  Transfer package found.")
        phrase = " ".join(input("  Enter protection phrase: ").strip().lower().split())
        print()
        print("  Decrypting vault...")
        print("  Verifying integrity...")
        try:
            vault = load_vault(path, phrase, is_transfer=True)
            if is_tmp:
                try:
                    path.unlink()
                except Exception:
                    pass
            print("  Vault decrypted successfully.")
            ui.press_enter()
            return vault
        except WrongPassphraseError:
            print()
            print("  ERROR: Incorrect protection phrase.")
            print("  Press Enter to retry, or type q to quit.")
            if input("  > ").strip().lower() == "q":
                if is_tmp:
                    try:
                        path.unlink()
                    except Exception:
                        pass
                return None
        except Exception as e:
            print(f"\n  ERROR: Could not decrypt vault: {e}")
            if is_tmp:
                try:
                    path.unlink()
                except Exception:
                    pass
            return None
