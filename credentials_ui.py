# ---------------------------------------------------------------------------
# Letterbox v3.1.0
# credentials_ui.py -- Module 1: Posteo credentials and passphrase setup
# ---------------------------------------------------------------------------
#
# Change Control
# 2026-05-09  M.Lines   v3.1.0  Initial release. See README.md and CHANGELOG.md.
import sys
import session_store
from pathlib import Path

from store.credentials import (
    CredentialsData,
    save_credentials,
    load_credentials,
    credentials_exist,
)
from store.config import (
    create_config,
    read_config,
    write_config,
    config_exists,
    has_agreed_disclaimer,
)
from transport.posteo import test_connection
from util.random import generate_salt


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(data_dir: Path, ui) -> None:
    """
    Enter or update Posteo credentials and passphrase.

    Args:
        data_dir: letterbox data directory
        ui:       UI helpers object (box, menu, press_enter, etc.)
    """
    creds_path  = data_dir / "credentials.dat"
    config_path = data_dir / "config.dat"

    updating = credentials_exist(creds_path)

    if updating:
        ui.box("UPDATE CREDENTIALS")
        print()
        print("  Credentials are already set.")
        print("  You can update the Posteo details")
        print("  and change your passphrase.")
        print()
        ui.divider()
        print()
        choice = ui.menu(["Update credentials", "Back"])
        if choice == "2":
            return
    else:
        ui.box("POSTEO CREDENTIALS")
        print()
        print("  Set up your Posteo account details.")
        print("  You will also set your passphrase here.")
        print("  The same passphrase protects your vault.")
        print()
        ui.divider()
        print()

    # --- Collect and verify Posteo credentials ---
    while True:
        print("  Enter Posteo email address:")
        username = input("  > ").strip()
        if not username:
            print()
            print("  Email address cannot be empty.")
            print()
            continue
        print()
        print("  Enter Posteo app password:")
        password = input("  > ").strip()
        if not password:
            print()
            print("  Password cannot be empty.")
            print()
            continue

        # Temporary credentials object for connection test
        test_creds = CredentialsData(
            username     = username,
            password     = password,
            folder       = "Letterbox-Setup",
            is_initiator = True,
        )

        print()
        print("  Testing connection...")
        if test_connection(test_creds):
            print("  Connected.")
            break

        print()
        print("  Could not connect. Check the address and password.")
        print("  Press Enter to try again, or type q to quit.")
        if input("  > ").strip().lower() == "q":
            return

    # --- Set passphrase ---
    print()
    ui.box("SET PASSPHRASE")
    print()
    if updating:
        print("  Enter a new passphrase, or press Enter")
        print("  to keep the existing one.")
        print()
        print("  NOTE: changing the passphrase requires")
        print("  re-generating your vault.")
        print()

    print("  This passphrase protects your credentials")
    print("  and vault. Never share it.")
    print()
    print("  There is no recovery option. Write it down")
    print("  and keep it somewhere physically safe.")
    print()

    if session_store.is_set() and not updating:
        passphrase = session_store.get_passphrase()
        print("  Using passphrase from current session.")
    else:
        passphrase = ui.enter_passphrase_with_confirm("Enter passphrase")
        if not passphrase:
            return

    # --- Save ---
    salt = generate_salt()

    # Credentials folder will be updated when vault is generated.
    # Store placeholder folder for now.
    creds = CredentialsData(
        username     = username,
        password     = password,
        folder       = "Letterbox-Setup",
        is_initiator = True,
    )

    if not config_exists(config_path):
        create_config(config_path, salt)
    else:
        # Update salt in config — passphrase changed
        from store.config import write_config
        config = read_config(config_path)
        config.salt = salt
        write_config(config_path, config)

    save_credentials(creds_path, creds, passphrase, salt)

    print()
    print("  ✦ Credentials saved.")
    if not updating:
        print("  You can now generate or import a vault.")
    ui.press_enter()
    session_store.set(passphrase, salt, creds)
    return
