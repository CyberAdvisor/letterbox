# main.py
#
# Letterbox v2.0 -- Proof of Concept
# Entry point and complete CLI user interface.
#
# Usage:
#   python3 main.py                    (iPad / production)
#   python3 main.py --data data/alice  (Mac development, Alice)
#   python3 main.py --data data/bob    (Mac development, Bob)
#   python3 main.py --data data/alice  (Mac development, Alice -- reset in-app)
#
# ---------------------------------------------------------------------------
# Change Control
# ---------------------------------------------------------------------------
# Date        Author    Description
# ---------------------------------------------------------------------------
# 2026-05-02  M.Lines   Initial version
# 2026-05-02  M.Lines   Inbox model UI, disclaimer, random pad assignment
# 2026-05-03  M.Lines   v1.1.0: Ephemeral mode: no history, pad erased after use
# 2026-05-03  M.Lines   v1.1.0: Vault format v2, FLAGS field, LBVAULT2/LBTRANS2 magic
# 2026-05-03  M.Lines   v1.1.0: APP_VERSION constant, version shown in menu
# 2026-05-03  M.Lines   v1.1.0: Ephemeral mode hides history/unread menu options
# 2026-05-03  M.Lines   v1.1.1: Pad erasure unconditional on send and receive
# 2026-05-03  M.Lines   v1.1.1: Setup returns credentials directly, skips re-login
# 2026-05-03  M.Lines   v1.1.1: Removed meaningless vault-import wait prompt
# 2026-05-03  M.Lines   v1.1.2: _check_platform() warning on non-Pythonista launch
# 2026-05-03  M.Lines   v1.1.2: Disclaimer header uses APP_VERSION constant
# 2026-05-03  M.Lines   v1.1.3: Ephemeral mode d/n/q prompt replaces yes/no
# 2026-05-03  M.Lines   v1.1.3: _is_icloud_path() and iCloud sync warning added
# 2026-05-03  M.Lines   v1.1.3: Compose: running character count after each line
# 2026-05-03  M.Lines   v1.1.3: _press_enter: scroll fix for Pythonista console
# 2026-05-03  M.Lines   v1.1.3: Platform warning shortened, references THREAT_MODEL
# 2026-05-03  M.Lines   v1.1.3: Transfer passphrase: confirmation before proceeding
# 2026-05-03  M.Lines   v1.1.3: File header version updated to v1.1.3
# 2026-05-03  M.Lines   v1.1.4: Ephemeral mode: removed n option, d/q only
# 2026-05-03  M.Lines   v1.1.5: Remove dead _pad_id key from new_messages list
# 2026-05-03  M.Lines   v1.1.5: Move hashlib to top-level imports
# 2026-05-03  M.Lines   v1.1.5: Remove unused TYPE_REPLY import
# 2026-05-03  M.Lines   v1.1.5: Remove unused credentials_exist import
# 2026-05-03  M.Lines   v1.1.5: Rewrite _check_platform as two clear early-return checks
# 2026-05-03  M.Lines   v1.1.5: Add TODO comment in _login for rollback detection gap
# 2026-05-03  M.Lines   v1.1.6: _reset_app(): in-app reset available on all platforms
# 2026-05-03  M.Lines   v1.1.6: _login(): offer RESET prompt before passphrase entry
# 2026-05-03  M.Lines   v1.1.7: Remove --reset flag and _reset_data_dir
# 2026-05-03  M.Lines   v1.1.8: Fix ephemeral mode description; remove pad erasure text
# 2026-05-03  M.Lines   v1.1.9: Display version number on startup
# 2026-05-03  M.Lines   v1.2.0: Display vault ID in menu status line
# 2026-05-03  M.Lines   v1.2.1: Type q to quit at passphrase prompts
# 2026-05-03  M.Lines   v1.2.2: Use objc_util NSURLIsUbiquitousItemKey for iCloud detection
# 2026-05-03  M.Lines   v1.2.3: User-facing 'pads' renamed to 'stamps' in UI strings
# 2026-05-03  M.Lines   v1.2.4: No code change -- docs only
# 2026-05-03  M.Lines   v1.2.5: Remove _is_icloud_path and iCloud detection code
# 2026-05-03  M.Lines   v1.2.6: No code change -- docs only
# 2026-05-03  M.Lines   v1.2.7: No code change -- THREAT_MODEL.md transport corrections
# 2026-05-03  M.Lines   v1.2.8: No code change -- THREAT_MODEL.md pad erasure correction
# 2026-05-03  M.Lines   v1.2.9: Vault rollback detection enforced in _login()
# 2026-05-03  M.Lines   v1.2.9: VaultRollbackError: locks app, offers RESET or exit
# 2026-05-03  M.Lines   v1.2.9: lookup_receive_pad: fix false PadReplayError in ephemeral mode
# 2026-05-03  M.Lines   v1.2.9: PAD_WARNING_LEVELS reversed: most severe threshold checked first
# 2026-05-03  M.Lines   v1.2.10: Test suite: statistical pad entropy tests, rollback tests, ephemeral replay test
# 2026-05-03  M.Lines   v2.0: Physical vault transfer via file (AirDrop/Files app)
# 2026-05-03  M.Lines   v2.0: _run_setup(): role + transport choice, no step-preview list
# 2026-05-03  M.Lines   v2.0: _setup_as_alice(): Posteo and File paths, clean UI
# 2026-05-03  M.Lines   v2.0: _setup_as_bob(): Posteo and File paths, fix 'four words' bug
# 2026-05-03  M.Lines   v2.0: _setup_message_transport(): shared credential entry helper
# 2026-05-03  M.Lines   v2.0: _save_transfer_vault_to_file(): write vault to filesystem
# 2026-05-03  M.Lines   v2.0: _load_transfer_vault_from_file(): read vault from filesystem
# ---------------------------------------------------------------------------

import hashlib
import sys
import os
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Version check
# ---------------------------------------------------------------------------

def _check_version() -> None:
    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 10):
        print(
            f"Python 3.10 or higher is required.\n"
            f"You have Python {major}.{minor}.\n"
            "Download Python at https://python.org"
        )
        sys.exit(1)

_check_version()


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------

from core.constants import (
    APP_VERSION,
    MAX_PASSPHRASE_ATTEMPTS,
    HISTORY_PAGE_SIZE,
    MAX_CONTENT_BYTES,
    TYPE_POST,
    TYPE_PADDING,
    PAD_ASSIGN_SIZE,
    PAD_COUNT,
    is_pythonista,
)
from core.exceptions import (
    LetterboxError,
    WrongPassphraseError,
    PassphraseMismatchError,
    VaultNotFoundError,
    VaultPersistError,
    VaultRollbackError,
    PadExhaustedError,
    PadAlreadyUsedError,
    PadReplayError,
    ChecksumError,
    ContentTooLongError,
    TransmissionSizeError,
    UnknownMessageTypeError,
    DatabaseError,
    CredentialsError,
    ConnectionError,
    SendError,
    ReceiveError,
    SetupIncompleteError,
)
from core.message import encrypt_message, decrypt_message, parse_header
from core.pad import (
    reserve_send_pad,
    lookup_receive_pad,
    confirm_pad_used,
    check_pad_warning,
)
from store.config import (
    config_exists,
    create_config,
    read_config,
    record_failed_attempt,
    record_successful_login,
    get_last_failed_timestamp,
    update_vault_sequence,
    get_vault_sequence,
    record_disclaimer_agreed,
    has_agreed_disclaimer,
)
from store.vault import (
    generate_vault,
    save_vault,
    load_vault,
    reencrypt_vault,
    VAULT_FLAG_EPHEMERAL,
)
from store.history import MessageHistory, DEFAULT_CONTACT_ID
from store.credentials import (
    CredentialsData,
    save_credentials,
    load_credentials,
    make_folder_name,
)
from transport.posteo import (
    post_message,
    collect_messages,
    upload_vault,
    download_vault,
    test_connection,
)
from util.random import (
    generate_salt,
    generate_bundle_id,
    generate_transfer_passphrase,
)


# ---------------------------------------------------------------------------
# Data directory
# ---------------------------------------------------------------------------

def get_data_dir() -> Path:
    """
    Return the data directory for this session.

    On iPad (Pythonista): fixed path in Pythonista documents folder.
    On Mac (development): path from --data argument, or data/default.

    Reset is handled in-app via _reset_app() at the login prompt.
    The --reset command-line flag has been removed.
    """
    if is_pythonista():
        base = Path(os.path.expanduser("~/Documents"))
        path = base / "letterbox"
        path.mkdir(parents=True, exist_ok=True)
        return path

    data_path = "data/default"
    if "--data" in sys.argv:
        idx = sys.argv.index("--data")
        if idx + 1 < len(sys.argv):
            data_path = sys.argv[idx + 1]

    path = Path(data_path)
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _print_divider() -> None:
    print("-" * 52)


def _print_header(title: str) -> None:
    print()
    _print_divider()
    print(f"  {title}")
    _print_divider()


def _format_timestamp(ts: int) -> str:
    if ts == 0:
        return "never"
    t = time.localtime(ts)
    return time.strftime("%d %b %Y at %H:%M", t)


def _press_enter(prompt: str = "Press Enter to continue.") -> None:
    sys.stdout.flush()
    input(f"\n  {prompt}")
    # Pythonista console: print blank lines to push content up so the
    # input prompt is visible without the user needing to scroll down.
    if is_pythonista():
        print("\n" * 3)
    sys.stdout.flush()


def _print_wrapped(text: str, indent: str = "  ", width: int = 44) -> None:
    words = text.split()
    line  = ""
    for word in words:
        if len(line) + len(word) + 1 > width:
            print(f"{indent}{line}")
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        print(f"{indent}{line}")


# ---------------------------------------------------------------------------
# Disclaimer (shown once ever)
# ---------------------------------------------------------------------------

def _check_platform() -> None:
    """
    Warn prominently if the app is not running inside Pythonista.

    Letterbox is designed and tested exclusively for Pythonista 3
    on iPad. This check fires every launch when outside Pythonista
    -- it cannot be silenced because the vulnerabilities are
    present every session.

    iCloud storage risks are addressed in THREAT_MODEL.md rather
    than by runtime detection, which is unreliable on iOS due to
    transparent VFS-level sync.
    """
    # Check 1: Running outside Pythonista entirely
    if not is_pythonista():
        print()
        print("!" * 52)
        print("  WARNING — NOT RUNNING IN PYTHONISTA")
        print("!" * 52)
        print()
        print("  THIS ENVIRONMENT IS FOR TESTING ONLY.")
        print("  DO NOT USE FOR REAL CORRESPONDENCE.")
        print()
        print("  Running outside Pythonista on iPad introduces")
        print("  serious vulnerabilities including: no iOS")
        print("  encryption at rest, no app sandbox, swap")
        print("  memory exposure, and no Secure Enclave")
        print("  passphrase protection.")
        print()
        print("  See THREAT_MODEL.md for full details.")
        print()
        print("!" * 52)
        print()
        answer = input("  Type TEST to continue, or anything else to exit: ")
        print()
        if answer.strip() != "TEST":
            print("Exiting.")
            sys.exit(0)
        return

    # Pythonista with local storage: all good


def _show_disclaimer(config_path: Path) -> None:
    """
    Show disclaimer once. User must type AGREE to continue.
    If they do not agree the application exits immediately.
    Agreement is recorded in config and never shown again.
    """
    print()
    print("=" * 52)
    print(f"  LETTERBOX v{APP_VERSION} -- PROOF OF CONCEPT")
    print("=" * 52)
    print()
    print("  By using this software you acknowledge:")
    print()
    print("  - This is not a production-ready security tool")
    print("  - No warranty is provided of any kind")
    print("  - You have read README.md and THREAT_MODEL.md")
    print("  - You accept all liability for your use of")
    print("    this software and any consequences thereof")
    print("  - This software does not protect you from")
    print("    people who can physically or legally")
    print("    threaten you in order to access")
    print("    your messages")
    print()
    print("=" * 52)
    print()
    answer = input("  Type AGREE to continue, or anything else to exit: ")
    print()
    if answer.strip() != "AGREE":
        print("Exiting.")
        sys.exit(0)

    if config_path.exists():
        try:
            record_disclaimer_agreed(config_path)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Passphrase entry
# ---------------------------------------------------------------------------

def _enter_passphrase(prompt: str) -> str:
    """
    Prompt for passphrase entry. Passphrase is visible as typed.

    Visible entry is intentional: on iPad autocorrect can silently
    alter invisible input causing unexpected lockouts. Visible entry
    lets the user confirm what was typed before submitting.
    Enter your passphrase when no one else can see your screen.

    Typing q (or Q) alone exits the app cleanly.
    """
    print()
    print("  Note: passphrase is visible as you type.")
    print("  Enter when no one else can see your screen.")
    print("  Type q to quit.")
    print()
    value = input(f"  {prompt}: ")
    if value.strip().lower() == "q":
        print("\n  Goodbye.\n")
        sys.exit(0)
    return value


def _enter_passphrase_with_confirm(prompt: str) -> str:
    """Prompt for passphrase with confirmation. Loops until entries match.
    Typing q at either prompt exits the app cleanly.
    """
    while True:
        p1 = _enter_passphrase(prompt)
        p2 = _enter_passphrase("Confirm passphrase")
        if p1 == p2:
            return p1
        print("\n  Passphrases do not match. Please try again.")


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

def _reset_app(data_dir: Path) -> None:
    """
    Wipe all app data after explicit confirmation.

    Deletes the entire data directory: vault, credentials, history,
    and config. The app will run setup on the next launch.

    Available on all platforms including iPad, where the --reset
    command-line flag is not accessible.

    Requires the user to type RESET to confirm. Any other input
    cancels without deleting anything.
    """
    print()
    print("!" * 52)
    print("  RESET — ALL DATA WILL BE DELETED")
    print("!" * 52)
    print()
    print("  This will permanently delete:")
    print("  - Your vault (all stamp data)")
    print("  - Your message history")
    print("  - Your Posteo credentials")
    print("  - Your configuration")
    print()
    print("  This cannot be undone.")
    print("  A new vault exchange will be required.")
    print()

    confirm = input("  Type RESET to confirm, or anything else to cancel: ").strip()
    print()

    if confirm != "RESET":
        print("  Reset cancelled.")
        _press_enter()
        return

    if data_dir.exists():
        import shutil
        shutil.rmtree(data_dir)

    print("  All data deleted.")
    print("  The app will now exit. Relaunch to run setup.")
    print()
    sys.exit(0)


def _login(data_dir: Path) -> tuple:
    """
    Prompt for passphrase and unlock encrypted files.
    Returns (passphrase, salt, vault) on success.
    Calls sys.exit() after MAX_PASSPHRASE_ATTEMPTS failures.
    """
    config_path = data_dir / "config.dat"
    vault_path  = data_dir / "vault.dat"

    try:
        config = read_config(config_path)
    except FileNotFoundError:
        print("\n  No configuration found. Run setup first.")
        sys.exit(1)
    except SetupIncompleteError as e:
        print(f"\n  Setup incomplete: {e}")
        sys.exit(1)

    # Offer reset before the passphrase prompt.
    # This is the only way to reset on iPad where --reset is unavailable.
    # Shown once per login attempt, not inside the retry loop.
    print()
    print("  Enter your passphrase to continue.")
    print("  Or type RESET to wipe all data and start over.")
    print()
    reset_check = input("  RESET or press Enter to continue: ").strip()
    if reset_check == "RESET":
        _reset_app(data_dir)
        # _reset_app exits on confirmation; if cancelled we fall through
        # and continue to the passphrase prompt below.

    attempts_this_session = 0

    while True:
        passphrase = _enter_passphrase("Enter passphrase")

        try:
            vault = load_vault(vault_path, passphrase)

            # Rollback detection: config.dat records the highest send
            # sequence ever committed. After N sends, exactly N send
            # pads should be marked used in the vault index.
            # If config.dat records more sends than the vault has used
            # send pads, the vault has been restored from a backup that
            # predates those sends -- pad reuse is possible.
            stored_sequence = get_vault_sequence(config_path)
            used_send_pads  = sum(
                1 for i in vault.send_pads if vault.index[i]
            )
            if stored_sequence > used_send_pads:
                raise VaultRollbackError(
                    f"Vault appears to have been restored from a backup.\n"
                    f"config.dat records {stored_sequence} messages sent "
                    f"but the vault index shows only {used_send_pads} "
                    f"send pads used.\n"
                    "The vault may be out of sync with what was actually "
                    "sent. Using it risks reusing pad material.\n"
                    "The vault is locked."
                )

            previous_failures = record_successful_login(config_path)

            if previous_failures > 0:
                last_ts = get_last_failed_timestamp(config_path)
                print()
                print("=" * 52)
                print("  WARNING")
                print("=" * 52)
                print(
                    f"\n  {previous_failures} failed passphrase "
                    f"attempt{'s' if previous_failures > 1 else ''} "
                    f"since your last login."
                )
                print(f"  Last attempt: {_format_timestamp(last_ts)}")
                print("\n  Someone may have tried to access your vault.")
                print("  If this was not you, your device may have")
                print("  been accessed without your knowledge.")
                _press_enter()

            return passphrase, config.salt, vault

        except WrongPassphraseError:
            attempts_this_session += 1
            record_failed_attempt(config_path)
            remaining = MAX_PASSPHRASE_ATTEMPTS - attempts_this_session

            if remaining <= 0:
                print(
                    "\n  Too many incorrect attempts.\n"
                    "  Please relaunch the application to try again."
                )
                sys.exit(1)

            print(
                f"\n  Incorrect passphrase. "
                f"{remaining} attempt"
                f"{'s' if remaining > 1 else ''} remaining."
            )

        except VaultRollbackError:
            print()
            print("!" * 52)
            print("  COMPROMISED VAULT")
            print("!" * 52)
            print()
            print("  The vault appears to have been restored from a")
            print("  backup. Using it risks reusing pad material,")
            print("  which would compromise all past and future")
            print("  correspondence.")
            print()
            print("  This vault cannot be used.")
            print()
            print("  You must reset and run setup again with your")
            print("  contact. Both parties need a new vault.")
            print()
            print("  Type RESET to delete all data and start over.")
            print("  Any other input will exit the app.")
            print()
            answer = input("  > ").strip()
            if answer == "RESET":
                _reset_app(data_dir)
            sys.exit(1)

        except VaultNotFoundError:
            print("\n  Vault file not found. Setup may be incomplete.")
            sys.exit(1)


# ---------------------------------------------------------------------------
# Setup helpers
# ---------------------------------------------------------------------------

def _save_transfer_vault_to_file(
    vault:           object,
    transfer_phrase: str,
    salt:            bytes,
    data_dir:        Path,
) -> Path:
    """
    Encrypt the vault as a transfer vault and save it to a file
    the user can share via AirDrop or the Files app.

    On iPad the file is written to the Letterbox data directory
    (~/Documents/letterbox/). The user then shares it manually
    using the Files app or AirDrop.

    On Mac (development) the file is written to the data directory
    for that session.

    Returns the path where the file was saved.
    """
    out_path = data_dir / "letterbox_transfer.vault"

    vault.is_transfer = True
    save_vault(vault, out_path, transfer_phrase, salt)
    vault.is_transfer = False

    return out_path


def _load_transfer_vault_from_file(
    data_dir: Path,
) -> tuple:
    """
    Prompt for the path to a transfer vault file and return
    (transfer_vault_bytes, path).

    On iPad the default location is the Letterbox data directory.
    Accepts any valid path. Validates the file exists and is
    non-empty before returning.

    Returns (path, vault_bytes).
    """
    default = data_dir / "letterbox_transfer.vault"

    print()
    print("  Enter the path to the transfer vault file.")
    if default.exists():
        print(f"  Default: {default}")
        print("  Press Enter to use the default.")
    print()

    while True:
        raw = input("  Path: ").strip()
        if not raw and default.exists():
            path = default
        elif not raw:
            print("  No default found. Enter the file path.")
            continue
        else:
            path = Path(raw)

        if not path.exists():
            print(f"  File not found: {path}")
            print("  Check the path and try again.")
            continue

        vault_bytes = path.read_bytes()
        if not vault_bytes:
            print("  File is empty. Check the path and try again.")
            continue

        return path, vault_bytes


def _setup_message_transport(
    bundle_id:   int,
    is_alice:    bool,
    passphrase:  str,
    salt:        bytes,
    data_dir:    Path,
) -> CredentialsData:
    """
    Collect Posteo credentials and save them.

    Called by both Alice and Bob after the vault exchange is
    complete, regardless of which transfer method was used.
    Returns the saved CredentialsData.
    """
    _print_header("Message Transport")
    print()
    print("  Enter your shared Posteo account details.")
    print("  Use an app password, not your main account password.")
    print()

    username = input("  Posteo address: ").strip()
    password = input("  App password:   ").strip()

    credentials = CredentialsData(
        username     = username,
        password     = password,
        folder       = make_folder_name(bundle_id),
        is_initiator = is_alice,
    )

    print("\n  Testing connection...")
    if not test_connection(credentials):
        print(
            "\n  Could not connect to Posteo with these credentials.\n"
            "  Check the address and app password.\n"
            "  Setup has been saved -- relaunch to retry transport."
        )
    else:
        print("  Connection successful.")

    creds_path = data_dir / "credentials.dat"
    save_credentials(creds_path, credentials, passphrase, salt)

    return credentials


# ---------------------------------------------------------------------------
# Setup -- Alice
# ---------------------------------------------------------------------------

def _setup_as_alice(data_dir: Path, use_file_transfer: bool) -> tuple:
    """
    Alice generates the vault and either uploads it to Posteo
    or saves it to a file for physical transfer.
    """
    # --- Encryption mode ---
    _print_header("Encryption Mode")
    print()
    print("  1  Standard   — messages saved to encrypted history")
    print("  2  Ephemeral  — messages never saved to disk")
    print()

    while True:
        mode_choice = input("  > ").strip()
        if mode_choice == "1":
            ephemeral = False
            break
        if mode_choice == "2":
            ephemeral = True
            break
        print("  Please enter 1 or 2.")

    # --- Generate vault ---
    print()
    print("  Generating vault...")
    print("  This may take 20-30 seconds.")
    print("  Keep the app in the foreground.")
    print()

    bundle_id       = generate_bundle_id()
    salt            = generate_salt()
    vault           = generate_vault(bundle_id, ephemeral=ephemeral)
    transfer_phrase = generate_transfer_passphrase()

    print("  Vault generated.")

    # --- Personal passphrase ---
    _print_header("Your Passphrase")
    print()
    print("  Choose a strong passphrase to protect your vault.")
    print("  This passphrase is yours alone -- never share it.")
    print()
    print("  IMPORTANT: There is no recovery option.")
    print("  Write it down and store it somewhere physically safe.")
    print()

    passphrase = _enter_passphrase_with_confirm("Choose your passphrase")

    config_path = data_dir / "config.dat"
    vault_path  = data_dir / "vault.dat"

    create_config(config_path, salt)
    save_vault(vault, vault_path, passphrase, salt)
    record_disclaimer_agreed(config_path)

    print("\n  Vault saved.")

    # --- Vault transfer ---
    if use_file_transfer:
        _print_header("Save Transfer Vault")
        print()
        print("  Saving encrypted transfer vault to file...")
        print()

        out_path = _save_transfer_vault_to_file(
            vault, transfer_phrase, salt, data_dir
        )

        print(f"  Saved to: {out_path}")
        print()
        print("  Share this file with your contact via AirDrop")
        print("  or the Files app.")

        _print_header("Provide to Your Contact")
        print()
        print("  Provide all of the following to your contact:")
        print()
        print(f"  Transfer phrase:  {transfer_phrase}")
        print()
        print("  Also share the vault file saved above.")
        print()
        _press_enter("Press Enter when you have shared the file and provided the passphrase.")

    else:
        # Posteo transfer -- credentials needed before upload
        _print_header("Message Transport")
        print()
        print("  Enter your shared Posteo account details.")
        print("  Use an app password, not your main account password.")
        print()

        username = input("  Posteo address: ").strip()
        password = input("  App password:   ").strip()

        credentials_for_upload = CredentialsData(
            username     = username,
            password     = password,
            folder       = make_folder_name(bundle_id),
            is_initiator = True,
        )

        print("\n  Testing connection...")
        if not test_connection(credentials_for_upload):
            print(
                "\n  Could not connect to Posteo with these credentials.\n"
                "  Check the address and app password.\n"
                "  Setup has been saved -- relaunch to retry transport."
            )
        else:
            print("  Connection successful.")

        creds_path = data_dir / "credentials.dat"
        save_credentials(creds_path, credentials_for_upload, passphrase, salt)

        print("\n  Uploading vault for your contact...")
        print("  This may take a minute -- the vault is large.")

        tmp_vault_path = data_dir / "transfer_vault.tmp"
        vault.is_transfer = True
        save_vault(vault, tmp_vault_path, transfer_phrase, salt)
        vault.is_transfer = False

        transfer_vault_bytes = tmp_vault_path.read_bytes()
        tmp_vault_path.unlink()

        try:
            upload_vault(transfer_vault_bytes, credentials_for_upload)
            print("  Vault uploaded.")
        except Exception as e:
            print(f"\n  Could not upload vault: {e}")
            print("  Ask your contact to try importing later.")

        _print_header("Provide to Your Contact")
        print()
        print("  Provide all of the following to your contact:")
        print()
        print(f"  Posteo address:   {username}")
        print(f"  App password:     {password}")
        print(f"  Transfer phrase:  {transfer_phrase}")
        print()
        _press_enter("Press Enter when you have provided these details.")

    _print_header("Setup Complete")
    print()
    print("  You are ready to correspond.")
    if use_file_transfer:
        print("  Your contact can import the vault file when ready.")
    else:
        print("  Your contact can import the vault when ready.")
    print()

    return passphrase, salt, vault


# ---------------------------------------------------------------------------
# Setup -- Bob
# ---------------------------------------------------------------------------

def _setup_as_bob(data_dir: Path, use_file_transfer: bool) -> tuple:
    """
    Bob imports the vault Alice generated, either by downloading
    from Posteo or loading from a file.
    """
    salt = generate_salt()

    if use_file_transfer:
        _print_header("Import Vault")
        print()
        print("  Locate the vault file your contact shared with you.")
        print("  Save it to your Letterbox folder if not already there.")
        print()

        path, transfer_vault_bytes = _load_transfer_vault_from_file(data_dir)

        print()
        transfer_phrase = input("  Transfer phrase: ").strip()

    else:
        _print_header("Import Vault")
        print()
        print("  Enter the details your contact provided.")
        print()

        username        = input("  Posteo address:  ").strip()
        password        = input("  App password:    ").strip()
        transfer_phrase = input("  Transfer phrase: ").strip()

        credentials_for_download = CredentialsData(
            username     = username,
            password     = password,
            folder       = "Letterbox-Setup",
            is_initiator = False,
        )

        print("\n  Connecting to Posteo...")
        if not test_connection(credentials_for_download):
            print(
                "\n  Could not connect to Posteo with these credentials.\n"
                "  Check the address and app password and try again."
            )
            sys.exit(1)

        print("  Connected. Downloading vault...")
        print("  This may take a minute -- the vault is large.")

        try:
            transfer_vault_bytes = download_vault(credentials_for_download)
        except Exception as e:
            print(f"\n  Could not download vault: {e}")
            sys.exit(1)

        print("  Vault downloaded.")

    # --- Decrypt transfer vault ---
    tmp_path = data_dir / "transfer_incoming.tmp"
    tmp_path.write_bytes(transfer_vault_bytes)

    print("\n  Decrypting vault...")
    try:
        vault = load_vault(tmp_path, transfer_phrase, is_transfer=True)
    except WrongPassphraseError:
        print(
            "\n  Incorrect transfer phrase.\n"
            "  Check what your contact provided and try again.\n"
            "  Relaunch to retry."
        )
        tmp_path.unlink()
        sys.exit(1)
    except Exception as e:
        print(f"\n  Could not decrypt vault: {e}")
        tmp_path.unlink()
        sys.exit(1)

    tmp_path.unlink()

    # Clean up transfer vault file after successful import
    if use_file_transfer and path.exists():
        try:
            path.unlink()
        except Exception:
            pass

    print("  Vault decrypted successfully.")

    bundle_id = vault.bundle_id

    # --- Personal passphrase ---
    _print_header("Your Passphrase")
    print()
    print("  Choose a strong passphrase to protect your vault.")
    print("  This is your own passphrase -- different from the")
    print("  transfer phrase, which is now discarded.")
    print()
    print("  IMPORTANT: There is no recovery option.")
    print("  Write it down and store it somewhere physically safe.")
    print()

    passphrase = _enter_passphrase_with_confirm("Choose your passphrase")

    config_path = data_dir / "config.dat"
    vault_path  = data_dir / "vault.dat"

    create_config(config_path, salt)
    reencrypt_vault(vault, vault_path, passphrase, salt)
    record_disclaimer_agreed(config_path)

    # --- Message transport credentials ---
    if use_file_transfer:
        credentials = _setup_message_transport(
            bundle_id, False, passphrase, salt, data_dir
        )
    else:
        credentials = CredentialsData(
            username     = username,
            password     = password,
            folder       = make_folder_name(bundle_id),
            is_initiator = False,
        )
        creds_path = data_dir / "credentials.dat"
        save_credentials(creds_path, credentials, passphrase, salt)

    _print_header("Setup Complete")
    print()
    print("  Vault imported successfully.")
    print("  You are ready to correspond.")
    print()

    vault = load_vault(vault_path, passphrase)
    return passphrase, salt, vault


# ---------------------------------------------------------------------------
# First run setup
# ---------------------------------------------------------------------------

def _run_setup(data_dir: Path) -> tuple:
    _print_header("Letterbox Setup")
    print()
    print("  Before continuing, read README.md and THREAT_MODEL.md.")
    print()
    print("  1  Generate vault  — you are setting up first")
    print("  2  Import vault    — your contact set up first")
    print()

    while True:
        role = input("  > ").strip()
        if role in ("1", "2"):
            break
        print("  Please enter 1 or 2.")

    print()
    _print_header("Vault Transfer")
    print()
    print("  How will you exchange the vault with your contact?")
    print()
    print("  1  Posteo  — upload and download over IMAP")
    print("  2  File    — AirDrop or Files app")
    print()

    while True:
        transfer = input("  > ").strip()
        if transfer in ("1", "2"):
            break
        print("  Please enter 1 or 2.")

    use_file = (transfer == "2")

    if role == "1":
        return _setup_as_alice(data_dir, use_file)
    else:
        return _setup_as_bob(data_dir, use_file)

# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------

def _show_main_menu(history: MessageHistory, vault: object) -> str:
    """Show status and menu only. Returns chosen action."""
    _print_header(f"Letterbox v{APP_VERSION}")

    pads_remaining = vault.remaining_send_pads()

    print()
    vault_id = f"{vault.bundle_id:08x}"

    if vault.ephemeral:
        print(f"  Stamps: {pads_remaining}  Vault: {vault_id}  [ephemeral mode]")
    else:
        sent_count = history.get_next_send_sequence() - 1
        recv_count = len(history.get_received_sequences())
        unread     = history.get_unread_count()
        print(f"  Sent: {sent_count}  "
              f"Received: {recv_count}  "
              f"Unread: {unread}  "
              f"Stamps: {pads_remaining}  "
              f"Vault: {vault_id}")

    warning = check_pad_warning(vault)
    if warning:
        print(f"\n  *** {warning} ***")

    print()
    _print_divider()
    print()
    print("  c  Compose message")
    print("  r  Check for new messages")

    if not vault.ephemeral:
        if unread > 0:
            print(f"  u  Read unread  ({unread})")
        print("  h  History")

    print("  q  Quit")
    print()

    valid = {"c", "r", "q"}
    if not vault.ephemeral:
        valid.add("h")
        if unread > 0:
            valid.add("u")

    while True:
        choice = input("  > ").strip().lower()
        if choice in valid:
            return choice
        print("  Invalid choice.")


# ---------------------------------------------------------------------------
# Check for new messages
# ---------------------------------------------------------------------------

def _check_and_show_new(
    vault:       object,
    history:     MessageHistory,
    credentials: CredentialsData,
    data_dir:    Path,
    passphrase:  str,
    salt:        bytes,
) -> None:
    """
    Check Posteo for new messages, decrypt and store them,
    then display only the newly received messages.
    """
    print("\n  Checking for messages...")

    bundle_id  = vault.bundle_id
    vault_path = data_dir / "vault.dat"

    try:
        transmissions = collect_messages(
            bundle_id,
            credentials,
            skip_pad_set = vault.send_pads,
        )
    except (ConnectionError, ReceiveError) as e:
        print(f"\n  Could not check for messages: {e}")
        _press_enter()
        return

    if not transmissions:
        print("  No new messages.")
        _press_enter()
        return

    new_messages = []
    vault_dirty  = False

    for transmission in transmissions:
        try:
            bid, pid = parse_header(transmission)
            pad      = lookup_receive_pad(bid, pid, vault, history)
            msg      = decrypt_message(transmission, pad)

            if msg["type"] == TYPE_PADDING:
                continue

            confirm_pad_used(pid, vault)
            vault.erase_pad(pid)
            vault_dirty = True

            if not vault.ephemeral:
                history.save_received(
                    sequence = msg["sequence"],
                    pad_id   = pid,
                    msg_type = msg["type"],
                    content  = msg["content"],
                    checksum = msg["checksum"],
                )

            new_messages.append(msg)

        except PadAlreadyUsedError as e:
            if not getattr(e, "is_duplicate", False):
                print(f"\n  WARNING: Possible replay attack (pad {pid}).")

        except PadReplayError:
            print(f"\n  WARNING: Replay detected (pad {pid}). Rejected.")

        except ChecksumError:
            print("\n  WARNING: Message failed integrity check. Discarded.")

        except (TransmissionSizeError, UnknownMessageTypeError):
            pass

        except Exception as e:
            print(f"\n  Could not process a message: {e}")

    if vault_dirty:
        try:
            save_vault(vault, vault_path, passphrase, salt)
        except VaultPersistError as e:
            print(f"\n  CRITICAL: {e}")

    if not new_messages:
        print("  No new messages after processing.")
        _press_enter()
        return

    count = len(new_messages)
    print(f"  {count} new message{'s' if count > 1 else ''} received.\n")

    if vault.ephemeral:
        # Ephemeral mode: show each message and prompt d/q.
        # Pad bytes are already erased above (unconditionally).
        # d = acknowledge and delete from memory, advance to next
        # q = quit (offered only after the last message)
        total = len(new_messages)
        for i, msg in enumerate(new_messages):
            is_last = (i == total - 1)
            _print_divider()
            ts = _format_timestamp(int(time.time()))
            print(f"\n  [{msg['sequence']}] Received -- {ts}")
            print()
            _print_wrapped(msg["content"], indent="    ")
            print()

            if is_last:
                print("  d  Delete and return to menu")
                print("  q  Quit")
                valid = {"d", "q"}
            else:
                print("  d  Delete and next message")
                valid = {"d"}

            while True:
                answer = input("\n  > ").strip().lower()
                if answer in valid:
                    break
                print(f"  Please enter {'/'.join(sorted(valid))}.")

            if answer == "d":
                print("  Deleted.")
            elif answer == "q":
                return

    else:
        _print_divider()
        for msg in new_messages:
            ts = _format_timestamp(int(time.time()))
            print(f"\n  [{msg['sequence']}] Received -- {ts}")
            _print_wrapped(msg["content"], indent="    ")

        _show_gap_summary(history)

    _press_enter()


# ---------------------------------------------------------------------------
# Read unread
# ---------------------------------------------------------------------------

def _read_unread(history: MessageHistory) -> None:
    """Show all unread messages then mark them displayed."""
    msgs   = history.get_conversation(limit=10000)
    unread = [m for m in msgs
              if m["direction"] == "received" and m["displayed"] == 0]

    if not unread:
        print("\n  No unread messages.")
        _press_enter()
        return

    print(f"\n  {len(unread)} unread message"
          f"{'s' if len(unread) > 1 else ''}:\n")
    _print_divider()

    for msg in unread:
        ts = _format_timestamp(msg["timestamp"])
        print(f"\n  [{msg['sequence']}] Received -- {ts}")
        _print_wrapped(msg["content"], indent="    ")

    history.mark_all_displayed()
    _show_gap_summary(history)
    _press_enter()


# ---------------------------------------------------------------------------
# History (paged)
# ---------------------------------------------------------------------------

def _show_history(history: MessageHistory) -> None:
    """
    Show message history paged at HISTORY_PAGE_SIZE per page.
    Starts from most recent page. n=newer p=older q=back.
    Messages within each page shown oldest first.
    """
    all_msgs = history.get_conversation(limit=10000)

    if not all_msgs:
        print("\n  No messages in history.")
        _press_enter()
        return

    total       = len(all_msgs)
    page_size   = HISTORY_PAGE_SIZE
    total_pages = (total + page_size - 1) // page_size
    page        = total_pages - 1   # start on most recent page

    while True:
        _print_header(f"History  [page {page + 1} of {total_pages}]")

        start = page * page_size
        end   = min(start + page_size, total)
        msgs  = all_msgs[start:end]

        print()
        for msg in msgs:
            direction = msg["direction"]
            ts        = _format_timestamp(msg["timestamp"])
            unread    = (direction == "received"
                         and msg["displayed"] == 0)

            if direction == "received":
                marker = "  [NEW] " if unread else "  "
                print(f"{marker}[{msg['sequence']}] Received -- {ts}")
            else:
                print(f"  Sent -- {ts}")

            _print_wrapped(msg["content"], indent="    ")
            print()

        _print_divider()
        nav = []
        if page > 0:
            nav.append("p  Older")
        if page < total_pages - 1:
            nav.append("n  Newer")
        nav.append("q  Back")
        print("  " + "    ".join(nav))
        print()

        choice = input("  > ").strip().lower()

        if choice == "n" and page < total_pages - 1:
            page += 1
        elif choice == "p" and page > 0:
            page -= 1
        elif choice == "q":
            break

    history.mark_all_displayed()


# ---------------------------------------------------------------------------
# Gap summary
# ---------------------------------------------------------------------------

def _show_gap_summary(history: MessageHistory) -> None:
    received_seqs = history.get_received_sequences()
    highest       = history.get_highest_received_sequence()
    if highest == 0:
        return
    gaps = [i for i in range(1, highest + 1) if i not in received_seqs]
    if gaps:
        gap_str = ", ".join(str(g) for g in gaps[:5])
        if len(gaps) > 5:
            gap_str += "..."
        print(
            f"\n  Note: {len(gaps)} message"
            f"{'s' if len(gaps) > 1 else ''} missing "
            f"(sequence {gap_str})."
        )
        print("  Ask your contact to resend missing messages.")


# ---------------------------------------------------------------------------
# Compose
# ---------------------------------------------------------------------------

def _compose_message(
    vault:       object,
    history:     MessageHistory,
    credentials: CredentialsData,
    data_dir:    Path,
    passphrase:  str,
    salt:        bytes,
) -> None:
    """Compose and send a message. Blank line to send, Ctrl+C to cancel."""
    _print_header("Compose Message")
    print()
    print(f"  Type your message. Maximum {MAX_CONTENT_BYTES} characters.")
    print("  Type END on a new line to send.")
    print("  Press Ctrl+C to cancel.")
    print()

    lines    = []
    used     = 0

    try:
        while True:
            line = input("  > ")
            if line.strip().upper() == "END":
                break
            # Check if adding this line would exceed the limit
            candidate = "\n".join(lines + [line])
            candidate_len = len(candidate.encode("utf-8"))
            if candidate_len > MAX_CONTENT_BYTES:
                over = candidate_len - MAX_CONTENT_BYTES
                print(
                    f"  Too long: that line would exceed the limit by {over} "
                    f"character{'s' if over != 1 else ''}."
                )
                print(f"  [{MAX_CONTENT_BYTES - used} remaining] Shorten the line or type END to send what you have.")
                continue
            lines.append(line)
            used = len("\n".join(lines).encode("utf-8"))
            remaining = MAX_CONTENT_BYTES - used
            print(f"  [{remaining} remaining]")
    except KeyboardInterrupt:
        print("\n\n  Cancelled.")
        return

    if not lines:
        print("\n  Empty message not sent.")
        return

    content = "\n".join(lines)

    print()
    print("  Message to send:")
    print()
    _print_wrapped(content, indent="    ")
    print()
    confirm = input("  Send? (y/n): ").strip().lower()
    if confirm != "y":
        print("\n  Cancelled.")
        return

    try:
        pad_id, pad_bytes = reserve_send_pad(vault)
    except PadExhaustedError as e:
        print(f"\n  {e}")
        return

    vault_path = data_dir / "vault.dat"
    try:
        save_vault(vault, vault_path, passphrase, salt)
    except VaultPersistError as e:
        print(f"\n  CRITICAL: {e}")
        return

    sequence  = history.get_next_send_sequence()
    bundle_id = vault.bundle_id

    transmission = encrypt_message(
        content, sequence, pad_id, pad_bytes, bundle_id
    )

    checksum = hashlib.sha256(content.encode("utf-8")).digest()[:8]

    print("\n  Sending...")
    try:
        post_message(transmission, bundle_id, pad_id, credentials)
    except (ConnectionError, SendError) as e:
        print(f"\n  Could not send: {e}")
        print(
            "  The pad has been used. A retry will use a new pad.\n"
            "  Message has NOT been saved to history."
        )
        return

    # Always erase the pad bytes immediately after sending.
    # The original key material is no longer needed once the
    # message is transmitted; keeping it on disk serves no purpose
    # and creates unnecessary recovery risk.
    vault.erase_pad(pad_id)
    try:
        save_vault(vault, vault_path, passphrase, salt)
    except VaultPersistError as e:
        print(f"\n  WARNING: Could not erase pad on disk: {e}")

    if not vault.ephemeral:
        history.save_sent(sequence, pad_id, TYPE_POST, content, checksum)

    update_vault_sequence(data_dir / "config.dat", sequence)

    remaining = vault.remaining_send_pads()
    print(f"  Sent. ({remaining} stamps remaining)")
    _press_enter()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Application entry point.
    1. Determine data directory
    2. Show disclaimer if not yet agreed
    3. Run setup if first time
    4. Login
    5. Main inbox loop
    """
    data_dir    = get_data_dir()
    config_path = data_dir / "config.dat"

    print(f"\n  Letterbox v{APP_VERSION}")

    _check_platform()

    if not has_agreed_disclaimer(config_path):
        _show_disclaimer(config_path)

    if not config_exists(config_path):
        passphrase, salt, vault = _run_setup(data_dir)
    else:
        passphrase, salt, vault = _login(data_dir)

    creds_path = data_dir / "credentials.dat"
    try:
        credentials = load_credentials(creds_path, passphrase, salt)
    except CredentialsError as e:
        print(f"\n  Could not load credentials: {e}")
        sys.exit(1)

    try:
        with MessageHistory(data_dir, passphrase, salt) as history:
            while True:
                action = _show_main_menu(history, vault)

                if action == "c":
                    _compose_message(
                        vault, history, credentials,
                        data_dir, passphrase, salt,
                    )
                elif action == "r":
                    _check_and_show_new(
                        vault, history, credentials,
                        data_dir, passphrase, salt,
                    )
                elif action == "u":
                    _read_unread(history)
                elif action == "h":
                    _show_history(history)
                elif action == "q":
                    print("\n  Goodbye.\n")
                    break

    except DatabaseError as e:
        print(f"\n  Database error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\n  Goodbye.\n")


if __name__ == "__main__":
    main()
