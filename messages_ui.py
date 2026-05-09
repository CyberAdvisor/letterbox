# ---------------------------------------------------------------------------
# Letterbox v3.1.0
# messages_ui.py -- Module 3: send and receive messages
# ---------------------------------------------------------------------------
#
# Change Control
# 2026-05-09  M.Lines   v3.1.0  Initial release. See README.md and CHANGELOG.md.
import sys
from pathlib import Path

import session_store
from store.credentials import (
    load_credentials,
    credentials_exist,
)
from store.vault import load_vault, save_vault
from store.config import (
    read_config,
    get_vault_sequence,
    update_vault_sequence,
    get_recv_sequence,
    update_recv_sequence,
)
from core.constants import MAX_CONTENT_BYTES, PAD_COUNT, APP_VERSION
from core.exceptions import (
    WrongPassphraseError,
    PadExhaustedError,
    PadAlreadyUsedError,
    PadReplayError,
    DecryptionError,
    VaultPersistError,
    PosteoConnectionError,
    SendError,
    ReceiveError,
)
from core.message import encrypt_message, decrypt_message, parse_header
from core.pad import (
    reserve_send_pad,
    confirm_pad_used,
    lookup_receive_pad_v3,
    check_pad_warning,
    make_subject_token,
)
from transport.posteo import (
    post_message,
    collect_messages,
)
from util.random import generate_salt


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(data_dir: Path, ui) -> None:
    """
    Send and receive messages.

    Args:
        data_dir: letterbox data directory
        ui:       UI helpers object
    """
    creds_path  = data_dir / "credentials.dat"
    config_path = data_dir / "config.dat"
    vault_path  = data_dir / "vault.dat"

    # --- Prerequisite checks ---
    if not credentials_exist(creds_path):
        print()
        print("  No credentials found.")
        print("  Please set up Posteo credentials first (option 1).")
        ui.press_enter()
        return

    if not vault_path.exists():
        print()
        print("  No vault found.")
        print("  Please generate or import a vault first (option 2).")
        ui.press_enter()
        return

    # --- Unlock ---
    passphrase, salt, vault, credentials = _unlock(
        vault_path, creds_path, config_path, ui
    )
    if passphrase is None:
        return

    # --- Messaging menu ---
    while True:
        send_remaining = vault.remaining_send_pads()
        recv_ids       = set(range(PAD_COUNT)) - vault.send_pads
        recv_remaining = sum(1 for pid in recv_ids if not vault.index[pid])

        ui.box("LETTERBOX")
        print("  Secure OTP Correspondence".center(ui.BOX_WIDTH + 2))
        print(f"  v{APP_VERSION} · {vault.bundle_id:08x}".center(ui.BOX_WIDTH + 2))
        print()
        print(f"  Send pads remaining:    {send_remaining:,}")
        print(f"  Receive pads remaining: {recv_remaining:,}")
        ui.divider()

        warning = check_pad_warning(vault)
        if warning:
            print()
            print(f"  WARNING: {warning}")

        print()
        choice = ui.menu(["Send Message", "Check Mail", "Back"])

        if choice == "1":
            _send(vault, vault_path, config_path, credentials,
                  passphrase, salt, ui)

        elif choice == "2":
            _check_mail(vault, vault_path, config_path, credentials,
                        passphrase, salt, ui)

        elif choice == "3":
            return

        # Reload vault after each operation
        try:
            vault = load_vault(vault_path, passphrase)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Unlock
# ---------------------------------------------------------------------------

def _unlock(vault_path, creds_path, config_path, ui):
    """Unlock vault and credentials. Returns (passphrase, salt, vault, creds) or Nones."""
    config = read_config(config_path)
    salt   = config.salt

    # Reuse session passphrase if already set
    if session_store.is_set():
        try:
            vault = load_vault(vault_path, session_store.get_passphrase())
            credentials = session_store.get_credentials() or load_credentials(
                creds_path, session_store.get_passphrase(), salt
            )
            print("  Vault unlocked.")
            return session_store.get_passphrase(), salt, vault, credentials
        except Exception:
            session_store.clear()

    while True:
        passphrase = ui.enter_passphrase("Enter vault passphrase")
        print()
        print("  Decrypting vault...")
        print("  Verifying integrity...")

        try:
            vault = load_vault(vault_path, passphrase)
        except WrongPassphraseError:
            print()
            print("  ERROR:")
            print("  Vault decryption failed.")
            print("  Press Enter to retry, or type q to quit.")
            if input("  > ").strip().lower() == "q":
                return None, None, None, None
            continue
        except Exception as e:
            print(f"\n  ERROR: {e}")
            return None, None, None, None

        try:
            credentials = load_credentials(creds_path, passphrase, salt)
        except Exception as e:
            print(f"\n  ERROR loading credentials: {e}")
            return None, None, None, None

        session_store.set(passphrase, salt, credentials)
        print("  Vault unlocked.")
        return passphrase, salt, vault, credentials


# ---------------------------------------------------------------------------
# Send
# ---------------------------------------------------------------------------

def _send(vault, vault_path, config_path, credentials, passphrase, salt, ui):

    if vault.remaining_send_pads() == 0:
        ui.box("SEND UNAVAILABLE")
        print()
        print("  No remaining send pads.")
        print("  This vault can no longer send messages.")
        print("  Generate and exchange a new vault to continue.")
        ui.press_enter("Press Enter to return.")
        return

    while True:
        ui.box("SEND MESSAGE")
        print()
        print(f"  Maximum message length: {MAX_CONTENT_BYTES:,} characters")
        print("  Each line ends with Return.")
        print("  Press Return twice when done.")
        print()

        lines          = []
        warned_low     = False
        last_was_blank = False

        try:
            while True:
                line = input("  > ")

                if line == "":
                    if last_was_blank:
                        if lines and lines[-1] == "":
                            lines.pop()
                        break
                    last_was_blank = True
                    lines.append(line)
                    continue
                else:
                    last_was_blank = False

                candidate     = "\n".join(lines + [line])
                candidate_len = len(candidate.encode("utf-8"))

                if candidate_len > MAX_CONTENT_BYTES:
                    over = candidate_len - MAX_CONTENT_BYTES
                    print()
                    print(f"  Message is {over} character{'s' if over != 1 else ''} over the limit.")
                    print()
                    ch = ui.menu(["Start over", "Truncate to fit", "Cancel"])
                    if ch == "1":
                        break
                    elif ch == "3":
                        return
                    elif ch == "2":
                        cb = candidate.encode("utf-8")
                        tr = cb[:MAX_CONTENT_BYTES].decode("utf-8", errors="ignore")
                        lb = max(tr.rfind(" "), tr.rfind("\n"))
                        if lb > 0:
                            tr = tr[:lb]
                        lines = tr.split("\n")
                        break
                    continue

                lines.append(line)
                used      = len("\n".join(lines).encode("utf-8"))
                remaining = MAX_CONTENT_BYTES - used
                if not warned_low and remaining <= 100:
                    print(f"  [{remaining} characters remaining]")
                    warned_low = True

        except KeyboardInterrupt:
            print("\n\n  Cancelled.")
            return

        if not lines or all(ln == "" for ln in lines):
            print()
            print("  Nothing written.")
            ui.press_enter()
            return

        content = "\n".join(lines)

        ui.box("REVIEW MESSAGE")
        print()
        for ln in content.split("\n"):
            print(f"  {ln}")
        print()
        ui.divider()
        print()
        ch = ui.menu(["Send", "Rewrite", "Cancel"])
        if ch == "3":
            return
        if ch == "2":
            continue
        break

    # --- Encrypt and send ---
    print()
    print("  Preparing secure transmission...")

    try:
        pad_id, pad_bytes = reserve_send_pad(vault)
    except PadExhaustedError as e:
        print(f"\n  ERROR: {e}")
        return

    bundle_id = vault.bundle_id
    send_seq  = get_vault_sequence(config_path) + 1

    try:
        transmission = encrypt_message(
            content   = content,
            sequence  = send_seq,
            pad_id    = pad_id,
            pad_bytes = pad_bytes,
            bundle_id = bundle_id,
        )
    except Exception as e:
        vault.index[pad_id] = False  # unreserve
        print(f"\n  ERROR: Could not encrypt: {e}")
        return

    try:
        save_vault(vault, vault_path, passphrase, salt)
    except VaultPersistError as e:
        print(f"\n  CRITICAL: {e}")
        return

    print("  Uploading...")

    try:
        post_message(
            transmission = transmission,
            bundle_id    = bundle_id,
            pad_id       = pad_id,
            subject_key  = vault.subject_key,
            credentials  = credentials,
        )
    except (SendError, PosteoConnectionError):
        print()
        print("  WARNING:")
        print("  Transmission upload failed.")
        print("  The message was not delivered.")
        print("  The send pad was permanently consumed.")
        print("  Recreate the message and send it again.")
        vault.erase_pad(pad_id)
        save_vault(vault, vault_path, passphrase, salt)
        update_vault_sequence(config_path, send_seq)
        ui.press_enter("Press Enter to continue.")
        return

    vault.erase_pad(pad_id)
    save_vault(vault, vault_path, passphrase, salt)
    update_vault_sequence(config_path, send_seq)

    print("  Transmission complete.")
    ui.press_enter("Press Enter to return.")


# ---------------------------------------------------------------------------
# Check mail
# ---------------------------------------------------------------------------

def _check_mail(vault, vault_path, config_path, credentials, passphrase, salt, ui):

    print()
    print("  Checking mail...")

    bundle_id = vault.bundle_id

    try:
        results = collect_messages(
            bundle_id       = bundle_id,
            credentials     = credentials,
            own_token_table = {
                token for token, pid in vault.token_table.items()
                if pid in vault.send_pads
            },
        )
    except (PosteoConnectionError, ReceiveError) as e:
        print(f"\n  ERROR: Could not check mail: {e}")
        ui.press_enter()
        return

    if not results:
        print("  No new messages.")
        ui.press_enter()
        return

    print(f"  {len(results)} message{'s' if len(results) > 1 else ''} received.")

    expected_seq = get_recv_sequence(config_path) + 1

    for token, transmission in results:

        # O(1) lookup using pre-computed token table
        pad_id = vault.token_table.get(token)

        if pad_id is None:
            print()
            print("  WARNING:")
            print("  Could not identify pad for a received message.")
            print("  Message discarded.")
            ui.press_enter()
            continue

        # Get pad bytes
        try:
            pad_bytes = lookup_receive_pad_v3(pad_id, vault)
        except PadAlreadyUsedError as e:
            if e.is_duplicate:
                continue
            print()
            print("  WARNING: Pad already used. Possible replay.")
            ui.press_enter()
            continue
        except Exception:
            print()
            print("  WARNING: Unknown pad. Message discarded.")
            ui.press_enter()
            continue

        # Decrypt
        try:
            msg = decrypt_message(transmission, pad_bytes)
        except DecryptionError:
            print()
            print("  WARNING:")
            print("  Transmission authentication failed.")
            print("  The message was discarded.")
            print("  Request retransmission from your correspondent.")
            ui.press_enter()
            continue
        except Exception as e:
            print(f"\n  WARNING: Could not decrypt: {e}")
            ui.press_enter()
            continue

        recv_seq = msg.get('sequence', 0)

        # Stale/replay check
        if recv_seq > 0 and recv_seq < expected_seq:
            print()
            print("  WARNING:")
            print("  Stale or replayed transmission detected.")
            print(f"  Received #{recv_seq}  Expected #{expected_seq}")
            print("  Transmission discarded.")
            ui.press_enter()
            continue

        # Confirm pad used and save vault
        confirm_pad_used(pad_id, vault)
        save_vault(vault, vault_path, passphrase, salt)

        # Gap warning
        if recv_seq > expected_seq:
            print()
            print("  WARNING:")
            print("  One or more transmissions may be missing.")
            print(f"  Expected #{expected_seq}  Received #{recv_seq}")

        update_recv_sequence(config_path, recv_seq)
        expected_seq = recv_seq + 1

        # Display
        print()
        print("  Authenticated transmission received.")
        ui.divider()
        print()
        for ln in msg.get('content', '').split("\n"):
            print(f"  {ln}")
        print()
        ui.divider()
        ui.press_enter("Press Enter to clear message.")
