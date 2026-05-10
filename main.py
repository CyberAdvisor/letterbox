# ---------------------------------------------------------------------------
# Letterbox v3.1.0
# main.py -- Entry point, UI helpers, top-level menu, session_store integration
# ---------------------------------------------------------------------------
#
# Change Control
# 2026-05-09  M.Lines   v3.1.0  Initial release. See README.md and CHANGELOG.md.
# 2026-05-09  M.Lines   v3.2.0  Passphrase strength enforcement added.
import os
import sys
import textwrap
import time
from pathlib import Path

import session_store
from core.constants import APP_VERSION


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

def is_pythonista():
    try:
        import console
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# UI helpers (passed as object to sub-modules)
# ---------------------------------------------------------------------------

class UI:
    BOX_WIDTH = 46

    def box(self, title):
        print()
        print('┌' + '─' * self.BOX_WIDTH + '┐')
        print('│' + title.center(self.BOX_WIDTH) + '│')
        print('└' + '─' * self.BOX_WIDTH + '┘')

    def divider(self):
        print('─' * (self.BOX_WIDTH + 2))

    def press_enter(self, msg="Press Enter to continue."):
        input(f"\n  {msg}")

    def print_wrapped(self, text, width=60, indent="  "):
        for line in text.splitlines():
            if not line.strip():
                print()
                continue
            for wrapped in textwrap.wrap(line, width):
                print(f"{indent}{wrapped}")

    def menu(self, options):
        for i, label in enumerate(options, 1):
            print(f"  [{i}] {label}")
        print()
        valid = {str(i) for i in range(1, len(options) + 1)}
        while True:
            choice = input("  Select Option > ").strip()
            if choice in valid:
                return choice
            print("  Invalid selection.")

    def enter_passphrase(self, prompt):
        print()
        print("  Note: passphrase is visible as you type.")
        print("  Enter when no one else can see your screen.")
        print("  Type q to quit.")
        print()
        val = input(f"  {prompt}: ").strip()
        if val.lower() == 'q':
            print()
            print("  Goodbye.")
            print()
            sys.exit(0)
        return val

    def check_passphrase_strength(self, passphrase):
        """
        Returns a list of unmet requirements, empty if passphrase is strong enough.
        """
        errors = []
        if len(passphrase) < 10:
            errors.append("At least 10 characters required.")
        if not any(c.isupper() for c in passphrase):
            errors.append("At least one uppercase letter required.")
        if not any(not c.isalnum() and c != ' ' for c in passphrase):
            errors.append("At least one non-alphanumeric character required (not space).")
        return errors

    def enter_passphrase_with_confirm(self, prompt):
        while True:
            p1 = self.enter_passphrase(prompt)
            errors = self.check_passphrase_strength(p1)
            if errors:
                print()
                print("  Passphrase does not meet requirements:")
                for e in errors:
                    print(f"  - {e}")
                print()
                continue
            p2 = self.enter_passphrase("Confirm passphrase")
            if p1 == p2:
                return p1
            print()
            print("  Passphrases do not match. Try again.")

    def format_timestamp(self, ts):
        return time.strftime("%d %b %Y at %H:%M", time.localtime(ts))


# ---------------------------------------------------------------------------
# Data directory
# ---------------------------------------------------------------------------

def get_data_dir():
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
# Platform warning
# ---------------------------------------------------------------------------

def _check_platform():
    if not is_pythonista():
        print()
        print("  WARNING: Letterbox is designed for iPad / Pythonista 3.")
        print("  Running on another platform reduces security guarantees.")
        print("  iOS sandbox, filesystem encryption, and keylogger")
        print("  protection are not available on this platform.")
        print()


# ---------------------------------------------------------------------------
# Disclaimer
# ---------------------------------------------------------------------------

def _show_disclaimer(config_path, ui):
    from core.constants import DISCLAIMER_TEXT
    from store.config import record_disclaimer_agreed

    ui.box("DISCLAIMER")
    print()
    ui.print_wrapped(DISCLAIMER_TEXT)
    print()
    ui.divider()
    print()
    answer = input("  Type AGREE to continue, or anything else to exit: ").strip()
    print()
    if answer != "AGREE":
        print("  Goodbye.")
        print()
        sys.exit(0)
    if config_path.exists():
        try:
            record_disclaimer_agreed(config_path)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------

def main():
    from store.config import config_exists, has_agreed_disclaimer

    print(f"\n  Letterbox v{APP_VERSION}")
    _check_platform()

    data_dir    = get_data_dir()
    config_path = data_dir / "config.dat"
    ui          = UI()

    if not has_agreed_disclaimer(config_path):
        _show_disclaimer(config_path, ui)

    while True:
        ui.box("LETTERBOX")
        print("  Secure OTP Correspondence".center(ui.BOX_WIDTH + 2))
        # Show version and vault ID if vault exists
        vault_path = data_dir / "vault.dat"
        if vault_path.exists() and session_store.is_set():
            try:
                from store.vault import load_vault
                _v = load_vault(vault_path, session_store.get_passphrase())
                print(f"  v{APP_VERSION} · {_v.bundle_id:08x}".center(ui.BOX_WIDTH + 2))
            except Exception:
                print(f"  v{APP_VERSION}".center(ui.BOX_WIDTH + 2))
        else:
            print(f"  v{APP_VERSION}".center(ui.BOX_WIDTH + 2))
        print()
        ui.divider()
        print()
        creds_done = (data_dir / "credentials.dat").exists()
        vault_done = (data_dir / "vault.dat").exists()
        choice = ui.menu([
            f"Enter / Update Posteo Credentials{'  ✓' if creds_done else ''}",
            f"Generate / Import OTP Vault{'  ✓' if vault_done else ''}",
            "Send / Receive Messages",
            "Exit",
        ])

        if choice == "1":
            import credentials_ui
            credentials_ui.run(data_dir, ui)

        elif choice == "2":
            import vault_ui
            vault_ui.run(data_dir, ui)

        elif choice == "3":
            import messages_ui
            messages_ui.run(data_dir, ui)

        elif choice == "4":
            print()
            print("  Goodbye.")
            print()
            sys.exit(0)


if __name__ == "__main__":
    main()
