# ---------------------------------------------------------------------------
# Letterbox v3.1.0
# session_store.py -- In-session passphrase cache (module-level singleton)
# ---------------------------------------------------------------------------
#
# Change Control
# 2026-05-09  M.Lines   v3.1.0  Initial release. See README.md and CHANGELOG.md.
_passphrase   = None
_salt         = None
_credentials  = None


def set(passphrase, salt, credentials=None):
    global _passphrase, _salt, _credentials
    _passphrase  = passphrase
    _salt        = salt
    _credentials = credentials


def get_passphrase():
    return _passphrase


def get_salt():
    return _salt


def get_credentials():
    return _credentials


def set_credentials(credentials):
    global _credentials
    _credentials = credentials


def is_set():
    return _passphrase is not None


def clear():
    global _passphrase, _salt, _credentials
    _passphrase  = None
    _salt        = None
    _credentials = None
