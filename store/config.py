# store/config.py
#
# Reads and writes the config file.
#
# The config file is the only file stored unencrypted on disk.
# It contains no sensitive data -- only:
#   - the KDF salt (public by design -- needed to derive the key)
#   - failed passphrase attempt count since last successful login
#   - timestamp of last failed attempt
#   - timestamp of last successful login
#   - config format version
#
# The config file must exist before any other file can be opened,
# because the salt it contains is required to derive the encryption
# key used for the vault, credentials, and history database.
#
# File format (binary, fixed size):
#   [VERSION:           2 bytes]  unsigned short, big-endian
#   [SALT:             32 bytes]  random bytes, generated once at setup
#   [FAILED_ATTEMPTS:   2 bytes]  unsigned short, big-endian
#   [LAST_FAILED_TS:    8 bytes]  unix timestamp, big-endian, 0 = never
#   [LAST_SUCCESS_TS:   8 bytes]  unix timestamp, big-endian, 0 = never
#   [VAULT_SEQUENCE:    8 bytes]  last known vault send sequence counter
#                                 used to detect backup rollback
#   [DISCLAIMER_AGREED: 1 byte]   0 = not yet agreed, 1 = agreed
# Total: 61 bytes
#
# ---------------------------------------------------------------------------
# Change Control
# ---------------------------------------------------------------------------
# Date        Author    Description
# ---------------------------------------------------------------------------
# 2026-05-02  M.Lines   Initial version
# ---------------------------------------------------------------------------

import struct
import time
from pathlib import Path

from core.constants import CONFIG_VERSION, CONFIG_SALT_SIZE
from core.exceptions import (
    LetterboxError,
    SetupIncompleteError,
)


# ---------------------------------------------------------------------------
# Config file structure
# ---------------------------------------------------------------------------

# Byte offsets within the file
_OFFSET_VERSION        = 0    # 2 bytes
_OFFSET_SALT           = 2    # 32 bytes
_OFFSET_FAILED         = 34   # 2 bytes
_OFFSET_LAST_FAILED    = 36   # 8 bytes
_OFFSET_LAST_SUCCESS   = 44   # 8 bytes
_OFFSET_VAULT_SEQ      = 52   # 8 bytes
_OFFSET_DISCLAIMER     = 60   # 1 byte

CONFIG_FILE_SIZE       = 61   # total bytes


# ---------------------------------------------------------------------------
# ConfigData
# ---------------------------------------------------------------------------

class ConfigData:
    """
    Holds the contents of the config file.
    All fields are plain Python types -- no binary packing here.
    Packing and unpacking is handled by read_config() and write_config().
    """

    def __init__(
        self,
        salt:               bytes,
        failed_attempts:    int  = 0,
        last_failed_ts:     int  = 0,
        last_success_ts:    int  = 0,
        vault_sequence:     int  = 0,
        disclaimer_agreed:  bool = False,
    ):
        # salt must be exactly CONFIG_SALT_SIZE bytes
        if len(salt) != CONFIG_SALT_SIZE:
            raise LetterboxError(
                f"Salt must be {CONFIG_SALT_SIZE} bytes, "
                f"got {len(salt)}."
            )

        self.salt               = salt
        self.failed_attempts    = failed_attempts
        self.last_failed_ts     = last_failed_ts
        self.last_success_ts    = last_success_ts
        self.vault_sequence     = vault_sequence
        self.disclaimer_agreed  = disclaimer_agreed


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

def read_config(path: Path) -> ConfigData:
    """
    Read and parse the config file.

    Returns a ConfigData instance.

    Raises:
        FileNotFoundError    if the file does not exist
        SetupIncompleteError if the file is the wrong size
    """
    if not path.exists():
        raise FileNotFoundError(
            f"Config file not found: {path}\n"
            "Has setup been completed?"
        )

    raw = path.read_bytes()

    if len(raw) != CONFIG_FILE_SIZE:
        raise SetupIncompleteError(
            f"Config file is {len(raw)} bytes, "
            f"expected {CONFIG_FILE_SIZE}.\n"
            "The file may be corrupt or from an incompatible version.\n"
            "Reset and run setup again."
        )

    # Parse version. Only version 1 exists. Log unexpected version
    # but do not refuse to load -- fields are at fixed offsets.
    version = struct.unpack_from('>H', raw, _OFFSET_VERSION)[0]
    if version != CONFIG_VERSION:
        pass  # Future versions may extend the format gracefully

    salt               = raw[_OFFSET_SALT : _OFFSET_SALT + CONFIG_SALT_SIZE]
    failed_attempts    = struct.unpack_from('>H', raw, _OFFSET_FAILED)[0]
    last_failed_ts     = struct.unpack_from('>Q', raw, _OFFSET_LAST_FAILED)[0]
    last_success_ts    = struct.unpack_from('>Q', raw, _OFFSET_LAST_SUCCESS)[0]
    vault_sequence     = struct.unpack_from('>Q', raw, _OFFSET_VAULT_SEQ)[0]
    disclaimer_agreed = bool(raw[_OFFSET_DISCLAIMER])

    return ConfigData(
        salt               = salt,
        failed_attempts    = failed_attempts,
        last_failed_ts     = last_failed_ts,
        last_success_ts    = last_success_ts,
        vault_sequence     = vault_sequence,
        disclaimer_agreed  = disclaimer_agreed,
    )


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------

def write_config(path: Path, config: ConfigData) -> None:
    """
    Write a ConfigData instance to disk.

    Writes atomically -- writes to a temp file then renames.
    This prevents a corrupt config if the write is interrupted.

    Raises:
        OSError if the file cannot be written.
    """
    raw = bytearray(CONFIG_FILE_SIZE)

    struct.pack_into('>H', raw, _OFFSET_VERSION,      CONFIG_VERSION)
    raw[_OFFSET_SALT : _OFFSET_SALT + CONFIG_SALT_SIZE] = config.salt
    struct.pack_into('>H', raw, _OFFSET_FAILED,       config.failed_attempts)
    struct.pack_into('>Q', raw, _OFFSET_LAST_FAILED,  config.last_failed_ts)
    struct.pack_into('>Q', raw, _OFFSET_LAST_SUCCESS, config.last_success_ts)
    struct.pack_into('>Q', raw, _OFFSET_VAULT_SEQ,    config.vault_sequence)
    raw[_OFFSET_DISCLAIMER] = 1 if config.disclaimer_agreed else 0

    # Write atomically via temp file + rename.
    # On the same filesystem rename is atomic on both macOS and iOS.
    tmp_path = path.with_suffix('.tmp')
    try:
        tmp_path.write_bytes(bytes(raw))
        tmp_path.rename(path)
    except Exception:
        # Clean up temp file if anything went wrong
        if tmp_path.exists():
            tmp_path.unlink()
        raise


# ---------------------------------------------------------------------------
# Create (first run only)
# ---------------------------------------------------------------------------

def create_config(path: Path, salt: bytes) -> ConfigData:
    """
    Create a brand new config file with the given salt.
    All counters start at zero.

    Called once during first-run setup after the salt is generated.

    Raises:
        FileExistsError if a config file already exists at this path.
        OSError         if the file cannot be written.
    """
    if path.exists():
        raise FileExistsError(
            f"Config file already exists: {path}\n"
            "Setup has already been completed.\n"
            "Use --reset to start over."
        )

    config = ConfigData(salt=salt)
    write_config(path, config)
    return config


# ---------------------------------------------------------------------------
# Attempt tracking
# ---------------------------------------------------------------------------

def record_failed_attempt(path: Path) -> int:
    """
    Increment the failed attempt counter and record the timestamp.
    Writes the updated config to disk immediately.

    Returns the updated failed attempt count.
    """
    config                 = read_config(path)
    config.failed_attempts += 1
    config.last_failed_ts  = int(time.time())
    write_config(path, config)
    return config.failed_attempts


def record_successful_login(path: Path) -> int:
    """
    Record a successful login.

    Returns the failed attempt count that existed before this
    successful login. The caller uses this to decide whether
    to show a warning to the user.

    Resets failed_attempts to 0 and updates last_success_ts.
    """
    config             = read_config(path)
    previous_failures  = config.failed_attempts

    config.failed_attempts = 0
    config.last_success_ts = int(time.time())
    write_config(path, config)

    return previous_failures


def get_last_failed_timestamp(path: Path) -> int:
    """
    Return the unix timestamp of the last failed attempt.
    Returns 0 if there has never been a failed attempt.
    """
    config = read_config(path)
    return config.last_failed_ts


# ---------------------------------------------------------------------------
# Vault sequence tracking
#
# Stored in config (unencrypted) so it survives independently of
# the vault file. Used to detect if the vault was restored from
# a backup (rollback attack), which would risk pad reuse.
# ---------------------------------------------------------------------------

def get_vault_sequence(path: Path) -> int:
    """
    Return the last known vault send sequence counter.
    Returns 0 if never set.
    """
    config = read_config(path)
    return config.vault_sequence


def update_vault_sequence(path: Path, sequence: int) -> None:
    """
    Update the vault sequence counter.
    Called each time a message is successfully sent.

    The sequence counter only ever increases. If the vault file is
    restored from a backup, its internal sequence will be lower than
    this stored value, triggering a VaultRollbackError on next load.

    Raises:
        LetterboxError if sequence goes backwards -- this should
        never happen and indicates a serious problem.
    """
    config = read_config(path)

    if sequence < config.vault_sequence:
        raise LetterboxError(
            f"Sequence counter went backwards: "
            f"stored={config.vault_sequence}, "
            f"new={sequence}.\n"
            "This should never happen. Do not send messages."
        )

    config.vault_sequence = sequence
    write_config(path, config)


# ---------------------------------------------------------------------------
# Existence check
# ---------------------------------------------------------------------------

def record_disclaimer_agreed(path: Path) -> None:
    """
    Record that the user has agreed to the disclaimer.
    Called once after the user types AGREE at startup.
    Subsequent startups skip the disclaimer entirely.
    """
    config = read_config(path)
    config.disclaimer_agreed = True
    write_config(path, config)


def has_agreed_disclaimer(path: Path) -> bool:
    """
    Return True if the user has previously agreed to the disclaimer.
    Returns False if config does not exist or disclaimer not yet agreed.
    """
    if not path.exists():
        return False
    try:
        config = read_config(path)
        return config.disclaimer_agreed
    except Exception:
        return False


def config_exists(path: Path) -> bool:
    """
    Return True if a config file exists at the given path.
    Used at startup to determine whether to run setup or login.
    """
    return path.exists()
