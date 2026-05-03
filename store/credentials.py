# store/credentials.py
#
# Encrypted storage for Posteo shared account credentials.
#
# Stores the IMAP credentials for the shared Posteo account
# used as the message transport dead drop. These credentials
# are encrypted at rest using the same key derivation as the
# vault and history database, but with a distinct purpose string
# so the key is different even with the same passphrase.
#
# Credentials stored:
#   - IMAP host
#   - IMAP port
#   - username (email address)
#   - password (Posteo app password)
#   - folder name for outbound messages (e.g. Letterbox-ab)
#   - folder name for inbound messages  (e.g. Letterbox-ba)
#
# File format:
#   The credentials are serialised as JSON, encrypted with
#   XOR keystream + HMAC (same scheme as vault), and written
#   to disk. The salt comes from the config file.
#
# ---------------------------------------------------------------------------
# Change Control
# ---------------------------------------------------------------------------
# Date        Author    Description
# ---------------------------------------------------------------------------
# 2026-05-02  M.Lines   Initial version
# ---------------------------------------------------------------------------

import json
from pathlib import Path

from store.vault import derive_credentials_key, _encrypt, _decrypt
from core.exceptions import CredentialsError


# ---------------------------------------------------------------------------
# CredentialsData
# ---------------------------------------------------------------------------

class CredentialsData:
    """
    Holds the Posteo shared account credentials.

    Attributes:
        imap_host:    IMAP server hostname
        imap_port:    IMAP server port (usually 993)
        username:     account email address
        password:     Posteo app password
        folder:       shared folder for all messages
        is_initiator: True if this party generated the vault
    """

    # Posteo IMAP defaults
    DEFAULT_HOST = 'posteo.de'
    DEFAULT_PORT = 993

    def __init__(
        self,
        username:     str,
        password:     str,
        folder:       str,
        is_initiator: bool = True,
        imap_host:    str = DEFAULT_HOST,
        imap_port:    int = DEFAULT_PORT,
    ):
        if not username:
            raise ValueError("Username must not be empty.")
        if not password:
            raise ValueError("Password must not be empty.")
        if not folder:
            raise ValueError("Folder must not be empty.")

        self.imap_host    = imap_host
        self.imap_port    = imap_port
        self.username     = username
        self.password     = password
        self.folder       = folder
        self.is_initiator = is_initiator

    def to_dict(self) -> dict:
        return {
            'imap_host':  self.imap_host,
            'imap_port':  self.imap_port,
            'username':   self.username,
            'password':   self.password,
            'folder':       self.folder,
            'is_initiator': self.is_initiator,
        }

    @classmethod
    def from_dict(cls, d: dict) -> 'CredentialsData':
        return cls(
            username   = d['username'],
            password   = d['password'],
            folder       = d['folder'],
            is_initiator = d.get('is_initiator', True),
            imap_host  = d.get('imap_host', cls.DEFAULT_HOST),
            imap_port  = d.get('imap_port', cls.DEFAULT_PORT),
        )


# ---------------------------------------------------------------------------
# Folder name convention
# ---------------------------------------------------------------------------

def make_folder_name(bundle_id: int) -> str:
    """
    Generate the shared folder name for a given bundle ID.

    Both parties use the same folder -- they post to it and
    read from it. Each message is already encrypted so only
    the intended recipient can decrypt it. The bundle ID in
    the plaintext header identifies which vault to use.

    Args:
        bundle_id: the vault bundle ID as an integer

    Returns:
        folder name string e.g. 'Letterbox-a3f8c291'
    """
    return f'Letterbox-{bundle_id:08x}'


# ---------------------------------------------------------------------------
# Save and load
# ---------------------------------------------------------------------------

def save_credentials(
    path:        Path,
    credentials: CredentialsData,
    passphrase:  str,
    salt:        bytes,
) -> None:
    """
    Encrypt and write credentials to disk.

    Writes atomically via temp file + rename.

    Args:
        path:        destination file path
        credentials: CredentialsData to save
        passphrase:  user's passphrase
        salt:        32-byte salt from config

    Raises:
        CredentialsError if the file cannot be written.
    """
    key       = derive_credentials_key(passphrase, salt)
    plaintext = json.dumps(credentials.to_dict()).encode('utf-8')
    encrypted = _encrypt(plaintext, key)

    tmp_path = path.with_suffix('.tmp')
    try:
        tmp_path.write_bytes(encrypted)
        tmp_path.rename(path)
    except Exception as e:
        if tmp_path.exists():
            tmp_path.unlink()
        raise CredentialsError(
            f"Could not save credentials: {e}"
        ) from e


def load_credentials(
    path:       Path,
    passphrase: str,
    salt:       bytes,
) -> CredentialsData:
    """
    Read and decrypt credentials from disk.

    Args:
        path:       credentials file path
        passphrase: user's passphrase
        salt:       32-byte salt from config

    Returns:
        CredentialsData

    Raises:
        CredentialsError if the file is missing, corrupt,
        or the passphrase is wrong.
    """
    if not path.exists():
        raise CredentialsError(
            "Credentials file not found.\n"
            "Has setup been completed?"
        )

    try:
        encrypted = path.read_bytes()
    except OSError as e:
        raise CredentialsError(
            f"Could not read credentials file: {e}"
        ) from e

    key       = derive_credentials_key(passphrase, salt)
    plaintext = _decrypt(encrypted, key)

    if plaintext is None:
        raise CredentialsError(
            "Credentials could not be decrypted.\n"
            "The passphrase may be incorrect or "
            "the file may be corrupt."
        )

    try:
        data = json.loads(plaintext.decode('utf-8'))
        return CredentialsData.from_dict(data)
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        raise CredentialsError(
            f"Credentials file is corrupt: {e}"
        ) from e


def credentials_exist(path: Path) -> bool:
    """
    Return True if a credentials file exists at the given path.
    """
    return path.exists()
