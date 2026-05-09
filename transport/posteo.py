# transport/posteo.py
#
# IMAP dead drop transport using a shared Posteo account.
#
# Messages never travel as sent email. Instead:
#   - Sending:   Alice connects to the shared account and appends
#                a message directly to the outbound folder using
#                IMAP APPEND. No email is sent. No SMTP is used.
#   - Receiving: Bob connects to the same shared account and reads
#                messages from his inbound folder (Alice's outbound).
#                Messages are deleted after successful collection.
#
# This means:
#   - No SMTP logs anywhere
#   - No sender/recipient headers in any email
#   - No routing metadata
#   - The message never traverses the email network
#   - Posteo sees only that two IP addresses access the same account
#
# All messages are already OTP-encrypted before reaching this module.
# The transport does not need to provide confidentiality -- it only
# needs to provide delivery. Security comes from the encryption layer.
#
# Message format on the server:
#   Subject: msg-[bundle_id_hex]-[pad_id_hex]
#   Body:    MSG1:[base64 encoded transmission]
#
# The subject line encodes bundle_id and pad_id so the client can
# search for messages matching known bundle IDs without downloading
# all messages in the folder.
#
# ---------------------------------------------------------------------------
# Change Control
# 2026-05-09  M.Lines   v3.1.0  Complete rewrite. See README.md, CHANGELOG.md, TECHNICAL_OVERVIEW.md.
# ---------------------------------------------------------------------------
# Date        Author    Description
# ---------------------------------------------------------------------------
# 2026-05-02  M.Lines   Initial version
# 2026-05-09  M.Lines   v3.1.0: subject token obfuscation; own-message filter via token table
# ---------------------------------------------------------------------------

import base64
import email
import email.mime.text
import imaplib
import ssl
import time
from pathlib import Path

from core.constants import TRANSMISSION_SIZE, BUNDLE_ID_BYTES, PAD_ID_BYTES
from core.exceptions import (
    PosteoConnectionError,
    SendError,
    ReceiveError,
    VaultUploadError,
    VaultDownloadError,
    TransmissionSizeError,
)
from store.credentials import CredentialsData
from core.pad import make_subject_token


# ---------------------------------------------------------------------------
# Message encoding
# ---------------------------------------------------------------------------

# Prefix identifies this as a Letterbox transmission.
# Version number allows future format changes.
MSG_PREFIX = 'MSG1:'


def encode_transmission(transmission: bytes) -> str:
    """
    Encode a raw transmission as a printable string for the email body.

    Args:
        transmission: exactly TRANSMISSION_SIZE bytes

    Returns:
        string starting with MSG_PREFIX followed by base64
    """
    if len(transmission) != TRANSMISSION_SIZE:
        raise TransmissionSizeError(
            f"Transmission must be {TRANSMISSION_SIZE} bytes, "
            f"got {len(transmission)}."
        )
    return MSG_PREFIX + base64.b64encode(transmission).decode('ascii')


def decode_transmission(body: str) -> bytes:
    """
    Decode an email body back to raw transmission bytes.

    Args:
        body: email body string

    Returns:
        transmission bytes, or None if body is not a valid transmission
    """
    body = body.strip()
    if not body.startswith(MSG_PREFIX):
        return None
    try:
        data = base64.b64decode(body[len(MSG_PREFIX):])
    except Exception:
        return None
    if len(data) != TRANSMISSION_SIZE:
        return None
    return data


def make_subject(bundle_id: int, subject_token: str) -> str:
    """
    Build the email subject line from bundle_id and obfuscated token.
    """
    return f'msg-{bundle_id:08x}-{subject_token}'


def parse_subject(subject: str) -> tuple:
    """
    Extract bundle_id and subject_token from an email subject line.

    Returns (bundle_id, token_str) or (None, None) if no match.
    """
    try:
        parts = subject.strip().split('-')
        if len(parts) != 3 or parts[0] != 'msg':
            return None, None
        bundle_id = int(parts[1], 16)
        token     = parts[2]
        return bundle_id, token
    except (ValueError, IndexError):
        return None, None


# ---------------------------------------------------------------------------
# IMAP connection
# ---------------------------------------------------------------------------

def _connect(credentials: CredentialsData) -> imaplib.IMAP4_SSL:
    """
    Open an authenticated IMAP connection to Posteo.

    Args:
        credentials: CredentialsData with host, port, username, password

    Returns:
        authenticated IMAP4_SSL connection

    Raises:
        PosteoConnectionError if connection or login fails
    """
    try:
        context = ssl.create_default_context()
        conn    = imaplib.IMAP4_SSL(
            credentials.imap_host,
            credentials.imap_port,
            ssl_context=context,
        )
        conn.login(credentials.username, credentials.password)
        return conn
    except imaplib.IMAP4.error as e:
        raise PosteoConnectionError(
            f"Could not connect to {credentials.imap_host}: {e}\n"
            "Check your credentials and internet connection."
        ) from e
    except OSError as e:
        raise PosteoConnectionError(
            f"Network error connecting to {credentials.imap_host}: {e}\n"
            "Check your internet connection."
        ) from e


def _ensure_folder(conn: imaplib.IMAP4_SSL, folder: str) -> None:
    """
    Create an IMAP folder if it does not already exist.
    Silently succeeds if the folder already exists.
    """
    conn.create(folder)
    # CREATE returns NO if folder exists -- that is fine, ignore it


# ---------------------------------------------------------------------------
# Send (post to outbound folder)
# ---------------------------------------------------------------------------

def post_message(
    transmission:  bytes,
    bundle_id:     int,
    pad_id:        int,
    subject_key:   bytes,
    credentials:   CredentialsData,
) -> None:
    """
    Post an encrypted transmission to the outbound folder.

    Connects to the shared Posteo account, ensures the outbound
    folder exists, and appends the message directly using IMAP APPEND.
    No email is sent. No SMTP is involved.

    The pad must already be marked used and the vault saved before
    calling this. If this call fails, the message was not delivered
    but the pad is already consumed. The caller should save the
    transmission for manual retry with a new pad.

    Args:
        transmission:  exactly TRANSMISSION_SIZE encrypted bytes
        bundle_id:     vault bundle ID (for subject line)
        pad_id:        pad ID used (for subject line)
        credentials:   Posteo account credentials

    Raises:
        SendError if the message cannot be posted.
    """
    body    = encode_transmission(transmission)
    token   = make_subject_token(subject_key, pad_id)
    subject = make_subject(bundle_id, token)

    # Build a minimal email message -- no To, no From
    # These fields would create metadata we do not want
    # Use us-ascii charset: body is pure base64 ASCII.
    # 7bit transfer encoding: content is already ASCII-safe,
    # no further encoding by the MIME library needed.
    msg            = email.mime.text.MIMEText(body, 'plain', 'us-ascii')
    msg['Subject'] = subject
    msg.replace_header('Content-Transfer-Encoding', '7bit')

    try:
        conn = _connect(credentials)
        try:
            _ensure_folder(conn, credentials.folder)
            conn.select(credentials.folder)

            # APPEND writes directly to folder -- no sending
            conn.append(
                credentials.folder,
                '',       # no flags
                imaplib.Time2Internaldate(time.time()),
                msg.as_bytes(),
            )
        finally:
            try:
                conn.logout()
            except Exception:
                pass

    except PosteoConnectionError:
        raise
    except Exception as e:
        raise SendError(
            f"Could not post message: {e}\n"
            "Check your internet connection and Posteo credentials."
        ) from e


# ---------------------------------------------------------------------------
# Receive (collect from inbound folder)
# ---------------------------------------------------------------------------

def collect_messages(
    bundle_id:        int,
    credentials:      CredentialsData,
    own_token_table:  set = None,
) -> list:
    """
    Collect all pending transmissions from the shared folder.

    Returns list of (subject_token, transmission_bytes) tuples.
    Own messages (token is in own_token_table) are deleted but not returned.

    Args:
        bundle_id:        vault bundle ID to search for
        credentials:      Posteo account credentials
        own_token_table:  set of token strings we sent (from vault.token_table)

    Returns:
        list of (token, transmission_bytes) tuples

    Raises:
        ReceiveError if the folder cannot be accessed.
    """
    transmissions = []
    subject_prefix = f'msg-{bundle_id:08x}'

    own_tokens = own_token_table or set()

    try:
        conn = _connect(credentials)
        try:
            # Check inbound folder exists
            status, _ = conn.select(credentials.folder)
            if status != 'OK':
                # Folder does not exist yet -- no messages waiting
                return []

            # Search for messages matching our bundle ID
            status, message_ids = conn.search(
                None,
                f'SUBJECT "{subject_prefix}"'
            )

            if status != 'OK' or not message_ids[0]:
                return []

            ids = message_ids[0].split()

            for msg_id in ids:
                try:
                    # Fetch subject to get token, then check if it's our own message
                    msg_token = ''
                    status2, hdr = conn.fetch(msg_id, '(BODY[HEADER.FIELDS (SUBJECT)])')
                    if status2 == 'OK' and hdr and hdr[0]:
                        hdr_text = hdr[0][1]
                        if isinstance(hdr_text, bytes):
                            hdr_text = hdr_text.decode('utf-8', errors='ignore')
                        subject = ''
                        for line in hdr_text.splitlines():
                            if line.lower().startswith('subject:'):
                                subject = line[8:].strip()
                                break
                        _, token_from_subject = parse_subject(subject)
                        msg_token = token_from_subject or ''
                        if token_from_subject in own_tokens:
                            # Our own message -- leave for correspondent, skip
                            continue

                    # Fetch message
                    status, data = conn.fetch(msg_id, '(RFC822)')
                    if status != 'OK' or not data or not data[0]:
                        continue

                    raw_email = data[0][1]
                    if isinstance(raw_email, str):
                        raw_email = raw_email.encode('utf-8')

                    parsed = email.message_from_bytes(raw_email)
                    body   = parsed.get_payload(decode=True)

                    if body is None:
                        continue

                    body_str     = body.decode('utf-8', errors='ignore')
                    transmission = decode_transmission(body_str)

                    if transmission is not None:
                        transmissions.append((msg_token, transmission))
                        # Delete from server after successful decode
                        conn.store(msg_id, '+FLAGS', '\\Deleted')
                    # If decode failed, leave message on server

                except Exception:
                    # Skip individual message errors
                    # Leave the message on server for next attempt
                    continue

            # Expunge all deleted messages (own messages and received).
            # Previously only expunged when transmissions were found,
            # leaving own-message deletions unflushed until the next
            # receive that collected a real message.
            if transmissions or ids:
                conn.expunge()

        finally:
            try:
                conn.logout()
            except Exception:
                pass

    except PosteoConnectionError:
        raise
    except Exception as e:
        raise ReceiveError(
            f"Could not collect messages: {e}\n"
            "Check your internet connection and Posteo credentials."
        ) from e

    return transmissions


# ---------------------------------------------------------------------------
# Vault transfer via Posteo
# ---------------------------------------------------------------------------

VAULT_SUBJECT  = 'letterbox-vault-transfer'
VAULT_FOLDER   = 'Letterbox-Setup'


def _delete_stale_vaults(conn: imaplib.IMAP4_SSL) -> int:
    """
    Delete any existing vault transfers from the setup folder.

    Called before uploading a new vault so that Bob always finds
    exactly one vault -- the most recently generated one. Without
    this, multiple reset-and-setup cycles leave orphaned vaults
    on the server and Bob's client picks one arbitrarily.

    Args:
        conn: authenticated IMAP connection, already logged in

    Returns:
        number of stale vaults deleted
    """
    deleted = 0
    try:
        status, _ = conn.select(VAULT_FOLDER)
        if status != 'OK':
            return 0   # folder doesn't exist yet -- nothing to delete

        status, message_ids = conn.search(
            None, f'SUBJECT "{VAULT_SUBJECT}"'
        )
        if status != 'OK' or not message_ids[0]:
            return 0

        for msg_id in message_ids[0].split():
            conn.store(msg_id, '+FLAGS', '\\Deleted')
            deleted += 1

        if deleted:
            conn.expunge()

    except Exception:
        pass   # stale cleanup is best-effort; don't block the upload

    return deleted


def upload_vault(
    vault_bytes:  bytes,
    credentials:  CredentialsData,
) -> None:
    """
    Upload an encrypted transfer vault to the setup folder.

    Used during the initial exchange when Alice uploads the
    encrypted vault for Bob to collect.

    Deletes any previously uploaded vaults before uploading the
    new one, so Bob always finds exactly one vault. This handles
    the case where Alice resets and runs setup multiple times
    before Bob has imported.

    The vault is base64 encoded and stored as the email body
    in a dedicated setup folder, separate from message folders.

    Args:
        vault_bytes:  encrypted transfer vault bytes
        credentials:  Posteo account credentials

    Raises:
        VaultUploadError if the upload fails.
    """
    body           = 'VAULT1:' + base64.b64encode(vault_bytes).decode('ascii')
    # Use us-ascii charset and explicit 7bit transfer encoding.
    # The vault body is pure base64 ASCII -- no further encoding
    # by the MIME library is needed or wanted. utf-8 charset was
    # triggering additional base64 encoding expanding 39MB to 71MB.
    msg            = email.mime.text.MIMEText(body, 'plain', 'us-ascii')
    msg['Subject'] = VAULT_SUBJECT
    msg.replace_header('Content-Transfer-Encoding', '7bit')

    try:
        conn = _connect(credentials)
        try:
            # Delete any stale vaults before uploading the new one.
            # If Alice has reset and re-run setup, old vaults on the
            # server would otherwise confuse Bob's import.
            _delete_stale_vaults(conn)
            _ensure_folder(conn, VAULT_FOLDER)
            conn.append(
                VAULT_FOLDER,
                '',
                imaplib.Time2Internaldate(time.time()),
                msg.as_bytes(),
            )
        finally:
            try:
                conn.logout()
            except Exception:
                pass

    except PosteoConnectionError:
        raise
    except Exception as e:
        raise VaultUploadError(
            f"Could not upload vault: {e}"
        ) from e


def download_vault(credentials: CredentialsData) -> bytes:
    """
    Download the encrypted transfer vault from the setup folder.

    Used during initial setup when Bob collects the vault
    Alice has uploaded.

    Deletes the vault from the server after successful download.

    Args:
        credentials: Posteo account credentials

    Returns:
        encrypted vault bytes

    Raises:
        VaultDownloadError if no vault is found or download fails.
    """
    try:
        conn = _connect(credentials)
        try:
            status, _ = conn.select(VAULT_FOLDER)
            if status != 'OK':
                raise VaultDownloadError(
                    "No vault found on server.\n"
                    "Ask your contact to upload the vault first."
                )

            status, message_ids = conn.search(
                None,
                f'SUBJECT "{VAULT_SUBJECT}"'
            )

            if status != 'OK' or not message_ids[0]:
                raise VaultDownloadError(
                    "No vault found on server.\n"
                    "Ask your contact to upload the vault first."
                )

            ids = message_ids[0].split()
            # Use the most recent vault if multiple exist
            msg_id = ids[-1]

            status, data = conn.fetch(msg_id, '(RFC822)')
            if status != 'OK' or not data or not data[0]:
                raise VaultDownloadError(
                    "Could not download vault from server."
                )

            raw_email = data[0][1]
            if isinstance(raw_email, str):
                raw_email = raw_email.encode('utf-8')

            parsed = email.message_from_bytes(raw_email)
            body   = parsed.get_payload(decode=True)

            if body is None:
                raise VaultDownloadError(
                    "Vault message has no content."
                )

            body_str = body.decode('utf-8', errors='ignore').strip()

            if not body_str.startswith('VAULT1:'):
                raise VaultDownloadError(
                    "Server message is not a valid vault transfer."
                )

            vault_bytes = base64.b64decode(body_str[7:])

            # Vault is NOT deleted here. It is deleted only after
            # the importer has successfully decrypted and saved their
            # copy. This allows retry if the transfer phrase is wrong.
            return vault_bytes

        finally:
            try:
                conn.logout()
            except Exception:
                pass

    except (VaultDownloadError, PosteoConnectionError):
        raise
    except Exception as e:
        raise VaultDownloadError(
            f"Could not download vault: {e}"
        ) from e


def delete_transfer_vault(credentials: CredentialsData) -> None:
    """
    Delete the transfer vault from the setup folder on Posteo.

    Called after the importer has successfully decrypted and saved
    their vault copy. Safe to call even if no vault is present.

    Args:
        credentials: Posteo account credentials
    """
    try:
        conn = _connect(credentials)
        try:
            status, _ = conn.select(VAULT_FOLDER)
            if status != 'OK':
                return

            status, message_ids = conn.search(
                None,
                f'SUBJECT "{VAULT_SUBJECT}"'
            )

            if status != 'OK' or not message_ids[0]:
                return

            for msg_id in message_ids[0].split():
                conn.store(msg_id, '+FLAGS', '\\Deleted')
            conn.expunge()

        finally:
            try:
                conn.logout()
            except Exception:
                pass
    except Exception:
        pass  # Best effort -- vault will expire or be overwritten


def test_connection(credentials: CredentialsData) -> bool:
    """
    Test that the credentials work by connecting and logging out.

    Returns True if connection succeeds, False otherwise.
    Does not raise -- used for setup verification.
    """
    try:
        conn = _connect(credentials)
        conn.logout()
        return True
    except Exception:
        return False
