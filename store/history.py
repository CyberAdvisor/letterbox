# store/history.py
#
# Local message history database.
#
# Stores decrypted messages in a SQLite database encrypted at rest.
# The database is the permanent record of all correspondence.
# Once a message is decrypted and stored here, it is readable
# without the vault -- the vault is only needed for new messages.
#
# Encryption:
#   The database file is encrypted using the same key derivation
#   as the vault (PBKDF2 + XOR keystream + HMAC). The key is
#   derived with a different purpose string so it is distinct
#   from the vault key even with the same passphrase.
#
#   Encryption is applied to the entire database file. SQLite
#   operates on the plaintext in memory; the file on disk is
#   always encrypted.
#
#   On each session start:
#     1. Read encrypted database file
#     2. Decrypt to a temp file in the data directory
#     3. Open SQLite connection to the temp file
#     4. Use normally throughout the session
#     5. On close: re-encrypt temp file back to database file
#     6. Delete temp file
#
#   This approach is simple and requires no SQLite encryption
#   extensions -- just the Python stdlib sqlite3 module.
#
# Schema:
#   messages table:
#     id          INTEGER PRIMARY KEY AUTOINCREMENT
#     contact_id  TEXT NOT NULL        -- future multi-contact support
#     direction   TEXT NOT NULL        -- 'sent' or 'received'
#     sequence    INTEGER NOT NULL     -- sequence number
#     pad_id      INTEGER NOT NULL     -- pad used (for duplicate detection)
#     type        INTEGER NOT NULL     -- message type byte
#     content     TEXT NOT NULL        -- decrypted message text
#     checksum    BLOB NOT NULL        -- 8-byte checksum
#     timestamp   INTEGER NOT NULL     -- unix timestamp
#     displayed   INTEGER NOT NULL     -- 0 = unread, 1 = read
#
# The contact_id column is used for internal identification.
# Letterbox supports exactly one contact by design.
#
# ---------------------------------------------------------------------------
# Change Control
# ---------------------------------------------------------------------------
# Date        Author    Description
# ---------------------------------------------------------------------------
# 2026-05-02  M.Lines   Initial version
# ---------------------------------------------------------------------------

import os
import sqlite3
import time
from pathlib import Path

from store.vault import derive_history_key, _generate_keystream, _xor
from core.exceptions import DatabaseError, DatabaseCorruptError


# ---------------------------------------------------------------------------
# Default contact ID for v1 (single contact)
# ---------------------------------------------------------------------------

DEFAULT_CONTACT_ID = '001'


# ---------------------------------------------------------------------------
# Database encryption / decryption
# ---------------------------------------------------------------------------

def _encrypt_db_file(
    plaintext_path: Path,
    encrypted_path: Path,
    key:            bytes,
) -> None:
    """
    Encrypt a plaintext database file and write the result.
    Used when closing the database at end of session.

    Args:
        plaintext_path: path to the unencrypted SQLite file
        encrypted_path: destination path for the encrypted file
        key:            32-byte derived key
    """
    data      = plaintext_path.read_bytes()
    keystream = _generate_keystream(key, len(data))
    encrypted = _xor(data, keystream)

    tmp_path = encrypted_path.with_suffix('.tmp')
    try:
        tmp_path.write_bytes(encrypted)
        tmp_path.rename(encrypted_path)
    except Exception:
        if tmp_path.exists():
            tmp_path.unlink()
        raise


def _decrypt_db_file(
    encrypted_path: Path,
    plaintext_path: Path,
    key:            bytes,
) -> None:
    """
    Decrypt an encrypted database file and write the result.
    Used when opening the database at start of session.

    Args:
        encrypted_path: path to the encrypted database file
        plaintext_path: destination path for the decrypted file
        key:            32-byte derived key
    """
    data      = encrypted_path.read_bytes()
    keystream = _generate_keystream(key, len(data))
    plaintext = _xor(data, keystream)
    plaintext_path.write_bytes(plaintext)


# ---------------------------------------------------------------------------
# MessageHistory
# ---------------------------------------------------------------------------

class MessageHistory:
    """
    Manages the local message history database.

    Usage:
        history = MessageHistory(data_dir, passphrase, salt)
        history.open()
        # ... use history ...
        history.close()

    Or use as a context manager:
        with MessageHistory(data_dir, passphrase, salt) as history:
            # ... use history ...

    The database file on disk is always encrypted. A temporary
    plaintext file is used during the session and deleted on close.
    """

    # File names within the data directory
    DB_FILE   = 'history.db'       # encrypted database on disk
    TEMP_FILE = 'history.tmp.db'   # plaintext database in memory session

    def __init__(
        self,
        data_dir:   Path,
        passphrase: str,
        salt:       bytes,
    ):
        self._data_dir      = data_dir
        self._passphrase    = passphrase
        self._salt          = salt
        self._key           = derive_history_key(passphrase, salt)
        self._db_path       = data_dir / self.DB_FILE
        self._temp_path     = data_dir / self.TEMP_FILE
        self._conn          = None

    # -----------------------------------------------------------------------
    # Open / close
    # -----------------------------------------------------------------------

    def open(self) -> None:
        """
        Decrypt the database file (if it exists) and open
        a SQLite connection to the plaintext temp file.

        If no database file exists yet (first run), creates a
        new empty database.

        Raises:
            DatabaseError if the file cannot be opened.
        """
        try:
            if self._db_path.exists():
                # Decrypt existing database to temp file
                _decrypt_db_file(
                    self._db_path,
                    self._temp_path,
                    self._key,
                )
            # else: new database -- SQLite will create temp file

            self._conn = sqlite3.connect(str(self._temp_path))
            self._conn.row_factory = sqlite3.Row

            # Enable WAL mode for safer writes
            self._conn.execute('PRAGMA journal_mode=WAL')

            # Create schema if not present
            self._create_schema()

            # Verify integrity on open
            self._check_integrity()

        except sqlite3.Error as e:
            raise DatabaseError(
                f"Could not open message history: {e}"
            ) from e

    def close(self) -> None:
        """
        Close the SQLite connection, re-encrypt the database,
        and delete the plaintext temp file.

        Always call this when done -- the temp file contains
        unencrypted messages and must not be left on disk.
        """
        if self._conn is None:
            return

        try:
            self._conn.commit()
            self._conn.close()
            self._conn = None

            # Re-encrypt temp file back to database file
            if self._temp_path.exists():
                _encrypt_db_file(
                    self._temp_path,
                    self._db_path,
                    self._key,
                )
        finally:
            # Always delete temp file even if encryption fails
            if self._temp_path.exists():
                self._temp_path.unlink()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False   # do not suppress exceptions

    # -----------------------------------------------------------------------
    # Schema
    # -----------------------------------------------------------------------

    def _create_schema(self) -> None:
        """Create tables if they do not exist."""
        self._conn.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_id  TEXT    NOT NULL,
                direction   TEXT    NOT NULL,
                sequence    INTEGER NOT NULL,
                pad_id      INTEGER NOT NULL,
                type        INTEGER NOT NULL,
                content     TEXT    NOT NULL,
                checksum    BLOB    NOT NULL,
                timestamp   INTEGER NOT NULL,
                displayed   INTEGER NOT NULL DEFAULT 0
            )
        ''')

        # Index on sequence for fast gap detection lookups
        self._conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_sequence
            ON messages (contact_id, direction, sequence)
        ''')

        # Index on pad_id for duplicate detection
        self._conn.execute('''
            CREATE INDEX IF NOT EXISTS idx_pad_id
            ON messages (pad_id)
        ''')

        self._conn.commit()

    def _check_integrity(self) -> None:
        """
        Run SQLite integrity check.
        Raises DatabaseCorruptError if the database is damaged.
        """
        result = self._conn.execute(
            'PRAGMA integrity_check'
        ).fetchone()

        if result[0] != 'ok':
            raise DatabaseCorruptError(
                f"Message history database failed integrity check: "
                f"{result[0]}\n"
                "The database may be corrupt. "
                "Message history may need to be reset."
            )

    # -----------------------------------------------------------------------
    # Save messages
    # -----------------------------------------------------------------------

    def save_received(
        self,
        sequence:   int,
        pad_id:     int,
        msg_type:   int,
        content:    str,
        checksum:   bytes,
        contact_id: str = DEFAULT_CONTACT_ID,
    ) -> int:
        """
        Save a received and decrypted message to history.

        Called after successful decryption and pad confirmation.

        Args:
            sequence:   message sequence number
            pad_id:     pad used to decrypt (stored for duplicate detection)
            msg_type:   message type byte
            content:    decrypted message text
            checksum:   8-byte checksum from payload
            contact_id: contact identifier (default '001' for v1)

        Returns:
            database row id of the inserted record

        Raises:
            DatabaseError if the insert fails
        """
        try:
            cursor = self._conn.execute(
                '''INSERT INTO messages
                   (contact_id, direction, sequence, pad_id,
                    type, content, checksum, timestamp, displayed)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (
                    contact_id,
                    'received',
                    sequence,
                    pad_id,
                    msg_type,
                    content,
                    checksum,
                    int(time.time()),
                    0,   # unread
                )
            )
            self._conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            raise DatabaseError(
                f"Could not save received message: {e}"
            ) from e

    def save_sent(
        self,
        sequence:   int,
        pad_id:     int,
        msg_type:   int,
        content:    str,
        checksum:   bytes,
        contact_id: str = DEFAULT_CONTACT_ID,
    ) -> int:
        """
        Save a sent message to history.

        Called after successful transmission.

        Returns database row id of the inserted record.
        """
        try:
            cursor = self._conn.execute(
                '''INSERT INTO messages
                   (contact_id, direction, sequence, pad_id,
                    type, content, checksum, timestamp, displayed)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (
                    contact_id,
                    'sent',
                    sequence,
                    pad_id,
                    msg_type,
                    content,
                    checksum,
                    int(time.time()),
                    1,   # sent messages are always 'displayed'
                )
            )
            self._conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            raise DatabaseError(
                f"Could not save sent message: {e}"
            ) from e

    # -----------------------------------------------------------------------
    # Retrieve messages
    # -----------------------------------------------------------------------

    def get_conversation(
        self,
        contact_id: str = DEFAULT_CONTACT_ID,
        limit:      int = 50,
    ) -> list:
        """
        Return the most recent messages in conversation order.

        Returns both sent and received messages, ordered by
        sequence number with sent messages interspersed by timestamp.

        Args:
            contact_id: contact to retrieve for
            limit:      maximum number of messages to return

        Returns:
            list of dicts with keys:
                direction, sequence, content, timestamp, displayed, type
        """
        try:
            rows = self._conn.execute(
                '''SELECT direction, sequence, content,
                          timestamp, displayed, type
                   FROM messages
                   WHERE contact_id = ?
                   ORDER BY timestamp ASC, id ASC
                   LIMIT ?''',
                (contact_id, limit)
            ).fetchall()

            return [dict(row) for row in rows]

        except sqlite3.Error as e:
            raise DatabaseError(
                f"Could not retrieve conversation: {e}"
            ) from e

    def get_by_pad_id(self, pad_id: int) -> dict:
        """
        Look up a received message by its pad_id.

        Used by core.pad.lookup_receive_pad to detect duplicate
        delivery -- if a pad_id is already used AND appears in
        history, it is a duplicate.

        Args:
            pad_id: the pad ID from the received message header

        Returns:
            dict with message data, or None if not found
        """
        try:
            row = self._conn.execute(
                '''SELECT sequence, checksum, content
                   FROM messages
                   WHERE pad_id = ? AND direction = 'received'
                   LIMIT 1''',
                (pad_id,)
            ).fetchone()

            return dict(row) if row else None

        except sqlite3.Error as e:
            raise DatabaseError(
                f"Could not look up message by pad_id: {e}"
            ) from e

    def get_unread_count(
        self,
        contact_id: str = DEFAULT_CONTACT_ID,
    ) -> int:
        """
        Return the count of unread received messages.
        """
        try:
            row = self._conn.execute(
                '''SELECT COUNT(*) FROM messages
                   WHERE contact_id = ?
                   AND direction = 'received'
                   AND displayed = 0''',
                (contact_id,)
            ).fetchone()
            return row[0]
        except sqlite3.Error as e:
            raise DatabaseError(
                f"Could not count unread messages: {e}"
            ) from e

    def mark_all_displayed(
        self,
        contact_id: str = DEFAULT_CONTACT_ID,
    ) -> None:
        """
        Mark all received messages as displayed (read).
        Called when the user views the conversation.
        """
        try:
            self._conn.execute(
                '''UPDATE messages
                   SET displayed = 1
                   WHERE contact_id = ?
                   AND direction = 'received'
                   AND displayed = 0''',
                (contact_id,)
            )
            self._conn.commit()
        except sqlite3.Error as e:
            raise DatabaseError(
                f"Could not mark messages as displayed: {e}"
            ) from e

    # -----------------------------------------------------------------------
    # Sequence / gap detection
    # -----------------------------------------------------------------------

    def get_highest_received_sequence(
        self,
        contact_id: str = DEFAULT_CONTACT_ID,
    ) -> int:
        """
        Return the highest received sequence number.
        Returns 0 if no messages have been received.

        Used to detect gaps -- if we receive sequence 6 and
        the highest we have is 4, sequence 5 is missing.
        """
        try:
            row = self._conn.execute(
                '''SELECT MAX(sequence) FROM messages
                   WHERE contact_id = ?
                   AND direction = 'received' ''',
                (contact_id,)
            ).fetchone()
            return row[0] or 0
        except sqlite3.Error as e:
            raise DatabaseError(
                f"Could not get highest sequence: {e}"
            ) from e

    def get_received_sequences(
        self,
        contact_id: str = DEFAULT_CONTACT_ID,
    ) -> set:
        """
        Return a set of all received sequence numbers.
        Used to identify gaps in the sequence.
        """
        try:
            rows = self._conn.execute(
                '''SELECT sequence FROM messages
                   WHERE contact_id = ?
                   AND direction = 'received' ''',
                (contact_id,)
            ).fetchall()
            return {row[0] for row in rows}
        except sqlite3.Error as e:
            raise DatabaseError(
                f"Could not get received sequences: {e}"
            ) from e

    def get_next_send_sequence(
        self,
        contact_id: str = DEFAULT_CONTACT_ID,
    ) -> int:
        """
        Return the next sequence number to use for sending.
        Sequence numbers start at 1.

        Returns (highest sent sequence + 1), or 1 if nothing sent yet.
        """
        try:
            row = self._conn.execute(
                '''SELECT MAX(sequence) FROM messages
                   WHERE contact_id = ?
                   AND direction = 'sent' ''',
                (contact_id,)
            ).fetchone()
            highest = row[0] or 0
            return highest + 1
        except sqlite3.Error as e:
            raise DatabaseError(
                f"Could not get next send sequence: {e}"
            ) from e
