# core/exceptions.py
#
# All application exceptions in one place.
#
# Exceptions are organised by category. Each category maps to a
# specific part of the system. When catching exceptions, catch the
# most specific type possible -- never catch the base LetterboxError
# unless you genuinely mean to handle all errors the same way.
#
# ---------------------------------------------------------------------------
# Change Control
# ---------------------------------------------------------------------------
# Date        Author    Description
# ---------------------------------------------------------------------------
# 2026-05-02  M.Lines   Initial version
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class LetterboxError(Exception):
    """
    Base class for all Letterbox exceptions.
    Never raised directly -- always a subclass.
    """


# ---------------------------------------------------------------------------
# Passphrase errors
# ---------------------------------------------------------------------------

class PassphraseError(LetterboxError):
    """Base for passphrase-related errors."""

class WrongPassphraseError(PassphraseError):
    """
    Raised when a passphrase fails to decrypt a vault.
    The magic bytes in the decrypted block did not match.
    This means the passphrase was wrong, not that the file
    is corrupt -- those are distinguished by checking magic
    before checksum.
    """

class PassphraseMismatchError(PassphraseError):
    """
    Raised during setup when the two passphrase entries
    do not match. The user must try again.
    """

class TooManyAttemptsError(PassphraseError):
    """
    Raised after MAX_PASSPHRASE_ATTEMPTS consecutive wrong
    passphrases in a single session. The app should exit.
    """


# ---------------------------------------------------------------------------
# Vault errors
# ---------------------------------------------------------------------------

class VaultError(LetterboxError):
    """Base for vault-related errors."""

class VaultNotFoundError(VaultError):
    """
    Raised when a vault file does not exist at the
    expected path. Likely a new device or missing import.
    """

class VaultCorruptError(VaultError):
    """
    Raised when a vault file passes the magic check
    (correct passphrase) but fails the SHA256 checksum
    of the pad data. The file has been damaged.
    Distinct from WrongPassphraseError.
    """

class VaultVersionError(VaultError):
    """
    Raised when a vault file reports a version number
    this client does not understand. The user needs
    to update Letterbox.
    """

class VaultRollbackError(VaultError):
    """
    Raised when the vault sequence counter on disk is
    lower than the last known value stored in config.
    This indicates the vault was restored from a backup,
    which risks pad reuse. Sending is blocked until resolved.
    This is the most serious vault error.

    TODO: This exception is defined but not yet raised.
    The check belongs in main._login(), comparing the vault
    internal sequence against get_vault_sequence(config_path)
    after a successful load_vault() call. The infrastructure
    in store/config.py is complete -- only the enforcement
    call in _login() is missing.
    """

class VaultPersistError(VaultError):
    """
    Raised when the vault index cannot be saved to disk
    after marking a pad as used. The pad is marked used
    in memory but not persisted. Sending is blocked until
    the vault can be saved successfully.
    """

class VaultSizeError(VaultError):
    """
    Raised when a vault file is the wrong size.
    Indicates truncation or corruption during transfer.
    """


# ---------------------------------------------------------------------------
# Pad errors
# ---------------------------------------------------------------------------

class PadError(LetterboxError):
    """Base for pad lifecycle errors."""

class PadExhaustedError(PadError):
    """
    Raised when all assigned send pads have been used.
    A new vault exchange is required before sending
    more messages. Receiving is still possible.
    """

class PadAlreadyUsedError(PadError):
    """
    Raised when a received message references a pad that
    is already marked as used in the vault index.
    May indicate duplicate delivery or a replay attempt.
    The sequence number and checksum must be compared
    against message history to distinguish the two cases.
    """

class PadReplayError(PadError):
    """
    Raised when a received message references a pad that
    is already used AND the sequence number or checksum
    does not match the previously received message.
    This is a serious condition -- possible replay attack
    or vault corruption. The message is rejected.
    """

class UnknownBundleError(PadError):
    """
    Raised when a received transmission contains a bundle
    ID that does not match any known vault. The message
    cannot be decrypted.
    """


# ---------------------------------------------------------------------------
# Message errors
# ---------------------------------------------------------------------------

class MessageError(LetterboxError):
    """Base for message encoding/decoding errors."""

class TransmissionSizeError(MessageError):
    """
    Raised when a received transmission is not exactly
    TRANSMISSION_SIZE bytes. The message is discarded.
    """

class ChecksumError(MessageError):
    """
    Raised when the checksum inside a decrypted payload
    does not match the content. The message may have been
    tampered with in transit or corrupted. Discarded.
    """

class ContentTooLongError(MessageError):
    """
    Raised when the user tries to send a message whose
    UTF-8 encoding exceeds MAX_CONTENT_BYTES. The user
    should split the message into multiple messages.
    """

class UnknownMessageTypeError(MessageError):
    """
    Raised when a decrypted payload contains a message
    type byte that is not in KNOWN_TYPES. May indicate
    a newer client version on the other end.
    """

class PayloadCorruptError(MessageError):
    """
    Raised when a decrypted payload cannot be parsed --
    for example if content_len claims more bytes than
    are available. Indicates decryption with the wrong
    pad or file corruption.
    """


# ---------------------------------------------------------------------------
# Sequence errors
# ---------------------------------------------------------------------------

class SequenceError(LetterboxError):
    """Base for message sequence errors."""

class DuplicateMessageError(SequenceError):
    """
    Raised when a received message has a sequence number
    already present in message history AND the checksum
    matches. This is a duplicate delivery -- the message
    is silently discarded and this exception is logged
    but not shown to the user.
    """

class InvalidSequenceError(SequenceError):
    """
    Raised when a received message has a sequence number
    of zero or below. Sequence numbers start at 1.
    """


# ---------------------------------------------------------------------------
# Transport errors
# ---------------------------------------------------------------------------

class TransportError(LetterboxError):
    """Base for transport errors."""

class ConnectionError(TransportError):
    """
    Raised when the IMAP connection to Posteo cannot
    be established. Check credentials and connectivity.
    """

class SendError(TransportError):
    """
    Raised when a message cannot be posted to the
    shared Posteo folder. The pad has already been
    marked as used before this point -- the message
    is saved to the outbox for manual retry.
    The retry will use a new pad.
    """

class ReceiveError(TransportError):
    """
    Raised when messages cannot be collected from
    the shared Posteo folder.
    """

class VaultUploadError(TransportError):
    """
    Raised when the transfer vault cannot be uploaded
    to Posteo during the setup exchange.
    """

class VaultDownloadError(TransportError):
    """
    Raised when the transfer vault cannot be downloaded
    from Posteo during the setup exchange.
    """


# ---------------------------------------------------------------------------
# Storage errors
# ---------------------------------------------------------------------------

class StorageError(LetterboxError):
    """Base for local storage errors."""

class DatabaseError(StorageError):
    """
    Raised when the SQLite history database cannot
    be read or written. May indicate corruption or
    a full disk.
    """

class DatabaseCorruptError(StorageError):
    """
    Raised when the SQLite integrity check fails.
    The database may need to be rebuilt from scratch.
    Message history would be lost.
    """

class CredentialsError(StorageError):
    """
    Raised when the credentials file cannot be read,
    decrypted, or parsed. Posteo credentials are
    unavailable -- transport operations will fail.
    """


# ---------------------------------------------------------------------------
# Setup errors
# 2026-05-03  M.Lines   v1.1.5: Add TODO comment to VaultRollbackError (not yet raised)
# ---------------------------------------------------------------------------

class SetupError(LetterboxError):
    """Base for first-run setup errors."""

class AlreadySetupError(SetupError):
    """
    Raised when setup is attempted but a config file
    already exists. Setup should not run twice.
    """

class SetupIncompleteError(SetupError):
    """
    Raised when the app starts and finds a config file
    but missing vault or credentials -- setup was
    started but not completed. The user must reset
    and set up again.
    """
