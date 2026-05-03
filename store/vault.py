# store/vault.py
#
# Vault file read, write, and pad lifecycle management.
#
# The vault is the most security-critical file in the system.
# It contains the one-time pad data that protects all messages.
# Every function in this file has been written with that in mind.
#
# Responsibilities:
#   - Generate new vault pad data
#   - Encrypt vault to disk using a derived key
#   - Decrypt vault from disk, verifying passphrase and integrity
#   - Track which pads have been used (the index)
#   - Select unused pads for sending
#   - Mark pads as used
#
# Security-critical design decisions:
#
#   1. Pad is marked used BEFORE encryption, never after.
#      If the app crashes between marking and sending, the pad
#      is wasted. This is correct. Reusing a pad is catastrophic.
#      Wasting one is merely unfortunate.
#
#   2. Two checks on load: magic bytes then checksum.
#      Magic bytes confirm the passphrase is correct.
#      Checksum confirms the pad data is intact.
#      These are different failure modes with different messages.
#
#   3. Vault is written atomically via temp file + rename.
#      A crash during write cannot produce a half-written vault.
#
#   4. The vault index (used/unused bitmap) is stored inside
#      the encrypted block. It cannot be tampered with by an
#      attacker who does not have the passphrase.
#
# Encryption:
#   Key derivation: PBKDF2-HMAC-SHA256 (200,000 iterations)
#   Encryption:     XOR with a SHA256-based keystream
#   Authentication: HMAC-SHA256 of the ciphertext
#
#   The encryption is not AES -- it is a simple XOR keystream
#   derived from the key. This is intentional: it uses only
#   Python stdlib (hashlib, hmac), has no external dependencies,
#   and is simple enough to audit completely in minutes.
#   The security comes from the key derivation, not the cipher.
#
# ---------------------------------------------------------------------------
# Change Control
# ---------------------------------------------------------------------------
# Date        Author    Description
# ---------------------------------------------------------------------------
# 2026-05-02  M.Lines   Initial version
# 2026-05-03  M.Lines   v1.1.0: VaultData.ephemeral flag added
# 2026-05-03  M.Lines   v1.1.0: VaultData.pads changed from bytes to bytearray
# 2026-05-03  M.Lines   v1.1.0: VaultData.erase_pad() method added
# 2026-05-03  M.Lines   v1.1.0: generate_vault(ephemeral=False) parameter added
# 2026-05-03  M.Lines   v1.1.0: _build_plaintext writes FLAGS field to header
# 2026-05-03  M.Lines   v1.1.0: load_vault reads FLAGS field, accepts v1 vaults
# 2026-05-03  M.Lines   v1.1.0: reencrypt_vault preserves ephemeral flag
# 2026-05-03  M.Lines   v1.1.5: Remove duplicate PAD_ASSIGN_SIZE import
# 2026-05-03  M.Lines   v1.1.5: Fix stale ~39MB/_build_plaintext docstring
# ---------------------------------------------------------------------------

import hashlib
import hmac
import os
import secrets
import struct
from pathlib import Path

from core.constants import (
    PAD_COUNT,
    PAD_SIZE,
    PAD_ASSIGN_SIZE,
    VAULT_MAGIC,
    VAULT_VERSION,
    VAULT_SALT_SIZE,
    VAULT_MAGIC_SIZE,
    VAULT_CHECKSUM_SIZE,
    VAULT_VERSION_SIZE,
    VAULT_COUNT_SIZE,
    VAULT_PADSIZE_SIZE,
    VAULT_BUNDLE_ID_SIZE,
    VAULT_ASSIGN_SIZE,
    VAULT_INDEX_SIZE,
    VAULT_FLAGS_SIZE,
    VAULT_FLAG_EPHEMERAL,
    VAULT_PAD_DATA_SIZE,
    VAULT_HEADER_SIZE,
    TRANSFER_MAGIC,
    KDF_ITERATIONS,
    KDF_TRANSFER_ITERATIONS,
    KDF_KEY_SIZE,
)
from core.exceptions import (
    WrongPassphraseError,
    VaultCorruptError,
    VaultVersionError,
    VaultNotFoundError,
    VaultSizeError,
    VaultPersistError,
    PadExhaustedError,
    PadAlreadyUsedError,
)
from util.random import random_bytes, generate_pad_data


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def _derive_key(passphrase: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    """
    Derive a 256-bit encryption key from a passphrase and salt
    using PBKDF2-HMAC-SHA256.

    200,000 iterations makes brute-force attacks expensive.
    The salt ensures that the same passphrase produces a different
    key for each vault -- two vaults with the same passphrase are
    not linked.

    This is the only key derivation function in the system.
    All three protected files (vault, credentials, history) use
    keys derived from the same passphrase and salt via this function,
    with different purpose strings to produce distinct keys.

    Args:
        passphrase: the user's passphrase as a plain string
        salt:       32 random bytes from the config file

    Returns:
        32 bytes (256-bit key)
    """
    return hashlib.pbkdf2_hmac(
        'sha256',
        passphrase.encode('utf-8'),
        salt,
        iterations,
        dklen=KDF_KEY_SIZE,
    )


def derive_vault_key(
    passphrase: str,
    salt:       bytes,
    is_transfer: bool = False,
) -> bytes:
    """
    Derive the key used to encrypt the vault file.
    Transfer vaults use KDF_TRANSFER_ITERATIONS (10x more)
    to make offline cracking significantly harder.
    Personal vaults use KDF_ITERATIONS.
    """
    purpose    = b'letterbox-vault-v1'
    iterations = KDF_TRANSFER_ITERATIONS if is_transfer else KDF_ITERATIONS
    return _derive_key(passphrase, salt + purpose, iterations)


def derive_credentials_key(passphrase: str, salt: bytes) -> bytes:
    """
    Derive the key used to encrypt the credentials file.
    Distinct from the vault key even with the same passphrase.
    """
    purpose = b'letterbox-credentials-v1'
    return _derive_key(passphrase, salt + purpose)


def derive_history_key(passphrase: str, salt: bytes) -> bytes:
    """
    Derive the key used to encrypt the history database.
    Distinct from the vault and credentials keys.
    """
    purpose = b'letterbox-history-v1'
    return _derive_key(passphrase, salt + purpose)


# ---------------------------------------------------------------------------
# Keystream and encryption
# ---------------------------------------------------------------------------

def _generate_keystream(key: bytes, length: int) -> bytes:
    """
    Generate a deterministic keystream of the requested length
    by repeatedly hashing the key with a counter.

    This is used to XOR-encrypt the vault plaintext.
    It is not a one-time pad -- it is a stream cipher based on
    SHA256. Its security depends entirely on the key being secret.

    The key comes from PBKDF2 with 200,000 iterations, so the
    key is hard to brute-force even if the ciphertext is known.

    Args:
        key:    32-byte derived key
        length: number of keystream bytes to produce

    Returns:
        bytes of the requested length
    """
    stream    = bytearray()
    counter   = 0
    key_bytes = key  # already bytes

    while len(stream) < length:
        block = hashlib.sha256(
            key_bytes + counter.to_bytes(8, 'big')
        ).digest()
        stream.extend(block)
        counter += 1

    return bytes(stream[:length])


def _xor(data: bytes, keystream: bytes) -> bytes:
    """
    XOR data with keystream byte by byte.
    Both must be the same length.
    Encryption and decryption are the same operation.
    """
    assert len(data) == len(keystream), (
        f"XOR length mismatch: data={len(data)}, "
        f"keystream={len(keystream)}"
    )
    return bytes(d ^ k for d, k in zip(data, keystream))


def _encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    Encrypt plaintext using XOR keystream + HMAC authentication.

    Layout of returned ciphertext:
        [HMAC:       32 bytes]  HMAC-SHA256 of the XOR ciphertext
        [CIPHERTEXT: variable]  XOR of plaintext with keystream

    The HMAC authenticates the ciphertext. On decryption, the HMAC
    is verified before any other processing. This detects both
    tampering and wrong passphrase (which produces a wrong key,
    which produces a wrong HMAC).

    However: we also check the magic bytes inside the plaintext
    after decryption as a secondary human-readable check, because
    an HMAC failure alone could mean either wrong passphrase or
    tampering, and we want to give the user the right message.
    """
    keystream  = _generate_keystream(key, len(plaintext))
    ciphertext = _xor(plaintext, keystream)
    mac        = hmac.new(key, ciphertext, 'sha256').digest()
    return mac + ciphertext


def _decrypt(ciphertext_with_mac: bytes, key: bytes) -> bytes:
    """
    Decrypt ciphertext produced by _encrypt().

    Verifies the HMAC before decrypting. A failed HMAC means
    either wrong key (wrong passphrase) or tampered data.
    We return None on HMAC failure and let the caller check
    the magic bytes to determine which case it is.

    Returns decrypted plaintext, or None if HMAC verification fails.
    """
    if len(ciphertext_with_mac) < 32:
        return None

    mac_stored  = ciphertext_with_mac[:32]
    ciphertext  = ciphertext_with_mac[32:]
    mac_computed = hmac.new(key, ciphertext, 'sha256').digest()

    # Use hmac.compare_digest to prevent timing attacks
    if not hmac.compare_digest(mac_stored, mac_computed):
        return None

    keystream = _generate_keystream(key, len(ciphertext))
    return _xor(ciphertext, keystream)


# ---------------------------------------------------------------------------
# Vault index (used/unused bitmap)
# ---------------------------------------------------------------------------

def _index_to_bytes(index: list) -> bytes:
    """
    Pack the pad index (list of booleans) into a compact bitfield.
    Each pad gets one bit. PAD_COUNT pads = PAD_COUNT bits = 1250 bytes.

    Bit 0 of byte 0 = pad 0
    Bit 1 of byte 0 = pad 1
    ...
    Bit 7 of byte 0 = pad 7
    Bit 0 of byte 1 = pad 8
    etc.
    """
    result = bytearray(VAULT_INDEX_SIZE)
    for i, used in enumerate(index):
        if used:
            result[i // 8] |= (1 << (i % 8))
    return bytes(result)


def _bytes_to_index(data: bytes) -> list:
    """
    Unpack a compact bitfield back into a list of booleans.
    Inverse of _index_to_bytes.
    """
    index = []
    for i in range(PAD_COUNT):
        used = bool(data[i // 8] & (1 << (i % 8)))
        index.append(used)
    return index


# ---------------------------------------------------------------------------
# VaultData
# ---------------------------------------------------------------------------

class VaultData:
    """
    In-memory representation of a loaded vault.

    Attributes:
        pads:       raw pad bytes, length PAD_COUNT * PAD_SIZE
        index:      list of PAD_COUNT booleans, True = used
        bundle_id:  4-byte int identifying this vault in message headers
        is_transfer: True if this is a transfer vault (TRANSFER_MAGIC)
    """

    def __init__(
        self,
        pads:        bytes,
        index:       list,
        bundle_id:   int,
        send_pads:   set,
        is_transfer: bool = False,
        ephemeral:   bool = False,
    ):
        assert len(pads)  == PAD_COUNT * PAD_SIZE, (
            f"Pads wrong size: {len(pads)}"
        )
        assert len(index) == PAD_COUNT, (
            f"Index wrong length: {len(index)}"
        )
        assert bundle_id != 0, "Bundle ID must not be zero"
        assert len(send_pads) == PAD_ASSIGN_SIZE, (
            f"send_pads wrong size: {len(send_pads)}"
        )

        self.pads        = bytearray(pads)  # mutable so erase_pad() can zero it
        self.index       = index
        self.bundle_id   = bundle_id
        self.send_pads   = send_pads   # set of pad IDs we send with
        self.is_transfer = is_transfer
        self.ephemeral   = ephemeral   # no history, pad erased after use

    def get_pad(self, pad_id: int) -> bytes:
        """
        Return the raw bytes for a specific pad.
        Does NOT mark the pad as used -- caller must do that.

        Args:
            pad_id: integer 0 to PAD_COUNT-1

        Returns:
            PAD_SIZE bytes (a copy, not a view into the mutable buffer)
        """
        if not (0 <= pad_id < PAD_COUNT):
            raise ValueError(
                f"pad_id {pad_id} out of range 0-{PAD_COUNT - 1}."
            )
        start = pad_id * PAD_SIZE
        return bytes(self.pads[start : start + PAD_SIZE])

    def erase_pad(self, pad_id: int) -> None:
        """
        Overwrite a pad's bytes with fresh random data in-memory.

        Called after sending or receiving in ephemeral mode.
        The pad is already marked used; this ensures that even if the
        vault file is somehow read back, the original pad material is
        not recoverable from memory or the saved file.

        The vault must be saved to disk after this call so the
        randomised bytes replace the originals on disk as well.

        Args:
            pad_id: integer 0 to PAD_COUNT-1
        """
        if not (0 <= pad_id < PAD_COUNT):
            raise ValueError(
                f"pad_id {pad_id} out of range 0-{PAD_COUNT - 1}."
            )
        start = pad_id * PAD_SIZE
        self.pads[start : start + PAD_SIZE] = os.urandom(PAD_SIZE)

    def pick_unused_send_pad(self) -> int:
        """
        Randomly select an unused pad from the send range (0 to SPLIT_AT-1).

        Random selection (not sequential) prevents an observer from
        inferring message count from the pad IDs they see in headers.

        Returns the pad_id of the selected pad.

        Raises:
            PadExhaustedError if all send pads have been used.
        """
        unused = [
            i for i in self.send_pads
            if not self.index[i]
        ]

        if not unused:
            raise PadExhaustedError(
                "All send pads are used.\n"
                "A new vault exchange is required to send more messages.\n"
                "You can still receive messages with this vault."
            )

        return secrets.choice(unused)

    def mark_used(self, pad_id: int) -> None:
        """
        Mark a pad as used in the in-memory index.

        This must be called BEFORE the message is encrypted and sent.
        If the app crashes after marking but before sending, the pad
        is wasted. This is correct -- wasting a pad is safe.
        Reusing a pad is catastrophic.

        The caller must call save_vault() after this to persist
        the updated index to disk.

        Raises:
            PadAlreadyUsedError if the pad is already marked used.
        """
        if self.index[pad_id]:
            raise PadAlreadyUsedError(
                f"Pad {pad_id} is already marked as used.\n"
                "This should not happen in normal operation.\n"
                "Do not send messages until this is investigated."
            )
        self.index[pad_id] = True

    def remaining_send_pads(self) -> int:
        """Return the count of unused send pads."""
        return sum(1 for i in self.send_pads if not self.index[i])

    def remaining_receive_pads(self) -> int:
        """Return the count of unused receive pads."""
        recv_pads = set(range(PAD_COUNT)) - self.send_pads
        return sum(1 for i in recv_pads if not self.index[i])


# ---------------------------------------------------------------------------
# Build plaintext block
# ---------------------------------------------------------------------------

def _build_plaintext(
    vault:      VaultData,
    magic:      bytes,
) -> bytes:
    """
    Assemble the plaintext block that will be encrypted and written
    to disk.

    Layout:
        [MAGIC:     8 bytes]   confirms correct passphrase on load
        [CHECKSUM: 32 bytes]   SHA256 of pad data, confirms integrity
        [VERSION:   2 bytes]   vault format version
        [PAD_COUNT: 4 bytes]   number of pads
        [PAD_SIZE:  4 bytes]   bytes per pad
        [INDEX:   625 bytes]   used/unused bitmap
        [FLAGS:     2 bytes]   feature flags
        [PAD_DATA:   ~5MB]    the actual pads
    """
    checksum    = hashlib.sha256(bytes(vault.pads)).digest()
    index_bytes = _index_to_bytes(vault.index)

    # Encode send_pads assignment as sorted list of uint16 values
    sorted_sends  = sorted(vault.send_pads)
    assign_bytes  = struct.pack(
        f'>{PAD_ASSIGN_SIZE}H', *sorted_sends
    )

    flags = VAULT_FLAG_EPHEMERAL if vault.ephemeral else 0

    header = (
        magic
        + checksum
        + struct.pack('>H', VAULT_VERSION)
        + struct.pack('>I', PAD_COUNT)
        + struct.pack('>I', PAD_SIZE)
        + struct.pack('>I', vault.bundle_id)
        + assign_bytes
        + index_bytes
        + struct.pack('>H', flags)
    )

    assert len(header) == VAULT_HEADER_SIZE, (
        f"Header size mismatch: {len(header)} != {VAULT_HEADER_SIZE}"
    )

    return header + vault.pads


# ---------------------------------------------------------------------------
# Save vault
# ---------------------------------------------------------------------------

def save_vault(
    vault:      VaultData,
    path:       Path,
    passphrase: str,
    salt:       bytes,
) -> None:
    """
    Encrypt and write the vault to disk.

    Writes atomically via temp file + rename.
    A crash during write cannot produce a half-written vault file.

    The salt must be the same salt that is stored in the config file.
    It is written unencrypted at the start of the vault file so that
    the key can be re-derived on load.

    Args:
        vault:      VaultData to save
        path:       destination file path
        passphrase: user's passphrase
        salt:       32-byte salt from config

    Raises:
        VaultPersistError if the file cannot be written.
    """
    magic     = TRANSFER_MAGIC if vault.is_transfer else VAULT_MAGIC
    plaintext = _build_plaintext(vault, magic)
    key       = derive_vault_key(passphrase, salt,
                                  is_transfer=vault.is_transfer)
    encrypted = _encrypt(plaintext, key)

    # File layout: [SALT: 32 bytes][ENCRYPTED BLOCK: variable]
    file_data = salt + encrypted

    tmp_path = path.with_suffix('.tmp')
    try:
        tmp_path.write_bytes(file_data)
        tmp_path.rename(path)
    except Exception as e:
        if tmp_path.exists():
            tmp_path.unlink()
        raise VaultPersistError(
            f"Vault could not be saved: {e}\n"
            "Sending is disabled until the vault can be saved.\n"
            "Check available disk space."
        ) from e


# ---------------------------------------------------------------------------
# Load vault
# ---------------------------------------------------------------------------

def load_vault(
    path:        Path,
    passphrase:  str,
    is_transfer: bool = False,
) -> VaultData:
    """
    Read, decrypt, and verify a vault file.

    Performs two checks in order:
        1. HMAC verification  -- detects wrong passphrase or tampering
        2. Magic bytes check  -- confirms correct passphrase specifically
        3. Checksum check     -- confirms pad data integrity

    Steps 1 and 2 both catch wrong passphrases. Step 1 catches it
    first (before any decryption work). Step 2 provides a clear
    human-readable error message. Step 3 catches corruption.

    Args:
        path:        vault file path
        passphrase:  user's passphrase
        is_transfer: True if loading a transfer vault

    Returns:
        VaultData ready for use.

    Raises:
        VaultNotFoundError   if the file does not exist
        VaultSizeError       if the file is too small
        WrongPassphraseError if the passphrase is incorrect
        VaultCorruptError    if the pad data checksum fails
        VaultVersionError    if the vault format version is unknown
    """
    if not path.exists():
        raise VaultNotFoundError(
            f"Vault file not found: {path}"
        )

    file_data = path.read_bytes()

    # Minimum size check: salt + HMAC + at least the header
    min_size = VAULT_SALT_SIZE + 32 + VAULT_HEADER_SIZE
    if len(file_data) < min_size:
        raise VaultSizeError(
            f"Vault file is {len(file_data)} bytes, "
            f"minimum expected is {min_size}.\n"
            "The file is truncated or corrupt."
        )

    # Split salt from encrypted block
    salt            = file_data[:VAULT_SALT_SIZE]
    encrypted_block = file_data[VAULT_SALT_SIZE:]

    # Derive key and attempt decryption
    key       = derive_vault_key(passphrase, salt,
                                  is_transfer=is_transfer)
    plaintext = _decrypt(encrypted_block, key)

    if plaintext is None:
        # HMAC failed -- wrong passphrase or tampered file.
        # We report wrong passphrase because that is by far
        # the more common case. Tampering is addressed in
        # the threat model documentation.
        raise WrongPassphraseError(
            "Incorrect passphrase.\n"
            "The vault could not be decrypted."
        )

    # Check magic bytes to confirm correct passphrase
    # (secondary check after HMAC, provides clear error message)
    expected_magic = TRANSFER_MAGIC if is_transfer else VAULT_MAGIC
    actual_magic   = plaintext[:VAULT_MAGIC_SIZE]

    if actual_magic != expected_magic:
        raise WrongPassphraseError(
            "Incorrect passphrase.\n"
            "The vault could not be decrypted."
        )

    # Parse header fields
    offset   = VAULT_MAGIC_SIZE
    checksum = plaintext[offset : offset + VAULT_CHECKSUM_SIZE]
    offset  += VAULT_CHECKSUM_SIZE

    version  = struct.unpack_from('>H', plaintext, offset)[0]
    offset  += VAULT_VERSION_SIZE

    if version not in (1, VAULT_VERSION):
        raise VaultVersionError(
            f"Vault format version {version} is not supported.\n"
            f"This client supports versions 1 and {VAULT_VERSION}.\n"
            "Update Letterbox to open this vault."
        )

    stored_pad_count = struct.unpack_from('>I', plaintext, offset)[0]
    offset          += VAULT_COUNT_SIZE

    stored_pad_size  = struct.unpack_from('>I', plaintext, offset)[0]
    offset          += VAULT_PADSIZE_SIZE

    # Read bundle_id from header
    stored_bundle_id  = struct.unpack_from('>I', plaintext, offset)[0]
    offset           += VAULT_BUNDLE_ID_SIZE

    # Read send_pads assignment
    assign_values     = struct.unpack_from(
        f'>{PAD_ASSIGN_SIZE}H', plaintext, offset
    )
    send_pads         = set(assign_values)
    offset           += VAULT_ASSIGN_SIZE

    # Validate stored dimensions match our constants
    if stored_pad_count != PAD_COUNT or stored_pad_size != PAD_SIZE:
        raise VaultCorruptError(
            f"Vault dimensions mismatch: "
            f"stored pad_count={stored_pad_count} pad_size={stored_pad_size}, "
            f"expected pad_count={PAD_COUNT} pad_size={PAD_SIZE}.\n"
            "This vault was created with different settings."
        )

    # Parse index
    index_bytes = plaintext[offset : offset + VAULT_INDEX_SIZE]
    offset     += VAULT_INDEX_SIZE

    # Parse flags (v2+ only; v1 vaults have no flags field -- default to 0)
    vault_flags = 0
    if version >= 2:
        if offset + VAULT_FLAGS_SIZE <= len(plaintext):
            vault_flags = struct.unpack_from('>H', plaintext, offset)[0]
            offset     += VAULT_FLAGS_SIZE

    ephemeral = bool(vault_flags & VAULT_FLAG_EPHEMERAL)

    # Parse pad data
    pad_data = plaintext[offset:]

    if len(pad_data) != VAULT_PAD_DATA_SIZE:
        raise VaultCorruptError(
            f"Pad data is {len(pad_data)} bytes, "
            f"expected {VAULT_PAD_DATA_SIZE}.\n"
            "The vault file is corrupt."
        )

    # Verify pad data checksum
    computed_checksum = hashlib.sha256(pad_data).digest()
    if not hmac.compare_digest(checksum, computed_checksum):
        raise VaultCorruptError(
            "Vault integrity check failed.\n"
            "The passphrase is correct but the pad data is damaged.\n"
            "Restore from backup if available."
        )

    index = _bytes_to_index(index_bytes)

    return VaultData(
        pads        = pad_data,
        index       = index,
        bundle_id   = stored_bundle_id,
        send_pads   = send_pads,
        is_transfer = is_transfer,
        ephemeral   = ephemeral,
    )


# ---------------------------------------------------------------------------
# Generate new vault
# ---------------------------------------------------------------------------

def generate_vault(bundle_id: int, ephemeral: bool = False) -> VaultData:
    """
    Generate a brand new vault with fresh random pad data.

    This is called once during setup by the initiating party (Alice).
    It produces ~39MB of random bytes and may take 20-30 seconds
    on an iPad. The caller is responsible for showing progress.

    Args:
        bundle_id: random 4-byte int from generate_bundle_id()
        ephemeral: if True, vault operates in ephemeral mode --
                   no message history is saved, and pad bytes are
                   overwritten with random data after each use.
                   The flag is stored in the vault and applies to
                   both parties automatically after vault exchange.

    Returns:
        VaultData with all pads unused.
    """
    import random as _random
    pads     = generate_pad_data(PAD_COUNT, PAD_SIZE)
    index    = [False] * PAD_COUNT

    # Randomly assign PAD_ASSIGN_SIZE pad IDs to the initiator.
    # The remaining PAD_ASSIGN_SIZE go to the contact.
    # Random assignment means pad IDs reveal no direction metadata.
    all_ids   = list(range(PAD_COUNT))
    _random.shuffle(all_ids)
    send_pads = set(all_ids[:PAD_ASSIGN_SIZE])

    return VaultData(
        pads      = pads,
        index     = index,
        bundle_id = bundle_id,
        send_pads = send_pads,
        ephemeral = ephemeral,
    )


# ---------------------------------------------------------------------------
# Re-encrypt with new passphrase
# ---------------------------------------------------------------------------

def reencrypt_vault(
    vault:          VaultData,
    path:           Path,
    new_passphrase: str,
    salt:           bytes,
) -> None:
    """
    Re-encrypt the vault with a new passphrase.

    Used during the import flow when Bob decrypts the transfer vault
    with Alice's transfer passphrase and then re-encrypts with his
    own personal passphrase.

    The result is always a personal vault (VAULT_MAGIC), never a
    transfer vault -- regardless of what the source vault was.
    This is correct: after import the vault belongs to the user
    personally and is protected by their own passphrase.

    Args:
        vault:          the already-decrypted VaultData
        path:           destination path for re-encrypted vault
        new_passphrase: Bob's personal passphrase
        salt:           Bob's salt from his config file
    """
    # Force personal vault magic regardless of source
    vault.is_transfer = False
    # vault.ephemeral is preserved -- it was set by Alice at generate time
    # and stored in the vault flags, so Bob gets the same mode automatically.

    # Swap send_pads to the complement.
    # The transfer vault contains Alice's send_pads.
    # Bob's send_pads are the remaining pad IDs -- the complement.
    all_ids          = set(range(PAD_COUNT))
    vault.send_pads  = all_ids - vault.send_pads

    save_vault(vault, path, new_passphrase, salt)
