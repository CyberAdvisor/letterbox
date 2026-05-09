# util/random.py
#
# Random byte generation for security-critical operations.
#
# This is the single point where randomness enters the system.
# All pad generation, salt generation, and bundle ID generation
# goes through here. Nothing else in the codebase calls os.urandom
# directly -- they all call these functions.
#
# Centralising randomness here makes it easy to audit: one file,
# one function, one place to verify that the correct source is used.
#
# os.urandom() is used throughout. On all supported platforms:
#   macOS:  /dev/urandom via the kernel CSPRNG
#   iOS:    SecRandomCopyBytes via the Secure Enclave
#
# Both are cryptographically secure. Neither is a PRNG.
# The random module from Python's stdlib is NOT used here --
# it is a PRNG seeded from os.urandom and is not suitable
# for cryptographic key material.
#
# ---------------------------------------------------------------------------
# Change Control
# 2026-05-09  M.Lines   v3.1.0  Complete rewrite. See README.md, CHANGELOG.md, TECHNICAL_OVERVIEW.md.
# ---------------------------------------------------------------------------
# Date        Author    Description
# ---------------------------------------------------------------------------
# 2026-05-02  M.Lines   Initial version
# 2026-05-09  M.Lines   v3.1.0: generate_subject_key added for v3
# ---------------------------------------------------------------------------

import os
import secrets

from core.constants import WORDLIST


# ---------------------------------------------------------------------------
# Core random bytes
# ---------------------------------------------------------------------------

def random_bytes(n: int) -> bytes:
    """
    Return n cryptographically random bytes.

    Uses os.urandom() which on macOS and iOS draws from the
    operating system's cryptographic random source.

    This function is the only place in the codebase where
    random bytes are generated. All other modules call this.

    Args:
        n: number of bytes to generate. Must be > 0.

    Returns:
        bytes of length n.

    Raises:
        ValueError if n <= 0.
        OSError    if the OS random source is unavailable
                   (extremely unlikely on supported platforms).
    """
    if n <= 0:
        raise ValueError(
            f"random_bytes requires n > 0, got {n}."
        )
    return os.urandom(n)


# ---------------------------------------------------------------------------
# Specific generators used by other modules
# ---------------------------------------------------------------------------

def generate_salt() -> bytes:
    """
    Generate a fresh KDF salt for PBKDF2.
    Called once during setup. Never reused.

    Returns 32 random bytes.
    """
    from core.constants import CONFIG_SALT_SIZE
    return random_bytes(CONFIG_SALT_SIZE)


def generate_bundle_id() -> int:
    """
    Generate a random bundle ID for a new vault.

    The bundle ID is a 4-byte unsigned integer stored in the
    plaintext message header to identify which vault to use
    for decryption. It is chosen randomly so that an observer
    cannot tell from the ID alone how many vaults exist or
    in what order they were created.

    Returns a nonzero integer in the range 1 to 0xFFFFFFFF.
    Zero is excluded -- a zero bundle ID in a message header
    would be indistinguishable from an uninitialised field.
    """
    while True:
        value = int.from_bytes(random_bytes(4), 'big')
        if value != 0:
            return value


def generate_subject_key() -> bytes:
    """
    Generate a random subject obfuscation key.

    Stored in the vault and shared via vault transfer.
    Used to HMAC-obfuscate sequential pad IDs in the subject line
    so observers cannot infer message count or order from metadata.

    Returns:
        bytes of length SUBJECT_KEY_SIZE
    """
    from core.constants import SUBJECT_KEY_SIZE
    return os.urandom(SUBJECT_KEY_SIZE)


def generate_transfer_passphrase() -> str:
    """
    Generate a short, spoken-word passphrase for vault transfer.

    Selects 6 words at random from WORDLIST using secrets.choice,
    which uses os.urandom internally.

    The passphrase is intended to be spoken aloud during the vault
    exchange. It is temporary -- discarded by both parties after
    the vault import is complete.

    Six words provides approximately 57 bits of entropy against
    offline cracking of the transfer vault. Four words (~38 bits)
    was insufficient for a file stored on a third-party server.

    Returns a string of 6 words separated by spaces.
    Example: 'river table moon clock safe burn'
    """
    words = [secrets.choice(WORDLIST) for _ in range(6)]
    return ' '.join(words)


def generate_pad_data(pad_count: int, pad_size: int) -> bytes:
    """
    Generate the raw random pad data for a new vault.

    This is the most important call in the entire system.
    The security of every message depends on the randomness
    of these bytes. They must be:
      - Truly random (not pseudorandom)
      - Generated fresh for each vault
      - Never reused

    Args:
        pad_count: number of pads to generate (from constants)
        pad_size:  bytes per pad (from constants)

    Returns:
        bytes of length pad_count * pad_size (~5MB for defaults)

    Note on performance:
        Generating ~5MB via os.urandom is fast (under a second on iPad).
        The caller is responsible for showing progress to the user.
        This function does not print anything -- it just generates.
    """
    total = pad_count * pad_size
    return random_bytes(total)
