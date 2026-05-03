# core/message.py
#
# Message encryption and decryption.
#
# This module handles the innermost layer of the message format:
# building the 4096-byte plaintext payload, encrypting it with
# a one-time pad, and reversing that process on receipt.
#
# The encryption itself is a single XOR operation:
#
#   encrypted = bytes(p ^ k for p, k in zip(plaintext, pad))
#
# That is the complete encryption algorithm. Everything else in
# this file is payload construction, parsing, and verification.
#
# Payload layout (4096 bytes, always):
#   [TYPE:        1 byte ]  message type (post, reply, padding)
#   [SEQUENCE:    4 bytes]  send counter for this contact, starts at 1
#   [CHECKSUM:    8 bytes]  SHA256[:8] of content bytes
#   [CONTENT_LEN: 2 bytes]  actual content length in bytes
#   [CONTENT:     variable] UTF-8 encoded message text
#   [PADDING:     random  ] random bytes to fill exactly 4096 bytes
#
# Wire format (4104 bytes, always):
#   [BUNDLE_ID:   4 bytes]  plaintext -- identifies vault
#   [PAD_ID:      4 bytes]  plaintext -- identifies pad within vault
#   [PAYLOAD:  4096 bytes]  XOR-encrypted payload
#
# Security notes:
#
#   The padding inside the payload is always random bytes (from
#   os.urandom). Never zeros, never a fixed pattern. This prevents
#   an attacker who knows the payload structure from recovering
#   pad bytes by XORing against known plaintext at the end of
#   the message.
#
#   The checksum (SHA256[:8]) detects tampering. An attacker who
#   flips bits in the ciphertext in transit will corrupt the
#   checksum and the recipient will know the message was damaged.
#   8 bytes (64 bits) of checksum is sufficient to detect
#   accidental corruption and simple targeted attacks.
#
# ---------------------------------------------------------------------------
# Change Control
# ---------------------------------------------------------------------------
# Date        Author    Description
# ---------------------------------------------------------------------------
# 2026-05-02  M.Lines   Initial version
# ---------------------------------------------------------------------------

import hashlib
import struct

from core.constants import (
    PAD_SIZE,
    HEADER_SIZE,
    BUNDLE_ID_BYTES,
    PAD_ID_BYTES,
    TRANSMISSION_SIZE,
    PAYLOAD_HEADER_SIZE,
    PAYLOAD_TYPE_OFFSET,
    PAYLOAD_SEQUENCE_OFFSET,
    PAYLOAD_CHECKSUM_OFFSET,
    PAYLOAD_CONTENT_LEN_OFFSET,
    PAYLOAD_CONTENT_OFFSET,
    MAX_CONTENT_BYTES,
    TYPE_POST,
    TYPE_REPLY,
    TYPE_PADDING,
    KNOWN_TYPES,
)
from core.exceptions import (
    ContentTooLongError,
    TransmissionSizeError,
    ChecksumError,
    PayloadCorruptError,
    UnknownMessageTypeError,
)
from util.random import random_bytes


# ---------------------------------------------------------------------------
# Checksum
# ---------------------------------------------------------------------------

def _compute_checksum(content_bytes: bytes) -> bytes:
    """
    Compute the 8-byte checksum of message content.
    Uses the first 8 bytes of SHA256.

    Args:
        content_bytes: UTF-8 encoded message content

    Returns:
        8 bytes
    """
    return hashlib.sha256(content_bytes).digest()[:8]


# ---------------------------------------------------------------------------
# Build plaintext payload
# ---------------------------------------------------------------------------

def _build_payload(
    content:      str,
    sequence:     int,
    message_type: int,
) -> bytes:
    """
    Build the 4096-byte plaintext payload.

    The payload is always exactly PAD_SIZE bytes. Unused space
    after the content is filled with random bytes.

    Args:
        content:      message text (will be UTF-8 encoded)
        sequence:     send sequence number for this contact
        message_type: TYPE_POST, TYPE_REPLY, or TYPE_PADDING

    Returns:
        bytes of length PAD_SIZE

    Raises:
        ContentTooLongError if content exceeds MAX_CONTENT_BYTES
        ValueError          if sequence or message_type are invalid
    """
    if sequence < 1:
        raise ValueError(
            f"Sequence must be >= 1, got {sequence}."
        )

    if message_type not in KNOWN_TYPES:
        raise ValueError(
            f"Unknown message type {message_type:#04x}."
        )

    content_bytes = content.encode('utf-8')

    if len(content_bytes) > MAX_CONTENT_BYTES:
        raise ContentTooLongError(
            f"Message is {len(content_bytes)} bytes after encoding, "
            f"maximum is {MAX_CONTENT_BYTES} bytes "
            f"(approximately 680 words).\n"
            "Split the message into multiple shorter messages."
        )

    checksum    = _compute_checksum(content_bytes)
    content_len = len(content_bytes)

    # Build the fixed header portion
    header = (
        bytes([message_type])
        + struct.pack('>I', sequence)
        + checksum
        + struct.pack('>H', content_len)
    )

    assert len(header) == PAYLOAD_HEADER_SIZE  # 15 bytes

    # Pad with random bytes to reach exactly PAD_SIZE.
    # At maximum content length padding_size is zero -- that is
    # correct and valid. random_bytes is not called in that case.
    padding_size = PAD_SIZE - PAYLOAD_HEADER_SIZE - content_len
    padding      = random_bytes(padding_size) if padding_size > 0 else b''

    payload = header + content_bytes + padding

    assert len(payload) == PAD_SIZE, (
        f"Payload size mismatch: {len(payload)} != {PAD_SIZE}"
    )

    return payload


# ---------------------------------------------------------------------------
# Encrypt
# ---------------------------------------------------------------------------

def encrypt_message(
    content:      str,
    sequence:     int,
    pad_id:       int,
    pad_bytes:    bytes,
    bundle_id:    int,
    message_type: int = TYPE_POST,
) -> bytes:
    """
    Encrypt a message and return the complete transmission.

    This is the primary entry point for sending a message.
    The pad must already be reserved and marked used by the
    caller (via core.pad.reserve_send_pad) before calling this.

    The encryption is XOR: each byte of the plaintext payload
    is XORed with the corresponding byte of the pad. This is
    the one-time pad operation. The result is information-
    theoretically secure given a truly random pad used once.

    Args:
        content:      message text
        sequence:     send sequence number (from contact state)
        pad_id:       pad index in vault (from reserve_send_pad)
        pad_bytes:    PAD_SIZE bytes of pad material
        bundle_id:    vault identifier (from vault.bundle_id)
        message_type: TYPE_POST or TYPE_REPLY

    Returns:
        bytes of length TRANSMISSION_SIZE (4104 bytes)

    Raises:
        ContentTooLongError if content is too long
        ValueError          if pad_bytes is wrong length
    """
    if len(pad_bytes) != PAD_SIZE:
        raise ValueError(
            f"pad_bytes must be {PAD_SIZE} bytes, got {len(pad_bytes)}."
        )

    # Build plaintext payload
    payload = _build_payload(content, sequence, message_type)

    # XOR with pad -- the encryption step
    # This single line is the complete one-time pad operation
    encrypted = bytes(p ^ k for p, k in zip(payload, pad_bytes))

    # Prepend plaintext header
    header = (
        bundle_id.to_bytes(BUNDLE_ID_BYTES, 'big')
        + pad_id.to_bytes(PAD_ID_BYTES, 'big')
    )

    transmission = header + encrypted

    assert len(transmission) == TRANSMISSION_SIZE, (
        f"Transmission size mismatch: "
        f"{len(transmission)} != {TRANSMISSION_SIZE}"
    )

    return transmission


# ---------------------------------------------------------------------------
# Decrypt
# ---------------------------------------------------------------------------

def decrypt_message(
    transmission: bytes,
    pad_bytes:    bytes,
) -> dict:
    """
    Decrypt a received transmission and return the message contents.

    The caller is responsible for:
        1. Extracting bundle_id and pad_id from the header
        2. Looking up the correct pad via core.pad.lookup_receive_pad
        3. Passing those pad bytes here
        4. Calling core.pad.confirm_pad_used after this succeeds

    Args:
        transmission: complete received bytes, TRANSMISSION_SIZE long
        pad_bytes:    PAD_SIZE bytes of pad material from the vault

    Returns:
        dict with keys:
            'type':     int message type
            'sequence': int sequence number
            'content':  str message text
            'checksum': bytes 8-byte checksum (for duplicate detection)

    Raises:
        TransmissionSizeError  if transmission is wrong length
        ChecksumError          if content checksum does not match
        PayloadCorruptError    if payload cannot be parsed
        UnknownMessageTypeError if message type is not recognised
    """
    if len(transmission) != TRANSMISSION_SIZE:
        raise TransmissionSizeError(
            f"Transmission is {len(transmission)} bytes, "
            f"expected {TRANSMISSION_SIZE}."
        )

    if len(pad_bytes) != PAD_SIZE:
        raise PayloadCorruptError(
            f"Pad is {len(pad_bytes)} bytes, expected {PAD_SIZE}."
        )

    # Extract encrypted payload (skip 8-byte plaintext header)
    encrypted = transmission[HEADER_SIZE:]

    # XOR to decrypt -- same operation as encryption
    payload = bytes(e ^ k for e, k in zip(encrypted, pad_bytes))

    # Parse payload fields
    message_type = payload[PAYLOAD_TYPE_OFFSET]

    if message_type not in KNOWN_TYPES:
        raise UnknownMessageTypeError(
            f"Unknown message type {message_type:#04x}.\n"
            "This message may have been sent by a newer version "
            "of Letterbox."
        )

    sequence = struct.unpack_from(
        '>I', payload, PAYLOAD_SEQUENCE_OFFSET
    )[0]

    if sequence < 1:
        raise PayloadCorruptError(
            f"Invalid sequence number {sequence}. "
            "Sequence numbers start at 1."
        )

    stored_checksum = payload[
        PAYLOAD_CHECKSUM_OFFSET : PAYLOAD_CHECKSUM_OFFSET + 8
    ]

    content_len = struct.unpack_from(
        '>H', payload, PAYLOAD_CONTENT_LEN_OFFSET
    )[0]

    if content_len > MAX_CONTENT_BYTES:
        raise PayloadCorruptError(
            f"Content length field claims {content_len} bytes, "
            f"maximum is {MAX_CONTENT_BYTES}.\n"
            "The payload is corrupt."
        )

    content_bytes = payload[
        PAYLOAD_CONTENT_OFFSET : PAYLOAD_CONTENT_OFFSET + content_len
    ]

    if len(content_bytes) != content_len:
        raise PayloadCorruptError(
            f"Expected {content_len} content bytes, "
            f"got {len(content_bytes)}.\n"
            "The payload is truncated or corrupt."
        )

    # Verify checksum
    computed_checksum = _compute_checksum(content_bytes)
    if stored_checksum != computed_checksum:
        raise ChecksumError(
            "Message content does not match its checksum.\n"
            "The message may have been tampered with or "
            "corrupted in transit.\n"
            "Message discarded."
        )

    # Decode content
    try:
        content = content_bytes.decode('utf-8')
    except UnicodeDecodeError as e:
        raise PayloadCorruptError(
            f"Message content is not valid UTF-8: {e}\n"
            "The payload is corrupt."
        ) from e

    return {
        'type':     message_type,
        'sequence': sequence,
        'content':  content,
        'checksum': stored_checksum,
    }


# ---------------------------------------------------------------------------
# Header parsing (used by transport layer)
# ---------------------------------------------------------------------------

def parse_header(transmission: bytes) -> tuple:
    """
    Extract bundle_id and pad_id from a transmission header.

    Called by the transport layer before decryption to identify
    which vault and pad to use.

    Args:
        transmission: complete received bytes

    Returns:
        (bundle_id, pad_id) as integers

    Raises:
        TransmissionSizeError if transmission is too short
    """
    if len(transmission) < HEADER_SIZE:
        raise TransmissionSizeError(
            f"Transmission is {len(transmission)} bytes, "
            f"minimum header size is {HEADER_SIZE}."
        )

    bundle_id = int.from_bytes(
        transmission[:BUNDLE_ID_BYTES], 'big'
    )
    pad_id = int.from_bytes(
        transmission[BUNDLE_ID_BYTES:HEADER_SIZE], 'big'
    )

    return bundle_id, pad_id
