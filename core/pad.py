# core/pad.py
#
# Pad selection and lifecycle management for sending and receiving.
#
# This module sits between the vault (which stores pad data) and
# the message module (which encrypts content). It is responsible for:
#
#   - Selecting a pad for sending
#   - Marking pads used in the correct order
#   - Handling the receive-side pad lookup
#   - Detecting replay attacks and duplicate delivery
#
# The critical invariant this module enforces:
#
#   A pad is marked used BEFORE the message is encrypted and sent.
#   Never after. If the app crashes between marking and sending,
#   the pad is wasted. This is correct and safe.
#   Reusing a pad is catastrophic and must never happen.
#
# Pad assignment is stored in vault.send_pads (a set of pad IDs).
# The assignment is random -- no fixed range split.
# vault.send_pads contains the IDs this party sends with.
#
# ---------------------------------------------------------------------------
# Change Control
# ---------------------------------------------------------------------------
# Date        Author    Description
# ---------------------------------------------------------------------------
# 2026-05-02  M.Lines   Initial version
# 2026-05-03  M.Lines   v1.2.3: PAD_WARNING_LEVELS messages use 'stamps' not 'pads'
# 2026-05-03  M.Lines   v1.2.9: PAD_WARNING_LEVELS reversed -- most severe first
# ---------------------------------------------------------------------------

from core.constants import PAD_COUNT, PAD_SIZE
from core.exceptions import (
    PadExhaustedError,
    PadAlreadyUsedError,
    PadReplayError,
    UnknownBundleError,
)
from store.vault import VaultData


# ---------------------------------------------------------------------------
# Send-side pad operations
# ---------------------------------------------------------------------------

def reserve_send_pad(vault: VaultData) -> tuple:
    """
    Select an unused send pad and mark it used immediately.

    This is the first step of sending a message. The pad is
    marked used before any encryption or transmission occurs.
    If anything fails after this point, the pad is wasted --
    that is correct and safe.

    The caller must call save_vault() after this returns to
    persist the updated index to disk. If save_vault() fails,
    the pad is marked used in memory but not on disk. The caller
    must handle VaultPersistError and block sending until the
    vault can be saved.

    Args:
        vault: the loaded VaultData for this contact

    Returns:
        (pad_id, pad_bytes) tuple where:
            pad_id    is the integer index of the selected pad
            pad_bytes is the PAD_SIZE bytes of pad material

    Raises:
        PadExhaustedError if no send pads remain
    """
    pad_id    = vault.pick_unused_send_pad()
    pad_bytes = vault.get_pad(pad_id)

    # Mark used BEFORE returning. The caller must save the vault.
    vault.mark_used(pad_id)

    return pad_id, pad_bytes


# ---------------------------------------------------------------------------
# Receive-side pad operations
# ---------------------------------------------------------------------------

def lookup_receive_pad(
    bundle_id:       int,
    pad_id:          int,
    vault:           VaultData,
    message_history, # store.history.MessageHistory -- avoids circular import
) -> bytes:
    """
    Look up the pad for a received message and handle the
    already-used cases correctly.

    Three outcomes are possible:

    1. Pad is unused -- normal case.
       Return pad bytes. Caller will decrypt and then call
       confirm_pad_used() to mark it used.

    2. Pad is already used AND sequence+checksum match history --
       duplicate delivery (transport retried). Raise PadAlreadyUsedError
       with duplicate=True. Caller should discard silently.

    3. Pad is already used AND sequence+checksum do NOT match --
       replay attack or serious error. Raise PadReplayError.
       Caller should warn the user.

    Note: the pad is NOT marked used here. The caller marks it used
    via confirm_pad_used() only after successful decryption and
    history lookup. This keeps the sequence of operations clean:
        1. lookup_receive_pad  -- get pad bytes
        2. decrypt message     -- in core/message.py
        3. confirm_pad_used    -- mark used, save vault

    Args:
        bundle_id:       from the message plaintext header
        pad_id:          from the message plaintext header
        vault:           the VaultData for this contact
        message_history: provides get_by_pad_id() for duplicate check

    Returns:
        pad bytes (PAD_SIZE bytes) if the pad is unused.

    Raises:
        UnknownBundleError   if bundle_id does not match vault
        PadAlreadyUsedError  if duplicate delivery detected
        PadReplayError       if replay or vault corruption detected
    """
    # Confirm the bundle ID matches this vault
    if bundle_id != vault.bundle_id:
        raise UnknownBundleError(
            f"Message bundle ID {bundle_id:#010x} does not match "
            f"vault bundle ID {vault.bundle_id:#010x}.\n"
            "This message was not intended for this vault."
        )

    # Validate pad_id range
    if not (0 <= pad_id < PAD_COUNT):
        raise UnknownBundleError(
            f"Pad ID {pad_id} is out of range 0-{PAD_COUNT - 1}."
        )

    # A pad in our own send_pads set was sent by us, not our contact.
    # The transport layer filters these before downloading, but we
    # check here as a second line of defence against any that slip
    # through -- e.g. messages sent before this fix was in place.
    if pad_id in vault.send_pads:
        err = PadAlreadyUsedError(
            f"Pad {pad_id} is in our send set -- this is our own message."
        )
        err.is_duplicate = True
        raise err

    # Normal case: pad unused -- contact sent this message
    if not vault.index[pad_id]:
        return vault.get_pad(pad_id)

    # Pad already used -- check history to distinguish cases
    existing = message_history.get_by_pad_id(pad_id)

    if existing is not None:
        # Duplicate delivery -- same pad, same message
        # Raise with a flag the caller can check
        err = PadAlreadyUsedError(
            f"Pad {pad_id} already used. "
            "Duplicate delivery detected -- message discarded."
        )
        err.is_duplicate = True
        raise err

    # Pad used but not in history.
    # In ephemeral mode history is never written, so a used pad with
    # no history record is expected on duplicate delivery -- not a replay.
    if vault.ephemeral:
        err = PadAlreadyUsedError(
            f"Pad {pad_id} already used (ephemeral mode -- no history). "
            "Duplicate delivery -- message discarded."
        )
        err.is_duplicate = True
        raise err

    # Standard mode: used pad not in history is a genuine anomaly --
    # possible replay attack or vault corruption.
    err = PadReplayError(
        f"Pad {pad_id} is marked used but the message is not in history.\n"
        "This may indicate a replay attack or vault corruption.\n"
        "Message rejected."
    )
    err.is_duplicate = False
    raise err


def confirm_pad_used(
    pad_id: int,
    vault:  VaultData,
) -> None:
    """
    Mark a receive-side pad as used after successful decryption.

    Called after lookup_receive_pad() returns successfully and
    the message has been decrypted and verified. The vault must
    be saved to disk after this call.

    Args:
        pad_id: the pad ID from the received message header
        vault:  the VaultData for this contact

    Raises:
        PadAlreadyUsedError if the pad was already marked used
        (should not happen if lookup_receive_pad was called first)
    """
    vault.mark_used(pad_id)


# ---------------------------------------------------------------------------
# Pad exhaustion warning thresholds
# ---------------------------------------------------------------------------

# Warn the user when send pads drop to or below these levels.
# The UI checks remaining_send_pads() against these thresholds
# and shows appropriate warnings.
PAD_WARNING_LEVELS = [
    ( 10, "CRITICAL: Under 10 stamps remaining."),
    ( 50, "Under 50 stamps remaining. Send a message to arrange exchange."),
    (100, "Under 100 stamps remaining. Exchange a new vault urgently."),
    (200, "Under 200 stamps remaining. A new vault exchange is needed."),
    (500, "Under 500 stamps remaining. Plan a new vault exchange soon."),
]


def check_pad_warning(vault: VaultData) -> str:
    """
    Return a warning message if send pads are running low,
    or None if pads are plentiful.

    The most severe applicable warning is returned.
    Only one warning is returned per call -- the lowest threshold
    that has been crossed.

    Args:
        vault: the loaded VaultData

    Returns:
        warning string, or None if no warning needed
    """
    remaining = vault.remaining_send_pads()

    for threshold, message in PAD_WARNING_LEVELS:
        if remaining <= threshold:
            return f"{message} ({remaining} remaining)"

    return None
