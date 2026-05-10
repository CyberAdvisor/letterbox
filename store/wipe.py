# store/wipe.py
#
# Secure data wipe for lockout and duress scenarios.
#
# ---------------------------------------------------------------------------
# Change Control
# ---------------------------------------------------------------------------
# Date        Author    Description
# ---------------------------------------------------------------------------
# 2026-05-10  M.Lines   Initial version. Multi-pass random overwrite
#                       and deletion of all Letterbox data files.
# ---------------------------------------------------------------------------

import os
from pathlib import Path

# Number of overwrite passes before deletion.
# Three passes of random data is conventional for software-level
# wiping on flash storage. Note: on NAND flash the controller may
# redirect writes to different physical blocks, so this is not a
# cryptographic guarantee of erasure -- it raises the bar for recovery.
OVERWRITE_PASSES = 3

_WIPE_TARGETS = [
    "vault.dat",
    "credentials.dat",
    "history.db",
    "config.dat",
]


def _secure_delete(path: Path) -> None:
    """
    Multi-pass random overwrite followed by deletion of a single file.

    Each pass writes os.urandom() data over the full file length,
    fsyncing between passes to encourage physical writes through
    filesystem and OS caches.

    Raises no exceptions -- wipe must always complete.
    """
    try:
        size = path.stat().st_size
        if size > 0:
            with open(path, "r+b") as f:
                for _ in range(OVERWRITE_PASSES):
                    f.seek(0)
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
        path.unlink()
    except Exception:
        # Never raise -- silently attempt unlink even if overwrite failed
        try:
            path.unlink()
        except Exception:
            pass


def wipe_all_data(data_dir: Path) -> None:
    """
    Multi-pass random overwrite and delete all Letterbox data files.

    Targets: vault.dat, credentials.dat, history.db, config.dat

    Silent -- raises no exceptions. All user-facing messaging is
    the caller's responsibility.

    After this call, config_exists() returns False and the app
    will treat the next launch as a fresh install.
    """
    for name in _WIPE_TARGETS:
        path = data_dir / name
        if path.exists():
            _secure_delete(path)
