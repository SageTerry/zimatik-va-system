"""Temporary storage for uploaded scan artifacts (e.g. APKs for MobSF).

Unlike Nessus/SonarQube/ZAP, which scan a remote target VACE already knows
the address of, a mobile scan needs the binary itself. The uploaded file is
written to a scratch directory just long enough for ``MobSFClient`` to hand
it off to the MobSF daemon, then removed.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import uuid
from pathlib import Path

from fastapi import UploadFile

logger = logging.getLogger(__name__)

_UPLOAD_DIR = Path(tempfile.gettempdir()) / "vace-uploads"


def save_uploaded_file(upload_file: UploadFile) -> Path:
    """Stream ``upload_file`` to a uniquely-named path under the scratch upload dir.

    Returns the path it was written to. The original filename is preserved
    as a suffix only for readability in logs/debugging; uniqueness comes
    from the UUID prefix, so concurrent uploads never collide.
    """
    _UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    original_name = upload_file.filename or "upload"
    dest = _UPLOAD_DIR / f"{uuid.uuid4()}-{original_name}"

    with dest.open("wb") as out_file:
        shutil.copyfileobj(upload_file.file, out_file)

    logger.info("Saved uploaded file %s to %s", original_name, dest)
    return dest


def cleanup_temp_file(path: str | Path) -> None:
    """Best-effort delete of a temp file saved by ``save_uploaded_file``.

    Safe to call more than once (e.g. once right after upload, and again
    from a ``finally`` safety net) - a missing file is not an error.
    """
    try:
        Path(path).unlink()
        logger.info("Cleaned up temp file %s", path)
    except FileNotFoundError:
        pass
