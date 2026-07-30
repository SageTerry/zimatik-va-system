"""Temporary storage for uploaded scan artifacts (e.g. APKs for MobSF, code
archives for SonarQube/Bandit/Safety).

Unlike Nessus/SonarQube (REST)/ZAP, which scan a remote target VACE already
knows the address of, mobile and code-analysis scans need the artifact
itself. The uploaded file (or extracted archive) is written to a scratch
directory just long enough for the relevant client to consume it, then
removed.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import List, Union

from fastapi import UploadFile

logger = logging.getLogger(__name__)

_UPLOAD_DIR = Path(tempfile.gettempdir()) / "vace-uploads"


class ZipExtractionError(Exception):
    """Raised when a code archive can't be safely or successfully extracted."""


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


def extract_zip(zip_path: Union[str, Path], extract_dir: Union[str, Path]) -> List[Path]:
    """Extract a code archive into ``extract_dir`` and return the extracted file paths.

    The archive is untrusted input (a user upload), so every member is
    checked to resolve *inside* ``extract_dir`` before being written -
    without this, a crafted entry like ``../../etc/passwd`` (a "zip slip")
    could write outside the intended directory. Directory entries and any
    member that fails this check are skipped; a member failing the check
    is logged as a warning rather than aborting the whole extraction, since
    one poisoned entry shouldn't block analysis of an otherwise-legitimate
    archive.
    """
    zip_path = Path(zip_path)
    extract_dir = Path(extract_dir)
    extract_dir.mkdir(parents=True, exist_ok=True)
    extract_dir_resolved = extract_dir.resolve()

    extracted: List[Path] = []
    try:
        with zipfile.ZipFile(zip_path) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue

                dest = (extract_dir / member.filename).resolve()
                if dest != extract_dir_resolved and extract_dir_resolved not in dest.parents:
                    logger.warning("Skipping zip member outside extract_dir: %s", member.filename)
                    continue

                dest.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, dest.open("wb") as out_file:
                    shutil.copyfileobj(source, out_file)
                extracted.append(dest)
    except zipfile.BadZipFile as exc:
        raise ZipExtractionError(f"{zip_path} is not a valid zip archive") from exc

    logger.info("Extracted %d file(s) from %s into %s", len(extracted), zip_path, extract_dir)
    return extracted


def cleanup_extracted_files(extract_dir: Union[str, Path]) -> None:
    """Best-effort recursive delete of a directory populated by ``extract_zip``.

    Safe to call more than once, or on a directory that doesn't exist.
    """
    try:
        shutil.rmtree(extract_dir)
        logger.info("Cleaned up extracted files in %s", extract_dir)
    except FileNotFoundError:
        pass
