"""Validation service for uploaded network packet capture files (.pcap and .pcapng)."""

import os
from pathlib import Path
from typing import Tuple

# Known PCAP / PCAPNG magic byte signatures
PCAP_MAGIC_MICROSECONDS_BE = b"\xa1\xb2\xc3\xd4"
PCAP_MAGIC_MICROSECONDS_LE = b"\xd4\xc3\xb2\xa1"
PCAP_MAGIC_NANOSECONDS_BE = b"\xa1\xb2\x3c\x4d"
PCAP_MAGIC_NANOSECONDS_LE = b"\x4d\x3c\xb2\xa1"
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

PCAP_MAGICS = {
    PCAP_MAGIC_MICROSECONDS_BE: "PCAP (Big-Endian)",
    PCAP_MAGIC_MICROSECONDS_LE: "PCAP (Little-Endian)",
    PCAP_MAGIC_NANOSECONDS_BE: "PCAP (Nanosecond BE)",
    PCAP_MAGIC_NANOSECONDS_LE: "PCAP (Nanosecond LE)",
}

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
DEFAULT_MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB


class CaptureValidationError(Exception):
    """Base exception for packet capture validation failures."""
    pass


class CaptureFileNotFoundError(CaptureValidationError):
    """Raised when the specified capture file does not exist."""
    pass


class EmptyCaptureFileError(CaptureValidationError):
    """Raised when the capture file contains 0 bytes."""
    pass


class CaptureFileTooLargeError(CaptureValidationError):
    """Raised when the capture file exceeds the maximum allowed size."""
    pass


class InvalidFileExtensionError(CaptureValidationError):
    """Raised when the file does not have an authorized PCAP/PCAPNG extension."""
    pass


class InvalidPcapFormatError(CaptureValidationError):
    """Raised when the file header does not match valid PCAP/PCAPNG magic bytes."""
    pass


def validate_capture_file(
    file_path: str | Path,
    max_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES
) -> Tuple[str, int]:
    """
    Validates that a file is a legitimate, non-empty PCAP or PCAPNG file.

    Parameters:
        file_path: Path to the target packet capture file.
        max_size_bytes: Maximum permitted file size in bytes (defaults to 50MB).

    Returns:
        Tuple of (detected_format: str, file_size: int), where format is 'PCAP' or 'PCAPNG'.

    Raises:
        CaptureFileNotFoundError: If the file does not exist on disk.
        EmptyCaptureFileError: If the file is 0 bytes.
        CaptureFileTooLargeError: If file exceeds max_size_bytes.
        InvalidFileExtensionError: If the file extension is not .pcap or .pcapng.
        InvalidPcapFormatError: If magic bytes do not match PCAP/PCAPNG signatures.
    """
    path = Path(file_path)

    if not path.is_file():
        raise CaptureFileNotFoundError(f"Capture file not found: {path}")

    # Validate file extension
    ext = path.suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise InvalidFileExtensionError(
            f"Invalid file extension '{ext}'. Allowed extensions are: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )

    # Validate file size
    file_size = path.stat().st_size
    if file_size == 0:
        raise EmptyCaptureFileError(f"Capture file is empty (0 bytes): {path.name}")

    if file_size > max_size_bytes:
        max_mb = max_size_bytes / (1024 * 1024)
        current_mb = file_size / (1024 * 1024)
        raise CaptureFileTooLargeError(
            f"File size ({current_mb:.2f} MB) exceeds maximum allowed limit of {max_mb:.1f} MB."
        )

    # Validate magic bytes
    with open(path, "rb") as f:
        magic = f.read(4)

    if magic == PCAPNG_MAGIC:
        return "PCAPNG", file_size
    elif magic in PCAP_MAGICS:
        return "PCAP", file_size
    else:
        hex_magic = magic.hex()
        raise InvalidPcapFormatError(
            f"Invalid capture header signature (0x{hex_magic}). File is neither a valid PCAP nor PCAPNG."
        )
