"""Unit tests for capture file validator."""

import pytest
from app.services.validator import (
    CaptureFileNotFoundError,
    CaptureFileTooLargeError,
    EmptyCaptureFileError,
    InvalidFileExtensionError,
    InvalidPcapFormatError,
    validate_capture_file,
)


def test_validate_valid_pcap(synthetic_pcap_path):
    """Verifies that a genuine PCAP file passes validation and returns format and size."""
    fmt, size = validate_capture_file(synthetic_pcap_path)
    assert fmt == "PCAP"
    assert size > 0


def test_validate_missing_file():
    """Verifies that attempting to validate a non-existent file raises CaptureFileNotFoundError."""
    with pytest.raises(CaptureFileNotFoundError):
        validate_capture_file("non_existent_packet_file.pcap")


def test_validate_invalid_extension(tmp_path):
    """Verifies that an unsupported extension (.txt, .exe) raises InvalidFileExtensionError."""
    fake_txt = tmp_path / "packet_log.txt"
    fake_txt.write_bytes(b"hello world")
    with pytest.raises(InvalidFileExtensionError):
        validate_capture_file(fake_txt)


def test_validate_zero_byte_file(zero_byte_file_path):
    """Verifies that a 0-byte file raises EmptyCaptureFileError."""
    with pytest.raises(EmptyCaptureFileError):
        validate_capture_file(zero_byte_file_path)


def test_validate_corrupted_header(corrupted_file_path):
    """Verifies that a file with non-PCAP magic bytes raises InvalidPcapFormatError."""
    with pytest.raises(InvalidPcapFormatError):
        validate_capture_file(corrupted_file_path)


def test_validate_file_too_large(synthetic_pcap_path):
    """Verifies that exceeding the configured max byte limit raises CaptureFileTooLargeError."""
    with pytest.raises(CaptureFileTooLargeError):
        # Set max size to 10 bytes to intentionally trigger size validation
        validate_capture_file(synthetic_pcap_path, max_size_bytes=10)
