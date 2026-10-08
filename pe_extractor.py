"""Read-only, standard-library PE feature extraction for the saved ML model.

No code from uploaded executables is executed, imported, or saved to disk.
Only PE headers and embedded byte patterns are inspected.
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass

MAX_PE_BYTES = 20 * 1024 * 1024

# Base58Check addresses (legacy P2PKH/P2SH) and SegWit (bech32/bech32m).
_LEGACY_ADDRESS = re.compile(rb"(?<![A-Za-z0-9])[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?![A-Za-z0-9])")
_SEGWIT_ADDRESS = re.compile(rb"(?<![A-Za-z0-9])bc1[023456789acdefghjklmnpqrstuvwxyz]{11,87}(?![A-Za-z0-9])", re.I)
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


class PEFormatError(ValueError):
    """Raised when a file is not a supported, structurally valid PE image."""


def _read(data: bytes, fmt: str, offset: int, limit: int) -> int:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > limit or offset + size > len(data):
        raise PEFormatError("The PE header is truncated or inconsistent.")
    return struct.unpack_from(fmt, data, offset)[0]


def _base58check_valid(address: str) -> bool:
    number = 0
    for char in address:
        try:
            digit = _BASE58_ALPHABET.index(char)
        except ValueError:
            return False
        number = number * 58 + digit
    binary = number.to_bytes((number.bit_length() + 7) // 8, "big")
    binary = b"\x00" * (len(address) - len(address.lstrip("1"))) + binary
    if len(binary) != 25 or binary[0] not in (0x00, 0x05):
        return False
    return hashlib.sha256(hashlib.sha256(binary[:-4]).digest()).digest()[:4] == binary[-4:]


def _bech32_polymod(values: list[int]) -> int:
    generator = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i, mask in enumerate(generator):
            if (top >> i) & 1:
                chk ^= mask
    return chk


def _segwit_valid(address: str) -> bool:
    if address != address.lower() and address != address.upper():
        return False
    address = address.lower()
    if not address.startswith("bc1") or len(address) > 90:
        return False
    try:
        values = [_BECH32_ALPHABET.index(c) for c in address[3:]]
    except ValueError:
        return False
    if len(values) < 7:
        return False
    version = values[0]
    checksum = _bech32_polymod([3, 3, 0, 2, 3] + values)
    if version > 16 or checksum != (1 if version == 0 else 0x2BC830A3):
        return False
    # Convert 5-bit groups to 8-bit bytes; reject unexpected padding.
    accumulator = bits = 0
    program = []
    for value in values[1:-6]:
        accumulator = (accumulator << 5) | value
        bits += 5
        while bits >= 8:
            bits -= 8
            program.append((accumulator >> bits) & 0xFF)
    if bits >= 5 or ((accumulator << (8 - bits)) & 0xFF):
        return False
    return 2 <= len(program) <= 40 and (version != 0 or len(program) in (20, 32))


def _has_wallet_address(data: bytes) -> bool:
    """Heuristic: detect valid, unobfuscated mainnet wallet strings in bytes."""
    def found(blob: bytes) -> bool:
        return (any(_base58check_valid(m.group().decode("ascii")) for m in _LEGACY_ADDRESS.finditer(blob))
                or any(_segwit_valid(m.group().decode("ascii")) for m in _SEGWIT_ADDRESS.finditer(blob)))

    if found(data):
        return True
    # Windows binaries can contain UTF-16LE strings; scan them as text too.
    wide = data.decode("utf-16le", errors="ignore")
    return found(wide.encode("ascii", errors="replace"))


@dataclass(frozen=True)
class PEExtraction:
    features: dict[str, int]
    pe_kind: str
    sha256: str
    is_dll: bool
    size_bytes: int
    wallet_scan_note: str = (
        "BitcoinAddresses is approximated as 0/1 from valid visible wallet "
        "strings. This heuristic has not been verified against the dataset's "
        "original extraction method. Hidden/encoded addresses are not detected."
    )


def extract_pe_features(data: bytes) -> PEExtraction:
    """Parse a Windows PE32/PE32+ image without executing any file content."""
    if not isinstance(data, bytes):
        raise TypeError("Expected uploaded file bytes.")
    if not data:
        raise PEFormatError("The uploaded file is empty.")
    if len(data) > MAX_PE_BYTES:
        raise PEFormatError("The uploaded file exceeds the 20 MB upload limit.")
    if len(data) < 64 or data[:2] != b"MZ":
        raise PEFormatError("Not a Windows PE file (missing MZ header).")

    pe_offset = _read(data, "<I", 0x3C, len(data))
    if pe_offset < 0x40 or pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise PEFormatError("Not a valid Windows PE image (PE signature not found).")

    coff = pe_offset + 4
    machine = _read(data, "<H", coff, len(data))
    sections = _read(data, "<H", coff + 2, len(data))
    opt_size = _read(data, "<H", coff + 16, len(data))
    characteristics = _read(data, "<H", coff + 18, len(data))
    optional = coff + 20
    end_optional = optional + opt_size
    if not opt_size or end_optional > len(data):
        raise PEFormatError("Missing or truncated PE optional header.")

    magic = _read(data, "<H", optional, end_optional)
    if magic == 0x10B:
        pe_kind, stack_format, dir_count_at, directory_at = "PE32 (32-bit)", "<I", 92, 96
    elif magic == 0x20B:
        pe_kind, stack_format, dir_count_at, directory_at = "PE32+ (64-bit)", "<Q", 108, 112
    else:
        raise PEFormatError("Unsupported PE type (expected PE32 or PE32+).")
    # Headers are compared using the saved notebook's raw feature names.
    count = _read(data, "<I", optional + dir_count_at, end_optional)

    def directory(index: int) -> tuple[int, int]:
        if index >= count:
            return 0, 0
        start = optional + directory_at + index * 8
        return _read(data, "<I", start, end_optional), _read(data, "<I", start + 4, end_optional)

    export_rva, export_size = directory(0)
    _, resource_size = directory(2)
    debug_rva, debug_size = directory(6)
    iat_rva, _ = directory(12)
    features = {
        "Machine": machine,
        "DebugSize": debug_size,
        "DebugRVA": debug_rva,
        "MajorImageVersion": _read(data, "<H", optional + 44, end_optional),
        "MajorOSVersion": _read(data, "<H", optional + 40, end_optional),
        "ExportRVA": export_rva,
        "ExportSize": export_size,
        # Keep the historical column spelling used by the trained dataset.
        "IatVRA": iat_rva,
        "MajorLinkerVersion": _read(data, "<B", optional + 2, end_optional),
        "MinorLinkerVersion": _read(data, "<B", optional + 3, end_optional),
        "NumberOfSections": sections,
        "SizeOfStackReserve": _read(data, stack_format, optional + 72, end_optional),
        "DllCharacteristics": _read(data, "<H", optional + 70, end_optional),
        "ResourceSize": resource_size,
        "BitcoinAddresses": int(_has_wallet_address(data)),
    }
    return PEExtraction(
        features=features,
        pe_kind=pe_kind,
        sha256=hashlib.sha256(data).hexdigest(),
        is_dll=bool(characteristics & 0x2000),
        size_bytes=len(data),
    )
