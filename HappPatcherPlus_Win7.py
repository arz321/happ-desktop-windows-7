#!/usr/bin/env python3
"""Inject additional embedded files into this Happ Inno Setup 6.7.0 installer.

This is a deliberately narrow patcher for the Happ 4.7.2(636) Inno Setup 6.7.0
layout. It optionally embeds DLL files from an adjacent dll/ folder (if present),
embeds the adjacent pinned VxKex installer, and adds waited [Run] entries.
It does not use ISCC.
The RunEntry serializer is checked field-by-field before and after writing.

Python 3.10+, standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import lzma
import os
import re
import struct
import sys
import zlib
from pathlib import Path

MAGIC = b"rDlPtS"
ZLB_MAGIC = b"zlb\x1a"
SETUP_ID_PREFIX = b"Inno Setup Setup Data (6.7.0)"
SETUP_ID_SIZE = 64
ENCRYPTION_HEADER_SIZE = 53
BLOCK_HEADER_SIZE = 13
BLOCK_SIZE = 4096
OFFSET_TABLE_SIZE = 64
DATA_ENTRY_SIZE = 89
FILE_ENTRY_EXTRA_STRINGS = 12
FILE_ENTRY_TAIL_SIZE = 88
FILE_ENTRY_LOCATION_OFFSET = 60  # relative to the 88-byte binary tail
PE_SECURITY_DIRECTORY_INDEX = 4


class PatchError(Exception):
    pass


def u32(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u64(data: bytes | bytearray, offset: int) -> int:
    return struct.unpack_from("<Q", data, offset)[0]


def put_u32(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<I", data, offset, value)


def put_u64(data: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", data, offset, value)


def crc32(data: bytes | bytearray) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def find_offset_table(exe: bytes) -> int:
    hits = []
    pos = 0
    while True:
        pos = exe.find(MAGIC, pos)
        if pos < 0:
            break
        if pos + OFFSET_TABLE_SIZE <= len(exe):
            hits.append(pos)
        pos += 1
    if len(hits) != 1:
        raise PatchError(f"Expected one SetupLdr offset table, found {len(hits)}")
    return hits[0]


def read_offset_table(exe: bytes, pos: int) -> dict[str, int]:
    table = exe[pos:pos + OFFSET_TABLE_SIZE]
    if table[:12] != b"rDlPtS\xCD\xE6\xD7\x7B\x0B\x2A":
        raise PatchError("Unexpected SetupLdr offset-table identifier")
    if u32(table, 12) != 2:
        raise PatchError("Only SetupLdr offset-table revision 2 is supported")
    if crc32(table[:60]) != u32(table, 60):
        raise PatchError("SetupLdr offset-table CRC mismatch")
    return {
        "total_size": u64(table, 16),
        "offset_exe": u64(table, 24),
        "offset0": u64(table, 40),
        "offset1": u64(table, 48),
    }


def decode_block(exe: bytes, offset: int) -> tuple[bytes, int, bytes]:
    if offset + BLOCK_HEADER_SIZE > len(exe):
        raise PatchError("Header block starts outside the installer")
    stored_size = u64(exe, offset + 4)
    compressed = exe[offset + 12]
    if crc32(exe[offset + 4:offset + 13]) != u32(exe, offset):
        raise PatchError(f"Header block CRC mismatch at 0x{offset:X}")
    if compressed not in (0, 1):
        raise PatchError("Invalid header block compression flag")

    pos = offset + BLOCK_HEADER_SIZE
    end = pos + stored_size
    if end > len(exe):
        raise PatchError("Header block extends beyond installer")
    raw = bytearray()
    remaining = stored_size
    while remaining:
        if remaining < 4:
            raise PatchError("Truncated header-block CRC chunk")
        expected = u32(exe, pos)
        pos += 4
        remaining -= 4
        size = min(BLOCK_SIZE, remaining)
        chunk = exe[pos:pos + size]
        if len(chunk) != size or crc32(chunk) != expected:
            raise PatchError(f"Header-block data CRC mismatch at 0x{pos:X}")
        raw.extend(chunk)
        pos += size
        remaining -= size

    raw_bytes = bytes(raw)
    if compressed:
        if len(raw_bytes) < 5:
            raise PatchError("Compressed header block is too short")
        decoded = lzma.decompress(raw_bytes[:5] + b"\xff" * 8 + raw_bytes[5:],
                                 format=lzma.FORMAT_ALONE)
    else:
        decoded = raw_bytes
    return decoded, end, raw_bytes


def lzma_filter_from_props(props: bytes, dict_size_override: int | None = None) -> dict:
    if len(props) != 5:
        raise PatchError("Invalid LZMA properties")
    value = props[0]
    if value >= 9 * 5 * 5:
        raise PatchError("Unsupported LZMA property byte")
    lc = value % 9
    value //= 9
    lp = value % 5
    pb = value // 5
    dict_size = int.from_bytes(props[1:5], "little")
    if dict_size_override is not None:
        dict_size = dict_size_override
    if dict_size < 4096:
        dict_size = 4096
    return {
        "id": lzma.FILTER_LZMA1,
        "dict_size": dict_size,
        "lc": lc,
        "lp": lp,
        "pb": pb,
        "mode": lzma.MODE_NORMAL,
        "nice_len": 64,
        "mf": lzma.MF_BT4,
        "depth": 0,
    }


def encode_header_block(decoded: bytes, original_raw: bytes) -> bytes:
    if len(original_raw) < 5:
        raise PatchError("Original header LZMA properties are missing")
    props = original_raw[:5]
    filters = [lzma_filter_from_props(props)]
    compressed = lzma.compress(decoded, format=lzma.FORMAT_RAW, filters=filters)
    raw = props + compressed
    framed = bytearray()
    for start in range(0, len(raw), BLOCK_SIZE):
        chunk = raw[start:start + BLOCK_SIZE]
        framed += struct.pack("<I", crc32(chunk)) + chunk
    tail = struct.pack("<QB", len(framed), 1)
    return struct.pack("<I", crc32(tail)) + tail + framed


def parse_header_counts(block1: bytes) -> tuple[int, tuple[int, ...]]:
    """Return count-array offset and 17 TSetupHeader entry counts."""
    pos = 0
    for _ in range(39):
        if pos + 4 > len(block1):
            raise PatchError("Truncated TSetupHeader Unicode strings")
        size = u32(block1, pos)
        pos += 4 + size
        if pos > len(block1):
            raise PatchError("TSetupHeader Unicode string exceeds header")
    for _ in range(4):
        if pos + 4 > len(block1):
            raise PatchError("Truncated TSetupHeader ANSI strings")
        size = u32(block1, pos)
        pos += 4 + size
        if pos > len(block1):
            raise PatchError("TSetupHeader ANSI string exceeds header")
    if pos + 17 * 4 > len(block1):
        raise PatchError("TSetupHeader entry-count array is truncated")
    counts = struct.unpack_from("<17I", block1, pos)
    return pos, counts


def find_icon_table_start(block1: bytes, expected_icons: int) -> int:
    """Find the first icon entry by its two path strings in this Happ build."""
    name = "{group}\\Happ".encode("utf-16-le")
    expected_filename = "{app}\\Happ.exe"
    hits = []
    pos = 0
    while True:
        pos = block1.find(name, pos)
        if pos < 0:
            break
        if pos >= 4:
            name_len = u32(block1, pos - 4)
            if name_len == len(name):
                p2 = pos + len(name)
                if p2 + 4 <= len(block1):
                    file_len = u32(block1, p2)
                    if file_len <= 4096 and p2 + 4 + file_len <= len(block1):
                        filename = block1[p2 + 4:p2 + 4 + file_len].decode("utf-16-le", "strict")
                        if filename == expected_filename:
                            hits.append(pos - 4)
        pos += 1
    if not hits:
        raise PatchError("Could not locate the first Happ icon entry")
    # The second icon in this build has an empty Name and a Tasks value, so it
    # does not repeat the {group}\\Happ marker. The header count still verifies
    # that this is the expected two-icon layout.
    return min(hits)


def find_file_entry_template(block1: bytes) -> bytes:
    """Get a normal embedded DLL record tail from the original Happ file table."""
    dest = "{app}\\avcodec-61.dll".encode("utf-16-le")
    pos = 0
    matches = []
    while True:
        pos = block1.find(dest, pos)
        if pos < 0:
            break
        if pos >= 8 and u32(block1, pos - 4) == len(dest) and u32(block1, pos - 8) == 0:
            entry_start = pos - 8
            p = pos + len(dest)
            valid = True
            for _ in range(FILE_ENTRY_EXTRA_STRINGS):
                if p + 4 > len(block1) or u32(block1, p) != 0:
                    valid = False
                    break
                p += 4
            if valid and p + FILE_ENTRY_TAIL_SIZE <= len(block1):
                tail = block1[p:p + FILE_ENTRY_TAIL_SIZE]
                if u32(tail, FILE_ENTRY_LOCATION_OFFSET) == 256:
                    matches.append(tail)
        pos += 1
    if len(matches) != 1:
        raise PatchError(f"Expected one embedded DLL template record, found {len(matches)}")
    return matches[0]


def build_file_entry(destination: str, location_index: int, template_tail: bytes) -> bytes:
    dest_bytes = destination.encode("utf-16-le")
    if len(dest_bytes) > 65535:
        raise PatchError("Destination path is too long")
    tail = bytearray(template_tail)
    put_u32(tail, FILE_ENTRY_LOCATION_OFFSET, location_index * 256)
    return (
        struct.pack("<I", 0) +
        struct.pack("<I", len(dest_bytes)) + dest_bytes +
        (b"\x00\x00\x00\x00" * FILE_ENTRY_EXTRA_STRINGS) +
        bytes(tail)
    )


def filetime_utc(path: Path) -> int:
    # Windows FILETIME: 100 ns ticks since 1601-01-01 UTC.
    ns = path.stat().st_mtime_ns
    return (ns + 11644473600 * 1_000_000_000) // 100


def lzma2_dict_property(dict_size: int) -> int:
    """Return the one-byte LZMA2 dictionary property for a supported size."""
    for prop in range(41):
        size = (2 | (prop & 1)) << (prop // 2 + 11)
        if size >= dict_size:
            return prop
    raise PatchError("LZMA2 dictionary size is too large")


def compress_file_chunk(data: bytes, dict_size: int = 8 * 1024 * 1024) -> tuple[bytes, bytes]:
    # Happ's file-data archive uses LZMA2. The first byte after 'zlb\x1a'
    # is the LZMA2 dictionary property, not five LZMA1 properties.
    prop = lzma2_dict_property(dict_size)
    actual_dict_size = (2 | (prop & 1)) << (prop // 2 + 11)
    filters = [{"id": lzma.FILTER_LZMA2, "dict_size": actual_dict_size, "preset": 6}]
    stream = lzma.compress(data, format=lzma.FORMAT_RAW, filters=filters)
    payload = bytes([prop]) + stream
    restored = lzma.decompress(
        stream, format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA2, "dict_size": actual_dict_size}],
    )
    if restored != data:
        raise PatchError("New DLL LZMA2 round-trip verification failed")
    return ZLB_MAGIC + payload, payload


def build_location_entry(start_offset: int, original_size: int,
                         compressed_size: int, digest: bytes, timestamp: int) -> bytes:
    if len(digest) != 32:
        raise PatchError("SHA-256 digest must be 32 bytes")
    # TSetupFileLocationEntry, 6.7.0 layout, 89 bytes total:
    # first/last slice, start offset, chunk suboffset, original size,
    # compressed size, SHA-256, FILETIME, file version MS/LS, flags.
    record = bytearray(DATA_ENTRY_SIZE)
    struct.pack_into("<iiQQQQ", record, 0,
                     0, 0, start_offset, 0, original_size, compressed_size)
    record[40:72] = digest
    struct.pack_into("<QII", record, 72, timestamp, 0, 0)
    record[88] = 0x12  # timestamp is UTC (0x02), chunk uses LZMA2 (0x10)
    return bytes(record)



def find_wizard_images_start(block1: bytes) -> int:
    """Locate the first length-prefixed PNG wizard image in this Happ 6.7 build."""
    signature = b"\x89PNG\r\n\x1a\n"
    hits = []
    pos = 0
    while True:
        pos = block1.find(signature, pos)
        if pos < 0:
            break
        if pos >= 8:
            image_size = u32(block1, pos - 4)
            image_count = u32(block1, pos - 8)
            if image_count == 1 and image_size >= 8 and pos + image_size <= len(block1):
                # PNG end marker must be inside the length-prefixed payload.
                if block1[pos + image_size - 12:pos + image_size] == b"\x00\x00\x00\x00IEND\xaeB`\x82":
                    hits.append(pos - 8)
        pos += len(signature)
    if len(hits) != 2:
        raise PatchError(f"Expected exactly two length-prefixed wizard PNG images, found {len(hits)}")
    return min(hits)


def lp_u16(value: str) -> bytes:
    encoded = value.encode("utf-16-le")
    return struct.pack("<I", len(encoded)) + encoded


def build_run_entry(strings: list[str], version_range: bytes,
                    show_cmd: int = 1, wait: int = 0, flags: int = 0) -> bytes:
    """Serialize one Inno Setup 6.7.0 TSetupRunEntry (Unicode)."""
    if len(strings) != 13:
        raise PatchError(f"RunEntry requires 13 strings, got {len(strings)}")
    if len(version_range) != 20:
        raise PatchError(f"Expected a 20-byte Setup version range, got {len(version_range)}")
    if not 0 <= flags <= 0x0FFF:
        raise PatchError(f"RunEntry flags outside 12-bit range: {flags:#x}")
    record = b"".join(lp_u16(value) for value in strings)
    record += version_range
    record += struct.pack("<IBH", show_cmd, wait, flags)
    return record


KEX_SETUP_STRINGS = [
    r"{tmp}\KexSetup_Release_1_2_2_2316.exe",
    "/SILENTUNATTEND",
    "", "", "Installing VxKex...", "", "", "", "", "", "", "", "",
]

KEXCFG_STRINGS = [
    [r"{commonpf64}\VxKex\KexCfg.exe",
     r'/EXE:"{app}\Happ.exe" /ENABLE:YES /WINVERSPOOF:WIN10',
     "", "", "Configuring Happ compatibility...", "", "", "", "", "", "", "", ""],
    [r"{commonpf64}\VxKex\KexCfg.exe",
     r'/EXE:"{localappdata}\Happ\update\setup-Happ.x64.exe" /ENABLE:YES /WINVERSPOOF:WIN10',
     "", "", "Configuring Happ service compatibility...", "", "", "", "", "", "", "", ""],
    [r"{commonpf64}\VxKex\KexCfg.exe",
     r'/EXE:"{app}\happd.exe" /ENABLE:YES',
     "", "", "Configuring Happ service compatibility...", "", "", "", "", "", "", "", ""],
    [r"{commonpf64}\VxKex\KexCfg.exe",
     r'/EXE:"{app}\core\xray.exe" /ENABLE:YES',
     "", "", "Configuring Xray compatibility...", "", "", "", "", "", "", "", ""],
    [r"{commonpf64}\VxKex\KexCfg.exe",
     r'/EXE:"{app}\tun2\tun2proxy-bin.exe" /ENABLE:YES',
     "", "", "Configuring tun2proxy compatibility...", "", "", "", "", "", "", "", ""],
]


def build_kex_run_entry(version_range: bytes) -> bytes:
    """Build the waited KexSetup invocation used to install VxKex."""
    record = build_run_entry(KEX_SETUP_STRINGS, version_range)
    parsed = verify_run_entry(record, KEX_SETUP_STRINGS, version_range,
                              expected_wait=0, expected_flags=0)
    if parsed["filename"] != r"{tmp}\KexSetup_Release_1_2_2_2316.exe":
        raise PatchError("KexSetup RunEntry filename mismatch")
    return record


def build_kexcfg_run_entries(version_range: bytes) -> list[bytes]:
    """Build the five ordered KexCfg compatibility registrations."""
    entries = []
    for strings in KEXCFG_STRINGS:
        record = build_run_entry(strings, version_range)
        verify_run_entry(record, strings, version_range,
                         expected_wait=0, expected_flags=0)
        entries.append(record)
    return entries


def verify_run_entry(record: bytes, expected_strings: list[str],
                     expected_version_range: bytes,
                     expected_wait: int = 0, expected_flags: int = 0) -> dict[str, object]:
    """Parse and validate one 6.7.0 SetupRunEntry."""
    pos = 0
    strings: list[str] = []
    for _ in range(13):
        if pos + 4 > len(record):
            raise PatchError("RunEntry parser: truncated string length")
        size = u32(record, pos)
        pos += 4
        if size & 1 or pos + size > len(record):
            raise PatchError("RunEntry parser: invalid UTF-16 string length")
        try:
            value = record[pos:pos + size].decode("utf-16-le", "strict")
        except UnicodeDecodeError as exc:
            raise PatchError(f"RunEntry parser: invalid UTF-16 string: {exc}") from exc
        strings.append(value)
        pos += size

    if pos + 27 != len(record):
        raise PatchError("RunEntry parser: invalid version/show/wait/flags tail")
    winver = record[pos:pos + 20]
    pos += 20
    show_cmd = u32(record, pos)
    pos += 4
    wait = record[pos]
    pos += 1
    flags = int.from_bytes(record[pos:pos + 2], "little")
    if strings != expected_strings:
        raise PatchError(f"RunEntry parser: unexpected strings: {strings!r}")
    if winver != expected_version_range:
        raise PatchError("RunEntry parser: version range does not match Setup header")
    if show_cmd != 1 or wait != expected_wait or flags != expected_flags:
        raise PatchError(
            f"RunEntry parser: ShowCmd={show_cmd}, Wait={wait}, Flags={flags:#x}; "
            f"expected ShowCmd=1, Wait={expected_wait}, Flags={expected_flags:#x}"
        )
    return {"filename": strings[0], "parameters": strings[1],
            "show_cmd": show_cmd, "wait": wait, "flags": flags}



def patch_compiledcode_windows_version(block1: bytearray) -> tuple[int, int]:
    """Change Happ's minimum Windows check from Win10 build 15063 to Win7 build 7600.

    Offsets are relative to the IFPS magic at the beginning of CompiledCode.bin.
    The two target DWORDs were confirmed against the paired Inno Setup 6.7.0
    control installers and the user's hex comparison.
    """
    ifps = block1.find(b"IFPS")
    if ifps < 0 or block1.find(b"IFPS", ifps + 1) >= 0:
        raise PatchError("Expected exactly one IFPS CompiledCode block in Setup header")
    fields = ((0x15F1B, bytes.fromhex("0A 00 00 00"), bytes.fromhex("06 00 00 00")),
              (0x15F6B, bytes.fromhex("D7 3A 00 00"), bytes.fromhex("B0 1D 00 00")))
    changed = 0
    for rel, old, new in fields:
        pos = ifps + rel
        actual = bytes(block1[pos:pos + 4])
        if actual == old:
            block1[pos:pos + 4] = new
            changed += 1
        elif actual == new:
            pass  # idempotent: already patched
        else:
            raise PatchError(
                f"Unexpected CompiledCode version field at IFPS+0x{rel:X}: {actual.hex(' ')}"
            )
    return ifps, changed


def pe_security_directory(exe: bytes) -> tuple[int, int, int]:
    if exe[:2] != b"MZ":
        raise PatchError("Input is not a PE executable")
    pe = u32(exe, 0x3C)
    if pe + 24 > len(exe) or exe[pe:pe + 4] != b"PE\0\0":
        raise PatchError("Invalid PE header")
    opt = pe + 24
    magic = struct.unpack_from("<H", exe, opt)[0]
    if magic == 0x10B:
        number_dirs, dirs = opt + 92, opt + 96
    elif magic == 0x20B:
        number_dirs, dirs = opt + 108, opt + 112
    else:
        raise PatchError("Unsupported PE optional-header type")
    count = u32(exe, number_dirs)
    entry = dirs + PE_SECURITY_DIRECTORY_INDEX * 8
    if count <= PE_SECURITY_DIRECTORY_INDEX:
        return 0, 0, entry
    cert_offset, cert_size = struct.unpack_from("<II", exe, entry)
    if cert_offset and cert_size and cert_offset + cert_size > len(exe):
        raise PatchError("PE certificate directory points outside installer")
    return cert_offset, cert_size, entry


def parse_location_record(block2: bytes, index: int) -> dict[str, int | bytes]:
    off = index * DATA_ENTRY_SIZE
    if off + DATA_ENTRY_SIZE > len(block2):
        raise PatchError("Data location index outside second header block")
    return {
        "start_offset": u64(block2, off + 8),
        "suboffset": u64(block2, off + 16),
        "original_size": u64(block2, off + 24),
        "compressed_size": u64(block2, off + 32),
        "sha256": block2[off + 40:off + 72],
        "timestamp": u64(block2, off + 72),
        "flags": block2[off + 88],
    }


def inject(input_exe: Path, file_paths: list[Path], output_exe: Path, kex_setup: Path | None = None) -> None:
    if not file_paths and not kex_setup:
        raise PatchError("No files were supplied for injection")
    if not input_exe.is_file():
        raise PatchError(f"Installer not found: {input_exe}")
    all_paths = list(file_paths) + ([kex_setup] if kex_setup else [])
    seen_names: set[str] = set()
    for path in all_paths:
        if not path.is_file():
            raise PatchError(f"Input file not found: {path}")
        if path.stat().st_size == 0:
            raise PatchError(f"Input file is empty: {path}")
        key = path.name.casefold()
        if key in seen_names:
            raise PatchError(f"Duplicate embedded filename: {path.name}")
        seen_names.add(key)

    exe = input_exe.read_bytes()
    table_pos = find_offset_table(exe)
    table = read_offset_table(exe, table_pos)
    setup_id = exe[table["offset0"]:table["offset0"] + SETUP_ID_SIZE].split(b"\0", 1)[0]
    if not setup_id.startswith(SETUP_ID_PREFIX):
        raise PatchError(f"Expected Inno Setup 6.7.0, found {setup_id!r}")

    # Header blocks are stored at Offset0; data chunks occupy Offset1..Offset0.
    block1_start = table["offset0"] + SETUP_ID_SIZE + ENCRYPTION_HEADER_SIZE
    block1, block2_start, raw1 = decode_block(exe, block1_start)
    block1 = bytearray(block1)
    compiled_ifps_offset, compiled_fields_changed = patch_compiledcode_windows_version(block1)
    block2, block2_end, raw2 = decode_block(exe, block2_start)
    if block2_end != table["offset_exe"]:
        raise PatchError("Second header block does not end at OffsetEXE")
    if len(block2) % DATA_ENTRY_SIZE:
        raise PatchError("Second header block is not a whole number of 89-byte entries")

    counts_pos, counts = parse_header_counts(block1)
    num_file_entries = counts[8]
    num_locations = counts[9]
    num_icons = counts[10]
    if num_locations != len(block2) // DATA_ENTRY_SIZE:
        raise PatchError(
            f"Header says {num_locations} file locations, block2 contains {len(block2) // DATA_ENTRY_SIZE}"
        )
    if num_icons != 2:
        raise PatchError(f"This Happ build is expected to contain 2 icon entries, found {num_icons}")

    # This exact build stores two icon records after the file-entry table.
    # The marker is checked against the parsed NumIconEntries count.
    icon_start = find_icon_table_start(block1, num_icons)
    template_tail = find_file_entry_template(block1)

    data_offset = table["offset1"]
    old_header_offset = table["offset0"]
    data_region = exe[data_offset:old_header_offset]
    if len(data_region) < 9 or data_region[:4] != ZLB_MAGIC:
        raise PatchError("Expected a single zlb data chunk at Offset1")

    # Existing files may already occupy multiple independent zlb chunks.
    # Verify that the location table accounts for the complete data region.
    existing_chunk_ends = []
    for i in range(num_locations):
        loc = parse_location_record(block2, i)
        start = int(loc["start_offset"])
        comp_size = int(loc["compressed_size"])
        if start < 0 or comp_size <= 0 or start + 4 + comp_size > len(data_region):
            raise PatchError(f"Existing data location {i} points outside the data region")
        if data_region[start:start + 4] != ZLB_MAGIC:
            raise PatchError(f"Existing data location {i} has no zlb marker")
        existing_chunk_ends.append(start + 4 + comp_size)
    if not existing_chunk_ends or max(existing_chunk_ends) != len(data_region):
        raise PatchError("Existing file-location records do not cover the complete data region")

    # Verify the original archive's LZMA1 properties. Newly added chunks below
    # are encoded independently as LZMA2.
    source_props = exe[data_offset + 4:data_offset + 9]
    lzma_filter_from_props(source_props, dict_size_override=8 * 1024 * 1024)

    new_file_records = bytearray()
    new_location_records = bytearray()
    new_chunks = bytearray()
    new_payloads: list[tuple[str, bytes, int, int]] = []
    current_data_relative_offset = len(data_region)

    all_paths = list(file_paths) + ([kex_setup] if kex_setup else [])
    seen_names: set[str] = set()
    for path in all_paths:
        data = path.read_bytes()
        chunk, compressed_payload = compress_file_chunk(data)
        location_index = num_locations + len(new_payloads)
        destination_name = path.name
        destination = ("{tmp}\\" if (kex_setup and path.resolve() == kex_setup.resolve()) else "{app}\\") + destination_name
        new_file_records += build_file_entry(destination, location_index, template_tail)
        new_location_records += build_location_entry(
            start_offset=current_data_relative_offset,
            original_size=len(data),
            compressed_size=len(compressed_payload),
            digest=hashlib.sha256(data).digest(),
            timestamp=filetime_utc(path),
        )
        new_chunks += chunk
        new_payloads.append((destination, data, current_data_relative_offset, len(compressed_payload)))
        current_data_relative_offset += len(chunk)

    # Insert file records immediately before the existing icon table.
    block1_new = bytearray(block1[:icon_start] + bytes(new_file_records) + block1[icon_start:])

    # Add one mandatory [Run] entry for KexSetup. It is processed by Inno Setup
    # after files have been copied and before the final completion page. The
    # RunEntries array is the final setup-entry array, immediately before the
    # two length-prefixed wizard PNG images.
    if kex_setup:
        if counts[15] != 0 or counts[16] != 0:
            raise PatchError("This patcher expects no existing Run/UninstallRun entries")
        run_pos = find_wizard_images_start(bytes(block1_new))
        # The 17 entry counters are followed by TSetupHeader.MinVersion and
        # OnlyBelowVersion (10 bytes each). ISCC copies this 20-byte range into
        # each compiled RunEntry; preserve it exactly.
        version_range_offset = counts_pos + 17 * 4
        version_range = bytes(block1[version_range_offset:version_range_offset + 20])
        if len(version_range) != 20:
            raise PatchError("Setup header version range is truncated")
        run_entries = [build_kex_run_entry(version_range)]
        run_entries.extend(build_kexcfg_run_entries(version_range))
        run_blob = b"".join(run_entries)
        block1_new[run_pos:run_pos] = run_blob
        put_u32(block1_new, counts_pos + 15 * 4, len(run_entries))

    put_u32(block1_new, counts_pos + 8 * 4, num_file_entries + len(all_paths))
    put_u32(block1_new, counts_pos + 9 * 4, num_locations + len(all_paths))
    block2_new = block2 + bytes(new_location_records)

    encoded1 = encode_header_block(bytes(block1_new), raw1)
    encoded2 = encode_header_block(block2_new, raw2)
    old_header_region = exe[old_header_offset:table["offset_exe"]]
    new_header_prefix = exe[old_header_offset:old_header_offset + SETUP_ID_SIZE + ENCRYPTION_HEADER_SIZE]
    new_header_region = new_header_prefix + encoded1 + encoded2
    header_delta = len(new_header_region) - len(old_header_region)
    data_delta = len(new_chunks)

    cert_offset, cert_size, security_entry = pe_security_directory(exe)
    payload_end = cert_offset if cert_offset and cert_size else len(exe)
    if payload_end < table["offset_exe"]:
        raise PatchError("Authenticode certificate overlaps the setup payload")

    prefix = exe[:data_offset]
    suffix = exe[table["offset_exe"]:payload_end]
    output = bytearray(prefix + data_region + bytes(new_chunks) + new_header_region + suffix)

    # Update SetupLdr offsets. Offset1 stays fixed; Offset0 moves by new chunks;
    # OffsetEXE and TotalSize move by both data and recompressed-header deltas.
    put_u64(output, table_pos + 16, table["total_size"] + data_delta + header_delta)
    put_u64(output, table_pos + 24, table["offset_exe"] + data_delta + header_delta)
    put_u64(output, table_pos + 40, table["offset0"] + data_delta)
    put_u32(output, table_pos + 60, crc32(output[table_pos:table_pos + 60]))

    # Any binary edit invalidates Authenticode. Remove the certificate directory
    # and zero the PE checksum, matching the existing HappPatcher behavior.
    if security_entry + 8 <= len(output):
        put_u32(output, security_entry, 0)
        put_u32(output, security_entry + 4, 0)
    pe = u32(output, 0x3C)
    put_u32(output, pe + 24 + 64, 0)

    # Read-after-write verification: headers, counts, location entries, and DLL bytes.
    verify = bytes(output)
    vt = read_offset_table(verify, table_pos)
    v_header_start = vt["offset0"] + SETUP_ID_SIZE + ENCRYPTION_HEADER_SIZE
    v1, v2_start, _ = decode_block(verify, v_header_start)
    v2, v_end, _ = decode_block(verify, v2_start)
    if v_end != vt["offset_exe"]:
        raise PatchError("Post-write verification: OffsetEXE mismatch")
    v_counts_pos, v_counts = parse_header_counts(v1)
    if v_counts[8] != num_file_entries + len(all_paths) or v_counts[9] != num_locations + len(all_paths):
        raise PatchError("Post-write verification: file-entry counts mismatch")
    expected_run_entries = []
    if kex_setup:
        expected_run_entries = [build_kex_run_entry(version_range)]
        expected_run_entries.extend(build_kexcfg_run_entries(version_range))
    if kex_setup and v_counts[15] != len(expected_run_entries):
        raise PatchError(
            f"Post-write verification: RunEntries count is {v_counts[15]}, "
            f"expected {len(expected_run_entries)}"
        )
    if kex_setup:
        v_run_pos = find_wizard_images_start(v1)
        expected_run_blob = b"".join(expected_run_entries)
        actual_run_blob = v1[v_run_pos - len(expected_run_blob):v_run_pos]
        if actual_run_blob != expected_run_blob:
            raise PatchError("Post-write verification: KexSetup/KexCfg RunEntries mismatch")
        cursor = 0
        for expected_strings, expected_entry in zip(
                [KEX_SETUP_STRINGS] + KEXCFG_STRINGS, expected_run_entries):
            verify_run_entry(expected_entry, expected_strings, version_range,
                             expected_wait=0, expected_flags=0)
            cursor += len(expected_entry)
        if cursor != len(actual_run_blob):
            raise PatchError("Post-write verification: RunEntry sequence length mismatch")
    if len(v2) != (num_locations + len(all_paths)) * DATA_ENTRY_SIZE:
        raise PatchError("Post-write verification: data-entry count mismatch")

    # Confirm inserted file entries are immediately before the icon table.
    v_icon_start = find_icon_table_start(v1, num_icons)
    check_pos = v_icon_start - len(new_file_records)
    for i, (dest, original, expected_start, expected_comp_size) in enumerate(new_payloads):
        p = check_pos
        src_len = u32(v1, p)
        p += 4 + src_len
        dest_len = u32(v1, p)
        p += 4
        actual_dest = v1[p:p + dest_len].decode("utf-16-le", "strict")
        p += dest_len
        if actual_dest != dest:
            raise PatchError(f"Post-write verification: destination mismatch for {dest}")
        for _ in range(FILE_ENTRY_EXTRA_STRINGS):
            if u32(v1, p) != 0:
                raise PatchError("Post-write verification: unexpected optional file-entry string")
            p += 4
        tail = v1[p:p + FILE_ENTRY_TAIL_SIZE]
        expected_loc = (num_locations + i) * 256
        if u32(tail, FILE_ENTRY_LOCATION_OFFSET) != expected_loc:
            raise PatchError("Post-write verification: file location pointer mismatch")
        check_pos = p + FILE_ENTRY_TAIL_SIZE

        loc = parse_location_record(v2, num_locations + i)
        if (loc["start_offset"] != expected_start or
                loc["original_size"] != len(original) or
                loc["compressed_size"] != expected_comp_size or
                loc["sha256"] != hashlib.sha256(original).digest()):
            raise PatchError(f"Post-write verification: data-location metadata mismatch for {dest}")
        chunk_start = vt["offset1"] + int(loc["start_offset"])
        if verify[chunk_start:chunk_start + 4] != ZLB_MAGIC:
            raise PatchError(f"Post-write verification: zlb marker missing for {dest}")
        prop = verify[chunk_start + 4]
        if prop > 40:
            raise PatchError(f"Post-write verification: invalid LZMA2 dictionary property for {dest}")
        dict_size = (2 | (prop & 1)) << (prop // 2 + 11)
        compressed = verify[chunk_start + 5:chunk_start + 4 + int(loc["compressed_size"])]
        restored = lzma.decompress(
            compressed, format=lzma.FORMAT_RAW,
            filters=[{"id": lzma.FILTER_LZMA2, "dict_size": dict_size}],
        )
        if restored != original:
            raise PatchError(f"Post-write verification: extracted bytes differ for {dest}")

    output_exe.parent.mkdir(parents=True, exist_ok=True)
    tmp = output_exe.with_suffix(output_exe.suffix + ".tmp")
    tmp.write_bytes(output)
    os.replace(tmp, output_exe)

    print(f"[+] Input: {input_exe}")
    print(f"[+] CompiledCode: Windows version check patched to Windows 7 (IFPS+0x15F1B=6, IFPS+0x15F6B=7600); fields changed: {compiled_fields_changed}")
    print(f"[+] Added files: {len(new_payloads)}")
    for dest, data, start, compressed_size in new_payloads:
        print(f"    {dest}: {len(data):,} bytes, chunk offset {start:,}, compressed {compressed_size:,} bytes")
    print(f"[+] Header delta: {header_delta:+,} bytes; data delta: {data_delta:+,} bytes")
    print(f"[+] Output: {output_exe}")
    print(f"[+] Output size: {len(output):,} bytes")
    print(f"[+] SHA-256: {hashlib.sha256(output).hexdigest()}")
    print("[!] Authenticode signature was removed because the EXE was modified.")
    if kex_setup:
        print("[+] RunEntries: 6 (KexSetup followed by five KexCfg commands)")
        print("[+] All six entries: Setup MinVersion range copied, ShowCmd=1, Wait=0, flags=0")
        for index, strings in enumerate(KEXCFG_STRINGS, 1):
            print(f"    KexCfg {index}: {strings[0]} {strings[1]}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Patch Happ Inno Setup 6.7.0 for Windows 7; "
            "Defaults to the Happ updater installer in LocalAppData; "
            "KexSetup is read from beside this script; DLLs are optional"
        )
    )
    parser.add_argument(
        "input_exe",
        nargs="?",
        type=Path,
        help="Input installer (default: %LOCALAPPDATA%\\Happ\\update\\setup-Happ.x64.exe)",
    )
    parser.add_argument(
        "output_exe",
        nargs="?",
        type=Path,
        help="Output installer (default: <script folder>\\<input name>_win7.exe)",
    )
    args = parser.parse_args()

    try:
        script_dir = Path(__file__).resolve().parent

        # Expand the default input using the current user's Local AppData.
        # Windows command-line tools do not automatically expand %VARIABLES%.
        if args.input_exe is None:
            local_app_data = (
                os.environ.get("LOCALAPPDATA")
                or os.environ.get("LocalAppData")
            )
            if not local_app_data:
                raise PatchError(
                    "LOCALAPPDATA is not set; specify input_exe explicitly."
                )
            input_exe = (
                Path(local_app_data) / "Happ" / "update" / "setup-Happ.x64.exe"
            )
        else:
            input_exe = args.input_exe.expanduser()

        if args.output_exe is None:
            output_exe = script_dir / f"{input_exe.stem}_win7{input_exe.suffix or '.exe'}"
        else:
            output_exe = args.output_exe.expanduser()

        dll_folder = script_dir / "dll"
        kex_path = script_dir / "KexSetup_Release_1_2_2_2316.exe"

        # DLLs are optional for current Happ builds. If the folder is absent,
        # or contains no DLL files, continue without embedding any DLLs.
        dlls = []
        if dll_folder.is_dir():
            dlls = sorted(
                (x for x in dll_folder.iterdir()
                 if x.is_file() and x.suffix.lower() == ".dll"),
                key=lambda x: x.name.casefold(),
            )
        if dlls:
            print(f"[+] Optional DLL files found in {dll_folder.name}/: {len(dlls)}")
            for item in dlls:
                print(f"    {item.name} ({item.stat().st_size:,} bytes)")
        else:
            print("[+] No optional DLL files found; continuing without adding DLLs")

        if not kex_path.is_file():
            raise PatchError(f"KexSetup file not found next to script: {kex_path}")
        kex_data = kex_path.read_bytes()
        if kex_data[:2] != b"MZ":
            raise PatchError(f"KexSetup is not a PE executable: {kex_path}")
        print(f"[+] KexSetup found beside script: {kex_path.name}")

        inject(input_exe, dlls, output_exe, kex_setup=kex_path)
        return 0
    except (PatchError, OSError, ValueError, struct.error, lzma.LZMAError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
