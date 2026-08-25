from __future__ import annotations

from pathlib import Path
import plistlib
import struct
import tempfile
import unittest

from openbundle.macho import (
    MAX_RPATH_BYTES,
    is_macho,
    parse_der_entitlements,
    parse_export_trie,
    parse_macho,
)
from tests.helpers import write_macho


def _uleb128(value: int) -> bytes:
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            return bytes(encoded)


def _flat_export_trie(symbols: list[str]) -> bytes:
    """Build a tiny trie whose root has one full-name edge per export."""

    terminal = b"\x02\x00\x00\x00"  # payload size, flags, address, children
    encoded_names = [name.encode() for name in symbols]
    # These fixtures remain below 128 bytes, so every node offset is one ULEB.
    root_size = 2 + sum(len(name) + 2 for name in encoded_names)
    self_test_size = root_size + len(terminal) * len(symbols)
    if self_test_size >= 128:
        raise ValueError("test export trie unexpectedly requires multi-byte offsets")
    root = bytearray((0, len(symbols)))
    next_offset = root_size
    for name in encoded_names:
        root.extend(name)
        root.append(0)
        root.extend(_uleb128(next_offset))
        next_offset += len(terminal)
    return bytes(root) + terminal * len(symbols)


def _string_table(names: list[str]) -> tuple[bytes, list[int]]:
    data = bytearray(b"\0")
    offsets = []
    for name in names:
        offsets.append(len(data))
        data.extend(name.encode())
        data.append(0)
    return bytes(data), offsets


def _rich_macho64(
    *,
    legacy_exports: bool = False,
    malformed_dysymtab: bool = False,
) -> bytes:
    names = [
        "_local",
        "debug.c",
        "_$s4Test5localyyF",
        "_main",
        "_$s4Test6publicyyF",
        "_puts",
    ]
    strings, string_indexes = _string_table(names)
    symbols = b"".join(
        (
            struct.pack("<IBBHQ", string_indexes[0], 0x0E, 1, 0, 0x1000),
            struct.pack("<IBBHQ", string_indexes[1], 0x64, 1, 0, 0),
            struct.pack("<IBBHQ", string_indexes[2], 0x0E, 1, 0, 0x1010),
            struct.pack("<IBBHQ", string_indexes[3], 0x0F, 1, 0, 0x1020),
            struct.pack("<IBBHQ", string_indexes[4], 0x0F, 1, 0, 0x1030),
            struct.pack("<IBBHQ", string_indexes[5], 0x01, 0, 0, 0),
        )
    )
    exports = _flat_export_trie(
        ["_main", "_$s4Test6publicyyF", "__mh_execute_header"]
    )

    header_size = 32
    segment_size = 72 + 80
    symtab_size = 24
    dysymtab_size = 80
    export_command_size = 48 if legacy_exports else 16
    sizeofcmds = segment_size + symtab_size + dysymtab_size + export_command_size
    image_info_offset = header_size + sizeofcmds
    symbol_offset = image_info_offset + 8
    string_offset = symbol_offset + len(symbols)
    export_offset = string_offset + len(strings)
    file_size = export_offset + len(exports)

    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        2,
        4,
        sizeofcmds,
        0,
        0,
    )
    segment = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        segment_size,
        b"__DATA\0" + b"\0" * 9,
        0,
        file_size,
        0,
        file_size,
        7,
        3,
        1,
        0,
    )
    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__objc_imageinfo",
        b"__DATA\0" + b"\0" * 9,
        image_info_offset,
        8,
        image_info_offset,
        2,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    symtab = struct.pack(
        "<IIIIII",
        0x2,
        symtab_size,
        symbol_offset,
        len(names),
        string_offset,
        len(strings),
    )
    undefined_index = 99 if malformed_dysymtab else 5
    dysymtab_fields = [
        0xB,
        dysymtab_size,
        0,
        3,
        3,
        2,
        undefined_index,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
    dysymtab = struct.pack("<20I", *dysymtab_fields)
    if legacy_exports:
        export_command = struct.pack(
            "<12I",
            0x80000022,
            export_command_size,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            export_offset,
            len(exports),
        )
    else:
        export_command = struct.pack(
            "<IIII", 0x80000033, export_command_size, export_offset, len(exports)
        )
    image_info = struct.pack("<II", 0, 7 << 8)
    return (
        header
        + segment
        + section
        + symtab
        + dysymtab
        + export_command
        + image_info
        + symbols
        + strings
        + exports
    )


def _macho32_with_symbols() -> bytes:
    names = ["_local", "_main", "_puts"]
    strings, string_indexes = _string_table(names)
    header_size = 28
    sizeofcmds = 24 + 80
    symbol_offset = header_size + sizeofcmds
    symbols = b"".join(
        (
            struct.pack("<IBBHI", string_indexes[0], 0x0E, 1, 0, 0x1000),
            struct.pack("<IBBHI", string_indexes[1], 0x0F, 1, 0, 0x1010),
            struct.pack("<IBBHI", string_indexes[2], 0x01, 0, 0, 0),
        )
    )
    string_offset = symbol_offset + len(symbols)
    header = struct.pack(
        "<IiiIIII", 0xFEEDFACE, 12, 0, 2, 2, sizeofcmds, 0
    )
    symtab = struct.pack(
        "<IIIIII", 0x2, 24, symbol_offset, 3, string_offset, len(strings)
    )
    dysymtab = struct.pack(
        "<20I", 0xB, 80, 0, 1, 1, 1, 2, 1, *([0] * 12)
    )
    return header + symtab + dysymtab + symbols + strings


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(encoded),)) + encoded


def _der(tag: int, payload: bytes) -> bytes:
    return bytes((tag,)) + _der_length(len(payload)) + payload


def _der_integer(value: int) -> bytes:
    for length in range(1, 9):
        try:
            payload = value.to_bytes(length, "big", signed=True)
        except OverflowError:
            continue
        if length == 1 or not (
            (payload[0] == 0 and payload[1] < 0x80)
            or (payload[0] == 0xFF and payload[1] >= 0x80)
        ):
            return _der(0x02, payload)
    raise ValueError("integer does not fit in Apple's DER plist format")


def _der_value(value: object) -> bytes:
    if isinstance(value, bool):
        # Apple's encoder deliberately uses 0x01 rather than canonical 0xFF.
        return _der(0x01, bytes((int(value),)))
    if isinstance(value, int):
        return _der_integer(value)
    if isinstance(value, str):
        return _der(0x0C, value.encode())
    if isinstance(value, bytes):
        return _der(0x04, value)
    if value is None:
        return _der(0x05, b"")
    if isinstance(value, list):
        return _der(0x30, b"".join(_der_value(item) for item in value))
    if isinstance(value, dict):
        entries = []
        for key, item in value.items():
            entries.append(_der(0x30, _der_value(key) + _der_value(item)))
        return _der(0xB0, b"".join(entries))
    raise TypeError(f"unsupported test DER value: {value!r}")


def _der_entitlements(entitlements: dict[str, object]) -> bytes:
    return _der(0x70, _der_integer(1) + _der_value(entitlements))


def _signature_superblob(
    entitlements: dict[str, object],
    *,
    xml_payload: bytes | None = None,
    include_xml: bool = True,
    include_der: bool = True,
) -> bytes:
    blobs: list[tuple[int, bytes]] = []
    if include_xml:
        payload = xml_payload
        if payload is None:
            payload = plistlib.dumps(entitlements, fmt=plistlib.FMT_XML)
        blobs.append(
            (5, struct.pack(">II", 0xFADE7171, 8 + len(payload)) + payload)
        )
    if include_der:
        payload = _der_entitlements(entitlements)
        blobs.append(
            (7, struct.pack(">II", 0xFADE7172, 8 + len(payload)) + payload)
        )

    table_size = 12 + 8 * len(blobs)
    indexes = bytearray()
    body = bytearray()
    offset = table_size
    for slot, blob in blobs:
        indexes.extend(struct.pack(">II", slot, offset))
        body.extend(blob)
        offset += len(blob)
    return (
        struct.pack(">III", 0xFADE0CC0, offset, len(blobs))
        + bytes(indexes)
        + bytes(body)
    )


def _macho64_with_signature(signature: bytes) -> bytes:
    header_size = 32
    command_size = 16
    signature_offset = header_size + command_size
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        2,
        1,
        command_size,
        0,
        0,
    )
    command = struct.pack(
        "<IIII", 0x1D, command_size, signature_offset, len(signature)
    )
    return header + command + signature


def _rpath_command(
    payload: bytes,
    *,
    endian: str = "<",
    path_offset: int = 12,
    command_size: int | None = None,
) -> bytes:
    if command_size is None:
        command_size = 12 + len(payload)
    body_size = max(0, command_size - 12)
    return (
        struct.pack(endian + "III", 0x8000001C, command_size, path_offset)
        + payload[:body_size].ljust(body_size, b"X")
    )


def _macho64_with_commands(
    commands: list[bytes],
    *,
    endian: str = "<",
    cpu_type: int = 0x0100000C,
) -> bytes:
    command_data = b"".join(commands)
    header = struct.pack(
        endian + "IiiIIIII",
        0xFEEDFACF,
        cpu_type,
        0,
        2,
        len(commands),
        len(command_data),
        0,
        0,
    )
    return header + command_data


def _macho32_with_commands(commands: list[bytes]) -> bytes:
    command_data = b"".join(commands)
    header = struct.pack(
        "<IiiIIII",
        0xFEEDFACE,
        12,
        0,
        2,
        len(commands),
        len(command_data),
        0,
    )
    return header + command_data


def _name16(value: str) -> bytes:
    return value.encode("ascii").ljust(16, b"\0")


def _segment64_command(
    name: str,
    file_offset: int,
    file_size: int,
    sections: list[tuple[str, int, int]],
) -> bytes:
    command_size = 72 + 80 * len(sections)
    command = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        command_size,
        _name16(name),
        0,
        file_size,
        file_offset,
        file_size,
        7,
        5,
        len(sections),
        0,
    )
    return command + b"".join(
        struct.pack(
            "<16s16sQQIIIIIIII",
            _name16(section_name),
            _name16(name),
            section_offset,
            section_size,
            section_offset,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        for section_name, section_offset, section_size in sections
    )


def _segment32_command(
    name: str,
    file_offset: int,
    file_size: int,
    sections: list[tuple[str, int, int]],
) -> bytes:
    command_size = 56 + 68 * len(sections)
    command = struct.pack(
        "<II16sIIIIiiII",
        0x1,
        command_size,
        _name16(name),
        0,
        file_size,
        file_offset,
        file_size,
        7,
        5,
        len(sections),
        0,
    )
    return command + b"".join(
        struct.pack(
            "<16s16sIIIIIIIII",
            _name16(section_name),
            _name16(name),
            section_offset,
            section_size,
            section_offset,
            2,
            0,
            0,
            0,
            0,
            0,
        )
        for section_name, section_offset, section_size in sections
    )


def _pad_slice(data: bytes, size: int) -> bytes:
    if len(data) > size:
        raise ValueError("test Mach-O load commands exceed its declared slice")
    return data.ljust(size, b"\xA5")


class MachOTests(unittest.TestCase):
    def test_reads_deduplicated_rpaths_in_load_command_order(self) -> None:
        commands = [
            _rpath_command(b"@executable_path/Frameworks\0"),
            _rpath_command(b"@loader_path/../Frameworks\0"),
            _rpath_command(b"@executable_path/Frameworks\0"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "RPaths"
            path.write_bytes(_macho64_with_commands(commands))
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        self.assertEqual(
            info["architectures"][0]["rpaths"],
            ["@executable_path/Frameworks", "@loader_path/../Frameworks"],
        )

    def test_reads_big_endian_rpaths(self) -> None:
        command = _rpath_command(
            b"@loader_path/Frameworks\0", endian=">"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "BigEndianRPath"
            path.write_bytes(
                _macho64_with_commands(
                    [command], endian=">", cpu_type=0x01000007
                )
            )
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        architecture = info["architectures"][0]
        self.assertEqual(architecture["architecture"], "x86_64")
        self.assertEqual(architecture["rpaths"], ["@loader_path/Frameworks"])

    def test_skips_malformed_and_oversized_rpaths(self) -> None:
        commands = [
            struct.pack("<II", 0x8000001C, 8),
            _rpath_command(b"inside-header\0", path_offset=8),
            _rpath_command(b"past-command\0", path_offset=0xFFFFFFFF),
            _rpath_command(b"unterminated"),
            _rpath_command(b"\xff\0"),
            _rpath_command(b"x" * (MAX_RPATH_BYTES + 1) + b"\0"),
            _rpath_command(b"@executable_path/Frameworks\0"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "MalformedRPaths"
            path.write_bytes(_macho64_with_commands(commands))
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        self.assertEqual(
            info["architectures"][0]["rpaths"],
            ["@executable_path/Frameworks"],
        )

    def test_reads_rpaths_from_each_fat_slice(self) -> None:
        first = _macho64_with_commands(
            [_rpath_command(b"@executable_path/Frameworks\0")]
        )
        second = _macho64_with_commands(
            [_rpath_command(b"@loader_path/Frameworks\0", endian=">")],
            endian=">",
            cpu_type=0x01000007,
        )
        table_size = 8 + 2 * 20
        second_offset = table_size + len(first)
        fat = (
            struct.pack(">II", 0xCAFEBABE, 2)
            + struct.pack(">iiIII", 0x0100000C, 0, table_size, len(first), 0)
            + struct.pack(
                ">iiIII", 0x01000007, 0, second_offset, len(second), 0
            )
            + first
            + second
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "UniversalRPaths"
            path.write_bytes(fat)
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        self.assertEqual(
            [item["rpaths"] for item in info["architectures"]],
            [
                ["@executable_path/Frameworks"],
                ["@loader_path/Frameworks"],
            ],
        )

    def test_clamps_thin_segments_and_rejects_invalid_sections(self) -> None:
        segment = _segment64_command(
            "__DATA",
            0x240,
            0x100,
            [
                ("__first", 0x240, 0x20),
                ("__overlap", 0x250, 0x10),
                ("__before", 0x230, 0x10),
                ("__tail", 0x260, 0x80),
            ],
        )
        overlapping_segment = _segment64_command(
            "__INVALID", 0x260, 0x10, []
        )
        rpath = _rpath_command(b"@loader_path/Frameworks\0")
        thin = _pad_slice(
            _macho64_with_commands([segment, overlapping_segment, rpath]),
            0x280,
        )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "MalformedThin"
            path.write_bytes(thin)
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        architecture = info["architectures"][0]
        self.assertEqual(
            [(item["name"], item["size"]) for item in architecture["segments"]],
            [("__DATA", 0x40), ("__INVALID", 0)],
        )
        self.assertEqual(
            [
                (item["name"], item["size"])
                for item in architecture["segments"][0]["sections"]
            ],
            [("__first", 0x20), ("__tail", 0x20)],
        )
        self.assertEqual(architecture["unattributed_bytes"], 0x240)
        self.assertEqual(architecture["rpaths"], ["@loader_path/Frameworks"])

    def test_clamps_segments_to_each_fat_slice(self) -> None:
        malformed_slice = _pad_slice(
            _macho32_with_commands(
                [
                    _segment32_command(
                        "__DATA",
                        0x200,
                        0x100,
                        [
                            ("__first", 0x200, 0x20),
                            ("__overlap", 0x210, 0x10),
                            ("__before", 0x1F0, 0x10),
                            ("__tail", 0x220, 0x80),
                        ],
                    ),
                    _rpath_command(b"@loader_path/First\0"),
                ]
            ),
            0x240,
        )
        second_slice = _macho64_with_commands(
            [_rpath_command(b"@loader_path/Second\0")]
        )
        table_size = 8 + 2 * 20
        second_offset = table_size + len(malformed_slice)
        fat = (
            struct.pack(">II", 0xCAFEBABE, 2)
            + struct.pack(
                ">iiIII", 12, 0, table_size, len(malformed_slice), 0
            )
            + struct.pack(
                ">iiIII", 0x0100000C, 0, second_offset, len(second_slice), 0
            )
            + malformed_slice
            + second_slice
        )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "MalformedUniversal"
            path.write_bytes(fat)
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        self.assertTrue(info["is_fat"])
        first, second = info["architectures"]
        self.assertEqual(first["segments"][0]["size"], 0x40)
        self.assertEqual(
            [
                (item["name"], item["size"])
                for item in first["segments"][0]["sections"]
            ],
            [("__first", 0x20), ("__tail", 0x20)],
        )
        self.assertEqual(first["unattributed_bytes"], 0x200)
        self.assertEqual(first["rpaths"], ["@loader_path/First"])
        self.assertEqual(second["rpaths"], ["@loader_path/Second"])

    def test_parses_thin_arm64_sections_and_symbol_table(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "Example"
            write_macho(binary)
            self.assertTrue(is_macho(binary))
            info = parse_macho(binary)
            self.assertIsNotNone(info)
            assert info is not None
            self.assertFalse(info["is_fat"])
            architecture = info["architectures"][0]
            self.assertEqual(architecture["architecture"], "arm64")
            self.assertEqual(architecture["file_type"], "executable")
            self.assertEqual(architecture["symbol_table_bytes"], 46)
            self.assertEqual(architecture["segments"][0]["name"], "__TEXT")
            self.assertEqual(
                architecture["segments"][0]["sections"][0]["name"], "__text"
            )
            self.assertEqual(
                architecture["segments"][0]["sections"][0]["size"], 64
            )
            self.assertEqual(
                architecture["segments"][0]["sections"][0]["file_offset"],
                280,
            )
            self.assertEqual(architecture["segments"][1]["name"], "__LINKEDIT")
            self.assertEqual(architecture["symbol_table"]["entry_bytes"], 32)
            self.assertEqual(architecture["symbol_table"]["string_bytes"], 14)

    def test_records_chained_fixup_region(self) -> None:
        data_offset = 48
        data_size = 12
        command = struct.pack(
            "<IIII", 0x80000034, 16, data_offset, data_size
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Fixups"
            path.write_bytes(
                _macho64_with_commands([command]) + b"\xA5" * data_size
            )
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        self.assertEqual(
            info["architectures"][0]["fixup_regions"],
            [
                {
                    "source": "LC_DYLD_CHAINED_FIXUPS",
                    "offset": data_offset,
                    "size": data_size,
                    "valid": True,
                }
            ],
        )

    def test_rejects_non_macho(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "text"
            path.write_text("hello")
            self.assertFalse(is_macho(path))
            self.assertIsNone(parse_macho(path))

    def test_classifies_64_bit_symbols_and_export_trie(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Rich"
            path.write_bytes(_rich_macho64())
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        architecture = info["architectures"][0]
        self.assertTrue(architecture["is_64"])
        self.assertTrue(architecture["is_executable"])
        self.assertEqual(architecture["swift_abi_version"], 7)

        dynamic = architecture["dynamic_symbol_table"]
        self.assertTrue(dynamic["valid"])
        self.assertEqual(dynamic["local_count"], 3)
        self.assertEqual(dynamic["external_defined_count"], 2)
        self.assertEqual(dynamic["undefined_count"], 1)

        symbols = architecture["symbol_table"]
        self.assertTrue(symbols["valid"])
        self.assertEqual(symbols["parsed_count"], 6)
        self.assertEqual(symbols["classifications"]["local"]["count"], 3)
        self.assertEqual(
            symbols["classifications"]["external_defined"]["count"], 2
        )
        self.assertEqual(symbols["classifications"]["undefined"]["count"], 1)
        self.assertEqual(symbols["classifications"]["debug"]["count"], 1)
        self.assertEqual(symbols["classifications"]["swift"]["count"], 2)
        estimate = symbols["strip_rSTx"]
        self.assertTrue(estimate["is_estimate"])
        self.assertTrue(estimate["swift_eligible"])
        self.assertEqual(estimate["candidate_count"], 4)
        self.assertEqual(estimate["candidate_entry_bytes"], 64)
        self.assertEqual(estimate["retained_count"], 2)
        self.assertGreater(estimate["estimated_bytes"], 64)

        exports = architecture["export_trie"]
        self.assertTrue(exports["valid"])
        self.assertEqual(exports["source"], "LC_DYLD_EXPORTS_TRIE")
        self.assertEqual(exports["symbol_count"], 3)
        self.assertTrue(exports["has_main"])
        self.assertTrue(exports["has_mh_execute_header"])
        self.assertEqual(
            exports["symbols_sample"],
            ["_main", "_$s4Test6publicyyF", "__mh_execute_header"],
        )

    def test_classifies_32_bit_nlist_entries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Legacy"
            path.write_bytes(_macho32_with_symbols())
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        architecture = info["architectures"][0]
        self.assertFalse(architecture["is_64"])
        symbols = architecture["symbol_table"]
        self.assertTrue(symbols["valid"])
        self.assertEqual(symbols["entry_size"], 12)
        self.assertEqual(symbols["classifications"]["local"]["count"], 1)
        self.assertEqual(
            symbols["classifications"]["external_defined"]["count"], 1
        )
        self.assertEqual(symbols["classifications"]["undefined"]["count"], 1)

    def test_reads_legacy_dyld_info_export_trie(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "LegacyExports"
            path.write_bytes(_rich_macho64(legacy_exports=True))
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        exports = info["architectures"][0]["export_trie"]
        self.assertTrue(exports["valid"])
        self.assertEqual(exports["source"], "LC_DYLD_INFO_ONLY")
        self.assertEqual(exports["symbol_count"], 3)

    def test_parses_symbol_metadata_in_each_fat_slice(self) -> None:
        first = _rich_macho64()
        second = _rich_macho64(legacy_exports=True)
        table_size = 8 + 2 * 20
        second_offset = table_size + len(first)
        fat = (
            struct.pack(">II", 0xCAFEBABE, 2)
            + struct.pack(">iiIII", 0x0100000C, 0, table_size, len(first), 0)
            + struct.pack(
                ">iiIII", 0x0100000C, 0, second_offset, len(second), 0
            )
            + first
            + second
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Universal"
            path.write_bytes(fat)
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        self.assertTrue(info["is_fat"])
        self.assertEqual(len(info["architectures"]), 2)
        self.assertEqual(
            [item["export_trie"]["source"] for item in info["architectures"]],
            ["LC_DYLD_EXPORTS_TRIE", "LC_DYLD_INFO_ONLY"],
        )
        self.assertTrue(
            all(
                item["symbol_table"]["strip_rSTx"]["candidate_count"] == 4
                for item in info["architectures"]
            )
        )

    def test_invalid_dysymtab_falls_back_to_nlist_types(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "BadDynamicRanges"
            path.write_bytes(_rich_macho64(malformed_dysymtab=True))
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        architecture = info["architectures"][0]
        self.assertFalse(architecture["dynamic_symbol_table"]["valid"])
        symbols = architecture["symbol_table"]
        self.assertTrue(symbols["valid"])
        self.assertEqual(symbols["classifications"]["local"]["count"], 3)
        self.assertEqual(
            symbols["classifications"]["external_defined"]["count"], 2
        )
        self.assertEqual(symbols["classifications"]["undefined"]["count"], 1)

    def test_out_of_bounds_export_payload_is_reported_not_read(self) -> None:
        binary = bytearray(_rich_macho64())
        export_command_offset = 32 + (72 + 80) + 24 + 80
        struct.pack_into(
            "<I", binary, export_command_offset + 8, len(binary) + 4096
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "BadExports"
            path.write_bytes(binary)
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        exports = info["architectures"][0]["export_trie"]
        self.assertFalse(exports["valid"])
        self.assertEqual(exports["parse_error"], "invalid-or-oversized-trie")

    def test_oversized_symbol_count_is_reported_without_allocating(self) -> None:
        binary = bytearray(_rich_macho64())
        symbol_command_offset = 32 + (72 + 80)
        struct.pack_into("<I", binary, symbol_command_offset + 12, 0xFFFFFFFF)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "BadSymbols"
            path.write_bytes(binary)
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        architecture = info["architectures"][0]
        symbols = architecture["symbol_table"]
        self.assertFalse(symbols["valid"])
        self.assertEqual(symbols["parse_error"], "invalid-or-oversized-table")
        self.assertFalse(architecture["dynamic_symbol_table"]["valid"])

    def test_export_trie_rejects_overflow_cycles_and_truncation(self) -> None:
        overflow = parse_export_trie(b"\x80" * 10)
        self.assertTrue(overflow["malformed"])
        self.assertEqual(overflow["symbol_count"], 0)

        cycle = parse_export_trie(b"\x00\x01a\x00\x00")
        self.assertTrue(cycle["malformed"])
        self.assertEqual(cycle["visited_node_count"], 1)

        valid = _flat_export_trie(["_main"])
        truncated = parse_export_trie(valid, max_nodes=1)
        self.assertTrue(truncated["truncated"])

        trailing = parse_export_trie(valid + b"not-part-of-the-trie")
        self.assertTrue(trailing["nonzero_trailing_bytes"])
        self.assertGreater(trailing["trailing_byte_count"], 0)
        self.assertFalse(truncated["malformed"])
        self.assertEqual(truncated["symbol_count"], 0)

    def test_reads_matching_xml_and_der_code_signature_entitlements(self) -> None:
        expected = {
            "application-identifier": "TEAM.com.example.app",
            "aps-environment": "production",
            "com.apple.developer.associated-domains": [
                "applinks:example.com",
                "webcredentials:example.com",
            ],
            "com.apple.developer.networking.multicast": True,
            "number": 42,
        }
        binary_data = _macho64_with_signature(_signature_superblob(expected))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Signed"
            path.write_bytes(binary_data)
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        architecture = info["architectures"][0]
        self.assertEqual(architecture["entitlements"], expected)
        self.assertEqual(architecture["entitlements_source"], "xml")
        self.assertEqual(info["entitlements"], [expected])
        signature = architecture["code_signature"]
        self.assertEqual(signature["entitlements_formats"], ["xml", "der"])
        self.assertTrue(signature["entitlements_match"])

    def test_uses_der_when_xml_entitlements_are_malformed(self) -> None:
        expected = {
            "application-identifier": "TEAM.com.example.app",
            "enabled": True,
        }
        signature = _signature_superblob(
            expected, xml_payload=b"not a property list"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "DERFallback"
            path.write_bytes(_macho64_with_signature(signature))
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        architecture = info["architectures"][0]
        self.assertEqual(architecture["entitlements"], expected)
        self.assertEqual(architecture["entitlements_source"], "der")
        code_signature = architecture["code_signature"]
        self.assertEqual(code_signature["entitlements_formats"], ["der"])
        self.assertEqual(
            code_signature["entitlements_errors"], {"xml": "invalid-plist"}
        )

    def test_rejects_malformed_code_signature_superblob_bounds(self) -> None:
        expected = {"application-identifier": "TEAM.com.example.app"}
        valid = _signature_superblob(expected)
        cases: list[tuple[str, bytearray, str]] = []

        bad_count = bytearray(valid)
        struct.pack_into(">I", bad_count, 8, 0xFFFFFFFF)
        cases.append(("count", bad_count, "invalid-superblob-bounds"))

        bad_index = bytearray(valid)
        struct.pack_into(">I", bad_index, 16, 0xFFFFFFFF)
        cases.append(("index", bad_index, "invalid-superblob-index"))

        bad_blob = bytearray(valid)
        first_blob_offset = struct.unpack_from(">I", bad_blob, 16)[0]
        struct.pack_into(">I", bad_blob, first_blob_offset + 4, 0xFFFFFFFF)
        cases.append(("blob", bad_blob, "invalid-code-signature-blob"))

        for label, signature, parse_error in cases:
            with self.subTest(label=label):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "Malformed"
                    path.write_bytes(_macho64_with_signature(bytes(signature)))
                    info = parse_macho(path)

                self.assertIsNotNone(info)
                assert info is not None
                architecture = info["architectures"][0]
                self.assertIsNone(architecture["entitlements"])
                self.assertEqual(
                    architecture["code_signature"]["parse_error"], parse_error
                )

    def test_fat_macho_deduplicates_entitlements_across_slices(self) -> None:
        expected = {
            "application-identifier": "TEAM.com.example.universal",
            "enabled": True,
        }
        first = _macho64_with_signature(_signature_superblob(expected))
        second = _macho64_with_signature(
            _signature_superblob(expected, include_xml=False)
        )
        table_size = 8 + 2 * 20
        second_offset = table_size + len(first)
        fat = (
            struct.pack(">II", 0xCAFEBABE, 2)
            + struct.pack(">iiIII", 0x0100000C, 0, table_size, len(first), 0)
            + struct.pack(
                ">iiIII", 0x0100000C, 0, second_offset, len(second), 0
            )
            + first
            + second
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "UniversalSigned"
            path.write_bytes(fat)
            info = parse_macho(path)

        self.assertIsNotNone(info)
        assert info is not None
        self.assertEqual(info["entitlements"], [expected])
        self.assertEqual(
            [item["entitlements_source"] for item in info["architectures"]],
            ["xml", "der"],
        )

    def test_der_entitlements_rejects_noncanonical_and_trailing_data(self) -> None:
        valid = _der_entitlements({"enabled": True})
        self.assertEqual(parse_der_entitlements(valid), {"enabled": True})
        self.assertIsNone(parse_der_entitlements(valid + b"\0"))
        self.assertIsNone(parse_der_entitlements(b"\x70\x80"))


if __name__ == "__main__":
    unittest.main()
