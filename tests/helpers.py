from __future__ import annotations

from pathlib import Path
import plistlib
import struct


def write_macho(path: Path) -> None:
    """Write a tiny arm64 Mach-O with separate text and linkedit regions."""

    header_size = 32
    text_segment_command_size = 72 + 80
    linkedit_segment_command_size = 72
    symbol_command_size = 24
    command_size = (
        text_segment_command_size
        + linkedit_segment_command_size
        + symbol_command_size
    )
    section_offset = header_size + command_size
    text_size = section_offset + 64
    symbol_names = b"\0_main\0_local\0"
    symbol_records = b"".join(
        (
            struct.pack("<IBBHQ", 1, 0x0F, 1, 0, section_offset),
            struct.pack("<IBBHQ", 7, 0x0E, 1, 0, section_offset + 16),
        )
    )
    symbol_offset = text_size
    string_offset = symbol_offset + len(symbol_records)
    linkedit_size = len(symbol_records) + len(symbol_names)
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        2,
        3,
        command_size,
        0,
        0,
    )
    text_segment = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        text_segment_command_size,
        b"__TEXT\0" + b"\0" * 9,
        0,
        text_size,
        0,
        text_size,
        7,
        5,
        1,
        0,
    )
    section = struct.pack(
        "<16s16sQQIIIIIIII",
        b"__text\0" + b"\0" * 9,
        b"__TEXT\0" + b"\0" * 9,
        section_offset,
        64,
        section_offset,
        2,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    linkedit_segment = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        linkedit_segment_command_size,
        b"__LINKEDIT\0" + b"\0" * 5,
        text_size,
        linkedit_size,
        text_size,
        linkedit_size,
        7,
        1,
        0,
        0,
    )
    symbols = struct.pack(
        "<IIIIII",
        0x2,
        symbol_command_size,
        symbol_offset,
        2,
        string_offset,
        len(symbol_names),
    )
    path.write_bytes(
        header
        + text_segment
        + section
        + linkedit_segment
        + symbols
        + b"\xAA" * 64
        + symbol_records
        + symbol_names
    )
    path.chmod(0o755)


def make_app(root: Path, small_file_count: int = 0) -> Path:
    app = root / "Test.app"
    (app / "Frameworks" / "Feature.framework").mkdir(parents=True)
    (app / "Resources").mkdir()
    info = {
        "CFBundleDisplayName": "Test App",
        "CFBundleName": "Test App",
        "CFBundleIdentifier": "com.example.test",
        "CFBundleShortVersionString": "1.0",
        "CFBundleVersion": "7",
        "CFBundleExecutable": "Test",
        "MinimumOSVersion": "15.0",
    }
    with (app / "Info.plist").open("wb") as handle:
        plistlib.dump(info, handle)
    write_macho(app / "Test")
    duplicate = b"same resource bytes" * 200
    (app / "Resources" / "one.dat").write_bytes(duplicate)
    (app / "Frameworks" / "Feature.framework" / "two.dat").write_bytes(duplicate)
    (app / "README.md").write_text("This should not ship.\n")
    for index in range(small_file_count):
        (app / "Resources" / f"tiny-{index}.json").write_text("{}")
    return app
