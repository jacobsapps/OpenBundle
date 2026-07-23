from __future__ import annotations

from pathlib import Path
import plistlib
import struct


def write_macho(path: Path) -> None:
    """Write a tiny, structurally valid arm64 Mach-O for parser tests."""

    header_size = 32
    segment_command_size = 72 + 80
    symbol_command_size = 24
    command_size = segment_command_size + symbol_command_size
    section_offset = header_size + command_size
    file_size = section_offset + 64
    header = struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        2,
        2,
        command_size,
        0,
        0,
    )
    segment = struct.pack(
        "<II16sQQQQiiII",
        0x19,
        segment_command_size,
        b"__TEXT\0" + b"\0" * 9,
        0,
        file_size,
        0,
        file_size,
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
    symbols = struct.pack("<IIIIII", 0x2, 24, 0, 10, 0, 100)
    path.write_bytes(header + segment + section + symbols + b"\xAA" * 64)
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

