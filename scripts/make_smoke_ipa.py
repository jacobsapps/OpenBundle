#!/usr/bin/env python3
"""Create a tiny deterministic IPA for the end-to-end browser smoke test."""

from __future__ import annotations

from argparse import ArgumentParser
from pathlib import Path
import hashlib
import json
import plistlib
import struct
import sys
import tempfile
import zipfile
import zlib


def _write_macho(path: Path) -> None:
    """Write a minimal arm64 Mach-O with text and linkedit metadata."""

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


def _deterministic_bytes(length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(f"openbundle-smoke-{counter}".encode()).digest())
        counter += 1
    return bytes(output[:length])


def _png(width: int = 48, height: int = 48) -> bytes:
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            rows.extend(((x * 5) % 256, (y * 7) % 256, ((x + y) * 3) % 256, 255))

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(bytes(rows), level=6))
        + chunk(b"IEND", b"")
    )


def build(output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="openbundle-smoke-") as directory:
        root = Path(directory)
        app = root / "Payload" / "Smoke.app"
        resources = app / "Resources"
        resources.mkdir(parents=True)
        with (app / "Info.plist").open("wb") as handle:
            plistlib.dump(
                {
                    "CFBundleDisplayName": "OpenBundle Smoke",
                    "CFBundleName": "OpenBundle Smoke",
                    "CFBundleIdentifier": "com.jacobstechtavern.openbundle.smoke",
                    "CFBundleShortVersionString": "1.0",
                    "CFBundleVersion": "1",
                    "CFBundleExecutable": "Smoke",
                    "MinimumOSVersion": "15.0",
                },
                handle,
            )
        _write_macho(app / "Smoke")
        repeated = _deterministic_bytes(180_000)
        (resources / "first.data").write_bytes(repeated)
        (resources / "second.data").write_bytes(repeated)
        (resources / "preview.png").write_bytes(_png())

        with zipfile.ZipFile(
            output,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=6,
        ) as archive:
            for source in sorted((root / "Payload").rglob("*")):
                if source.is_file():
                    entry = zipfile.ZipInfo(
                        source.relative_to(root).as_posix(),
                        date_time=(2026, 1, 1, 0, 0, 0),
                    )
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    entry.create_system = 3
                    mode = 0o100755 if source.name == "Smoke" else 0o100644
                    entry.external_attr = mode << 16
                    archive.writestr(entry, source.read_bytes(), compresslevel=6)


def write_reports(ipa: Path, json_output: Path, html_output: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "src"))
    from openbundle.analyzer import BundleAnalyzer
    from openbundle.report import render_report_html

    report = BundleAnalyzer().analyze(ipa)
    json_output.parent.mkdir(parents=True, exist_ok=True)
    html_output.parent.mkdir(parents=True, exist_ok=True)
    json_output.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
    html_output.write_text(render_report_html(report), encoding="utf-8")


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--report-json", type=Path)
    parser.add_argument("--report-html", type=Path)
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if bool(args.report_json) != bool(args.report_html):
        parser.error("--report-json and --report-html must be used together")
    build(output)
    if args.report_json and args.report_html:
        write_reports(
            output,
            args.report_json.expanduser().resolve(),
            args.report_html.expanduser().resolve(),
        )
    print(output)


if __name__ == "__main__":
    main()
