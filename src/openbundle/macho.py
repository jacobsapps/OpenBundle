"""Small, dependency-free Mach-O reader used for bundle attribution.

This intentionally reads only the load commands needed for size analysis. It
does not attempt to disassemble code or modify the binary.
"""

from __future__ import annotations

from pathlib import Path
import struct
from typing import Any, BinaryIO


MH_MAGIC = b"\xce\xfa\xed\xfe"
MH_CIGAM = b"\xfe\xed\xfa\xce"
MH_MAGIC_64 = b"\xcf\xfa\xed\xfe"
MH_CIGAM_64 = b"\xfe\xed\xfa\xcf"
FAT_MAGIC = b"\xca\xfe\xba\xbe"
FAT_CIGAM = b"\xbe\xba\xfe\xca"
FAT_MAGIC_64 = b"\xca\xfe\xba\xbf"
FAT_CIGAM_64 = b"\xbf\xba\xfe\xca"

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LAZY_LOAD_DYLIB = 0x20
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_BUILD_VERSION = 0x32

FILE_TYPES = {
    0x1: "object",
    0x2: "executable",
    0x3: "fixed-vm-library",
    0x4: "core",
    0x5: "preload",
    0x6: "dynamic-library",
    0x7: "dynamic-linker",
    0x8: "bundle",
    0x9: "dynamic-library-stub",
    0xA: "dSYM",
    0xB: "kext",
}

PLATFORMS = {
    1: "macOS",
    2: "iOS",
    3: "tvOS",
    4: "watchOS",
    5: "bridgeOS",
    6: "Mac Catalyst",
    7: "iOS Simulator",
    8: "tvOS Simulator",
    9: "watchOS Simulator",
    10: "DriverKit",
    11: "visionOS",
    12: "visionOS Simulator",
}

ZEROFILL_TYPES = {0x1, 0xC, 0x12}


def _version(value: int) -> str:
    return f"{value >> 16}.{(value >> 8) & 0xFF}.{value & 0xFF}"


def _arch_name(cpu_type: int, cpu_subtype: int) -> str:
    subtype = cpu_subtype & 0x00FFFFFF
    names = {
        7: "i386",
        0x01000007: "x86_64",
        12: "arm",
        0x0100000C: "arm64",
        0x0200000C: "arm64_32",
        18: "ppc",
        0x01000012: "ppc64",
    }
    name = names.get(cpu_type, f"cpu-{cpu_type:#x}")
    if cpu_type == 0x0100000C and subtype == 2:
        return "arm64e"
    return name


def is_macho(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            magic = handle.read(4)
        return magic in {
            MH_MAGIC,
            MH_CIGAM,
            MH_MAGIC_64,
            MH_CIGAM_64,
            FAT_MAGIC,
            FAT_CIGAM,
            FAT_MAGIC_64,
            FAT_CIGAM_64,
        }
    except OSError:
        return False


def _read_at(handle: BinaryIO, offset: int, count: int) -> bytes:
    handle.seek(offset)
    return handle.read(count)


def _cstring(data: bytes) -> str:
    return data.split(b"\0", 1)[0].decode("utf-8", "replace")


def _thin_slice(
    handle: BinaryIO, slice_offset: int, slice_size: int
) -> dict[str, Any] | None:
    magic = _read_at(handle, slice_offset, 4)
    if magic in {MH_MAGIC, MH_MAGIC_64}:
        endian = "<"
    elif magic in {MH_CIGAM, MH_CIGAM_64}:
        endian = ">"
    else:
        return None

    is_64 = magic in {MH_MAGIC_64, MH_CIGAM_64}
    header_size = 32 if is_64 else 28
    header = _read_at(handle, slice_offset, header_size)
    if len(header) != header_size:
        return None

    if is_64:
        (
            _,
            cpu_type,
            cpu_subtype,
            file_type,
            ncmds,
            sizeofcmds,
            flags,
            _,
        ) = struct.unpack(endian + "IiiIIIII", header)
    else:
        (
            _,
            cpu_type,
            cpu_subtype,
            file_type,
            ncmds,
            sizeofcmds,
            flags,
        ) = struct.unpack(endian + "IiiIIII", header)

    # Corrupt binaries should not be able to make us allocate arbitrary memory.
    if sizeofcmds > min(slice_size, 64 * 1024 * 1024) or ncmds > 100_000:
        return None
    commands = _read_at(handle, slice_offset + header_size, sizeofcmds)

    segments: list[dict[str, Any]] = []
    dependencies: list[str] = []
    symbol_bytes = 0
    encrypted = False
    uuid = None
    platform = None
    minimum_os = None
    sdk = None
    cursor = 0

    for _ in range(ncmds):
        if cursor + 8 > len(commands):
            break
        command, command_size = struct.unpack_from(endian + "II", commands, cursor)
        if command_size < 8 or cursor + command_size > len(commands):
            break

        if command == LC_SEGMENT_64 and command_size >= 72:
            fields = struct.unpack_from(endian + "II16sQQQQiiII", commands, cursor)
            (
                _,
                _,
                segment_name,
                _,
                virtual_size,
                file_offset,
                file_size,
                _,
                _,
                section_count,
                _,
            ) = fields
            section_cursor = cursor + 72
            sections: list[dict[str, Any]] = []
            for _ in range(section_count):
                if section_cursor + 80 > cursor + command_size:
                    break
                section = struct.unpack_from(
                    endian + "16s16sQQIIIIIIII", commands, section_cursor
                )
                (
                    section_name,
                    section_segment,
                    _,
                    section_size,
                    section_offset,
                    _,
                    _,
                    _,
                    section_flags,
                    _,
                    _,
                    _,
                ) = section
                original_size = section_size
                disk_backed = (
                    (section_flags & 0xFF) not in ZEROFILL_TYPES
                    and section_offset > 0
                    and section_offset < slice_size
                )
                if disk_backed:
                    section_size = min(section_size, slice_size - section_offset)
                else:
                    section_size = 0
                sections.append(
                    {
                        "name": _cstring(section_name),
                        "segment": _cstring(section_segment),
                        "size": int(section_size),
                        "virtual_size": int(original_size),
                    }
                )
                section_cursor += 80
            segments.append(
                {
                    "name": _cstring(segment_name),
                    "size": int(min(file_size, slice_size)),
                    "virtual_size": int(virtual_size),
                    "file_offset": int(file_offset),
                    "sections": sections,
                }
            )

        elif command == LC_SEGMENT and command_size >= 56:
            fields = struct.unpack_from(endian + "II16sIIIIiiII", commands, cursor)
            (
                _,
                _,
                segment_name,
                _,
                virtual_size,
                file_offset,
                file_size,
                _,
                _,
                section_count,
                _,
            ) = fields
            section_cursor = cursor + 56
            sections = []
            for _ in range(section_count):
                if section_cursor + 68 > cursor + command_size:
                    break
                section = struct.unpack_from(
                    endian + "16s16sIIIIIIIII", commands, section_cursor
                )
                section_size = section[3]
                section_offset = section[4]
                section_flags = section[8]
                disk_backed = (
                    (section_flags & 0xFF) not in ZEROFILL_TYPES
                    and section_offset > 0
                    and section_offset < slice_size
                )
                if disk_backed:
                    section_size = min(section_size, slice_size - section_offset)
                else:
                    section_size = 0
                sections.append(
                    {
                        "name": _cstring(section[0]),
                        "segment": _cstring(section[1]),
                        "size": int(section_size),
                        "virtual_size": int(section[3]),
                    }
                )
                section_cursor += 68
            segments.append(
                {
                    "name": _cstring(segment_name),
                    "size": int(min(file_size, slice_size)),
                    "virtual_size": int(virtual_size),
                    "file_offset": int(file_offset),
                    "sections": sections,
                }
            )

        elif command == LC_SYMTAB and command_size >= 24:
            _, _, _, symbol_count, _, string_size = struct.unpack_from(
                endian + "IIIIII", commands, cursor
            )
            symbol_bytes = int(symbol_count * (16 if is_64 else 12) + string_size)

        elif command in {
            LC_LOAD_DYLIB,
            LC_ID_DYLIB,
            LC_LOAD_WEAK_DYLIB,
            LC_REEXPORT_DYLIB,
            LC_LAZY_LOAD_DYLIB,
            LC_LOAD_UPWARD_DYLIB,
        }:
            if command_size >= 24:
                name_offset = struct.unpack_from(endian + "I", commands, cursor + 8)[0]
                if 0 < name_offset < command_size:
                    name = _cstring(commands[cursor + name_offset : cursor + command_size])
                    if name and command != LC_ID_DYLIB:
                        dependencies.append(name)

        elif command == LC_UUID and command_size >= 24:
            raw_uuid = commands[cursor + 8 : cursor + 24].hex().upper()
            uuid = "-".join(
                (
                    raw_uuid[0:8],
                    raw_uuid[8:12],
                    raw_uuid[12:16],
                    raw_uuid[16:20],
                    raw_uuid[20:32],
                )
            )

        elif command in {LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64}:
            if command_size >= 20:
                crypt_id = struct.unpack_from(endian + "I", commands, cursor + 16)[0]
                encrypted = encrypted or crypt_id != 0

        elif command == LC_BUILD_VERSION and command_size >= 24:
            _, _, platform_id, min_os, sdk_value, _ = struct.unpack_from(
                endian + "IIIIII", commands, cursor
            )
            platform = PLATFORMS.get(platform_id, f"platform-{platform_id}")
            minimum_os = _version(min_os)
            sdk = _version(sdk_value)

        cursor += command_size

    represented = sum(min(segment["size"], slice_size) for segment in segments)
    return {
        "architecture": _arch_name(cpu_type, cpu_subtype),
        "cpu_type": cpu_type,
        "cpu_subtype": cpu_subtype,
        "file_type": FILE_TYPES.get(file_type, f"type-{file_type}"),
        "file_type_id": file_type,
        "flags": flags,
        "size": int(slice_size),
        "segments": segments,
        "dependencies": sorted(set(dependencies)),
        "symbol_table_bytes": symbol_bytes,
        "encrypted": encrypted,
        "uuid": uuid,
        "platform": platform,
        "minimum_os": minimum_os,
        "sdk": sdk,
        "unattributed_bytes": max(0, int(slice_size - min(represented, slice_size))),
    }


def parse_macho(path: Path) -> dict[str, Any] | None:
    """Return a JSON-serializable description, or ``None`` for non Mach-O."""

    try:
        file_size = path.stat().st_size
        with path.open("rb") as handle:
            magic = handle.read(4)
            if magic in {MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64}:
                slice_info = _thin_slice(handle, 0, file_size)
                if not slice_info:
                    return None
                return {
                    "is_fat": False,
                    "size": file_size,
                    "architectures": [slice_info],
                }

            if magic not in {FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64}:
                return None

            is_64 = magic in {FAT_MAGIC_64, FAT_CIGAM_64}
            endian = ">" if magic in {FAT_MAGIC, FAT_MAGIC_64} else "<"
            count_data = handle.read(4)
            if len(count_data) != 4:
                return None
            architecture_count = struct.unpack(endian + "I", count_data)[0]
            if architecture_count > 1000:
                return None

            entry_size = 32 if is_64 else 20
            entries = handle.read(architecture_count * entry_size)
            slices: list[dict[str, Any]] = []
            for index in range(architecture_count):
                offset = index * entry_size
                if is_64:
                    (
                        _,
                        _,
                        slice_offset,
                        slice_size,
                        _,
                        _,
                    ) = struct.unpack_from(endian + "iiQQII", entries, offset)
                else:
                    (
                        _,
                        _,
                        slice_offset,
                        slice_size,
                        _,
                    ) = struct.unpack_from(endian + "iiIII", entries, offset)
                if slice_offset >= file_size or slice_size > file_size - slice_offset:
                    continue
                info = _thin_slice(handle, int(slice_offset), int(slice_size))
                if info:
                    info["file_offset"] = int(slice_offset)
                    slices.append(info)

            if not slices:
                return None
            return {
                "is_fat": True,
                "size": file_size,
                "architectures": slices,
                "container_overhead": max(
                    0, file_size - sum(item["size"] for item in slices)
                ),
            }
    except (OSError, struct.error, ValueError):
        return None

