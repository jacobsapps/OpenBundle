"""Small, dependency-free Mach-O reader used for bundle attribution.

The reader deliberately stays on the metadata side of the Mach-O format: it
does not disassemble or modify binaries.  Apart from segment attribution it
understands enough of the static/dynamic symbol tables and dyld export trie to
produce portable bundle-size diagnostics in environments where Apple's
``strip`` and ``nm`` tools are unavailable (notably the browser build).

All file-derived counts and offsets are treated as hostile input.  Ranges are
checked against the current thin slice, and potentially large tables have
explicit parsing limits.  The original load-command sizes are still reported
when a table is too large or malformed, but detailed metadata is marked
invalid rather than being partially trusted.
"""

from __future__ import annotations

import base64
from datetime import datetime
import math
from pathlib import Path
import plistlib
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
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LAZY_LOAD_DYLIB = 0x20
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1B
LC_RPATH = 0x8000001C
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
LC_ENCRYPTION_INFO_64 = 0x2C
LC_BUILD_VERSION = 0x32
LC_DYLD_EXPORTS_TRIE = 0x80000033

MH_EXECUTE = 0x2

N_STAB = 0xE0
N_TYPE = 0x0E
N_EXT = 0x01
N_UNDF = 0x0
N_PBUD = 0xC
REFERENCED_DYNAMICALLY = 0x10

EXPORT_SYMBOL_FLAGS_REEXPORT = 0x08
EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10

MAX_SYMBOL_COUNT = 1_000_000
MAX_STRING_TABLE_BYTES = 128 * 1024 * 1024
MAX_SYMBOL_TABLE_BYTES = 128 * 1024 * 1024
MAX_EXPORT_TRIE_BYTES = 64 * 1024 * 1024
MAX_EXPORT_TRIE_NODES = 250_000
MAX_EXPORT_SYMBOL_BYTES = 16 * 1024
SYMBOL_SAMPLE_LIMIT = 12
MAX_RPATH_BYTES = 16 * 1024
MAX_RPATH_COUNT = 4096

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_DETACHED_SIGNATURE = 0xFADE0CC1
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172
CSSLOT_ENTITLEMENTS = 5
CSSLOT_DER_ENTITLEMENTS = 7

MAX_CODE_SIGNATURE_BYTES = 64 * 1024 * 1024
MAX_CODE_SIGNATURE_BLOBS = 4096
MAX_ENTITLEMENTS_BYTES = 4 * 1024 * 1024
MAX_ENTITLEMENTS_DEPTH = 32
MAX_ENTITLEMENTS_VALUES = 50_000

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


def _range_is_valid(offset: int, size: int, container_size: int) -> bool:
    """Return whether ``[offset, offset + size)`` is inside a slice.

    Written without adding first so the same check is safe in languages with
    fixed-width integers when this parser is eventually mirrored or compiled.
    """

    return offset >= 0 and size >= 0 and offset <= container_size and size <= (
        container_size - offset
    )


def _claim_bounded_file_range(
    offset: int,
    size: int,
    owner_offset: int,
    owner_size: int,
    claimed: list[tuple[int, int]],
) -> int | None:
    """Claim a non-overlapping file range inside an owning range.

    Mach-O offsets and sizes are untrusted unsigned integers.  A range may be
    truncated at the owner's end, but a range that starts outside its owner or
    overlaps an earlier claim is invalid.  Empty in-bounds ranges are retained
    as zero-sized metadata and do not occupy file bytes.
    """

    if size < 0 or owner_size < 0:
        return None
    owner_end = owner_offset + owner_size
    if offset < owner_offset or offset > owner_end:
        return None
    if size == 0:
        return 0
    if offset == owner_end:
        return None

    bounded_size = min(size, owner_end - offset)
    end = offset + bounded_size
    if any(
        offset < claimed_end and claimed_start < end
        for claimed_start, claimed_end in claimed
    ):
        return None
    claimed.append((offset, end))
    return bounded_size


def _read_slice_range(
    handle: BinaryIO,
    slice_offset: int,
    slice_size: int,
    relative_offset: int,
    count: int,
    *,
    maximum: int | None = None,
) -> bytes | None:
    if not _range_is_valid(relative_offset, count, slice_size):
        return None
    if maximum is not None and count > maximum:
        return None
    data = _read_at(handle, slice_offset + relative_offset, count)
    return data if len(data) == count else None


class _EntitlementsParseError(ValueError):
    """Raised internally when an entitlements payload is not safely usable."""


def _normalise_entitlements(
    value: Any,
    *,
    depth: int = 0,
    budget: list[int] | None = None,
) -> Any:
    """Return a bounded, JSON-serializable property-list value."""

    if budget is None:
        budget = [MAX_ENTITLEMENTS_VALUES]
    if depth > MAX_ENTITLEMENTS_DEPTH or budget[0] <= 0:
        raise _EntitlementsParseError("entitlements-complexity-limit")
    budget[0] -= 1

    if value is None or isinstance(value, (bool, str, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _EntitlementsParseError("non-finite-number")
        return value
    if isinstance(value, bytes):
        return {"$base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds") + (
            "Z" if value.tzinfo is None else ""
        )
    if isinstance(value, (list, tuple)):
        return [
            _normalise_entitlements(item, depth=depth + 1, budget=budget)
            for item in value
        ]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str) or key in result:
                raise _EntitlementsParseError("invalid-dictionary-key")
            result[key] = _normalise_entitlements(
                item, depth=depth + 1, budget=budget
            )
        return result
    raise _EntitlementsParseError("unsupported-entitlements-value")


class _DEREntitlementsDecoder:
    """Bounded decoder for Apple's DER property-list entitlements format."""

    def __init__(self, data: bytes):
        self.data = data
        self.values_remaining = MAX_ENTITLEMENTS_VALUES

    def _take_value(self, depth: int) -> None:
        if depth > MAX_ENTITLEMENTS_DEPTH or self.values_remaining <= 0:
            raise _EntitlementsParseError("der-complexity-limit")
        self.values_remaining -= 1

    def _tlv(self, cursor: int, end: int) -> tuple[int, int, int, int]:
        if cursor >= end:
            raise _EntitlementsParseError("truncated-der-tag")
        tag = self.data[cursor]
        cursor += 1
        # Apple uses single-octet tags for every property-list type, including
        # the application/context-specific CoreEntitlements wrappers.
        if tag & 0x1F == 0x1F:
            raise _EntitlementsParseError("unsupported-der-tag")
        if cursor >= end:
            raise _EntitlementsParseError("truncated-der-length")
        first = self.data[cursor]
        cursor += 1
        if first & 0x80:
            octets = first & 0x7F
            if octets == 0 or octets > 4 or octets > end - cursor:
                raise _EntitlementsParseError("invalid-der-length")
            if self.data[cursor] == 0:
                raise _EntitlementsParseError("noncanonical-der-length")
            length = int.from_bytes(self.data[cursor : cursor + octets], "big")
            cursor += octets
            if length < 0x80:
                raise _EntitlementsParseError("noncanonical-der-length")
        else:
            length = first
        if length > end - cursor:
            raise _EntitlementsParseError("truncated-der-value")
        return tag, cursor, cursor + length, cursor + length

    def _dictionary(self, start: int, end: int, depth: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        cursor = start
        while cursor < end:
            entry_tag, entry_start, entry_end, cursor = self._tlv(cursor, end)
            if entry_tag != 0x30:
                raise _EntitlementsParseError("invalid-der-dictionary-entry")
            key, entry_cursor = self._value(entry_start, entry_end, depth + 1)
            value, entry_cursor = self._value(
                entry_cursor, entry_end, depth + 1
            )
            if entry_cursor != entry_end or not isinstance(key, str):
                raise _EntitlementsParseError("invalid-der-dictionary-entry")
            if key in result:
                raise _EntitlementsParseError("duplicate-der-dictionary-key")
            result[key] = value
        if cursor != end:
            raise _EntitlementsParseError("truncated-der-dictionary")
        return result

    def _collection(self, start: int, end: int, depth: int) -> list[Any]:
        result: list[Any] = []
        cursor = start
        while cursor < end:
            value, cursor = self._value(cursor, end, depth + 1)
            result.append(value)
        if cursor != end:
            raise _EntitlementsParseError("truncated-der-collection")
        return result

    def _value(self, cursor: int, end: int, depth: int) -> tuple[Any, int]:
        self._take_value(depth)
        tag, start, payload_end, next_cursor = self._tlv(cursor, end)
        payload = self.data[start:payload_end]

        if tag == 0x01:  # BOOLEAN
            # Apple's encoder writes 0x01 for true even though canonical DER
            # uses 0xFF; its decoder intentionally accepts either form.
            if len(payload) != 1:
                raise _EntitlementsParseError("invalid-der-boolean")
            return payload[0] != 0, next_cursor
        if tag == 0x02:  # INTEGER / CFNumber
            if not 1 <= len(payload) <= 8:
                raise _EntitlementsParseError("invalid-der-integer")
            if len(payload) > 1 and (
                (payload[0] == 0 and payload[1] < 0x80)
                or (payload[0] == 0xFF and payload[1] >= 0x80)
            ):
                raise _EntitlementsParseError("noncanonical-der-integer")
            return int.from_bytes(payload, "big", signed=True), next_cursor
        if tag == 0x04:  # OCTET STRING / CFData
            return {"$base64": base64.b64encode(payload).decode("ascii")}, next_cursor
        if tag == 0x05:  # NULL
            if payload:
                raise _EntitlementsParseError("invalid-der-null")
            return None, next_cursor
        if tag == 0x0C:  # UTF8 STRING
            try:
                return payload.decode("utf-8", "strict"), next_cursor
            except UnicodeDecodeError as error:
                raise _EntitlementsParseError("invalid-der-string") from error
        if tag == 0x12:  # NUMERIC STRING
            try:
                value = payload.decode("ascii", "strict")
            except UnicodeDecodeError as error:
                raise _EntitlementsParseError("invalid-der-string") from error
            if any(character not in " 0123456789" for character in value):
                raise _EntitlementsParseError("invalid-der-numeric-string")
            return value, next_cursor
        if tag in {0x17, 0x18}:  # UTC TIME / GENERALIZED TIME
            try:
                return payload.decode("ascii", "strict"), next_cursor
            except UnicodeDecodeError as error:
                raise _EntitlementsParseError("invalid-der-date") from error
        if tag == 0x30:  # SEQUENCE / CFArray
            return self._collection(start, payload_end, depth), next_cursor
        if tag in {0x31, 0xB0}:  # SET or CoreEntitlements dictionary
            return self._dictionary(start, payload_end, depth), next_cursor
        if tag == 0xF1:  # PRIVATE constructed SET / CFSet
            return self._collection(start, payload_end, depth), next_cursor
        raise _EntitlementsParseError("unsupported-der-value")

    def decode(self) -> dict[str, Any]:
        if not self.data or len(self.data) > MAX_ENTITLEMENTS_BYTES:
            raise _EntitlementsParseError("invalid-or-oversized-der")
        top_tag, start, end, next_cursor = self._tlv(0, len(self.data))
        if next_cursor != len(self.data):
            raise _EntitlementsParseError("trailing-der-data")

        if top_tag == 0x70:  # CoreEntitlements wrapper: version + dictionary
            version, cursor = self._value(start, end, 1)
            if type(version) is not int or version != 1:
                raise _EntitlementsParseError("unsupported-entitlements-version")
            dictionary_tag, dictionary_start, dictionary_end, cursor = self._tlv(
                cursor, end
            )
            if dictionary_tag != 0xB0 or cursor != end:
                raise _EntitlementsParseError("invalid-entitlements-wrapper")
            self._take_value(1)
            result = self._dictionary(dictionary_start, dictionary_end, 1)
        else:
            result, cursor = self._value(0, len(self.data), 0)
            if cursor != len(self.data):
                raise _EntitlementsParseError("trailing-der-data")

        if not isinstance(result, dict):
            raise _EntitlementsParseError("entitlements-are-not-a-dictionary")
        return result


def parse_der_entitlements(data: bytes) -> dict[str, Any] | None:
    """Decode Apple's DER entitlements payload without platform APIs."""

    try:
        return _DEREntitlementsDecoder(data).decode()
    except (_EntitlementsParseError, RecursionError):
        return None


def _parse_xml_entitlements(data: bytes) -> dict[str, Any] | None:
    if not data or len(data) > MAX_ENTITLEMENTS_BYTES:
        return None
    try:
        value = _normalise_entitlements(plistlib.loads(data))
    except (
        _EntitlementsParseError,
        plistlib.InvalidFileException,
        OverflowError,
        RecursionError,
        TypeError,
        ValueError,
    ):
        return None
    return value if isinstance(value, dict) else None


def _parse_code_signature(
    data: bytes,
    *,
    offset: int,
    signature_size: int,
) -> tuple[dict[str, Any], dict[str, Any] | None, str | None]:
    """Read entitlements slots from an embedded code-signature SuperBlob."""

    summary: dict[str, Any] = {"offset": offset, "size": signature_size}
    if len(data) < 12:
        summary["parse_error"] = "truncated-superblob"
        return summary, None, None
    magic, superblob_size, blob_count = struct.unpack_from(">III", data)
    summary.update(
        {"superblob_size": int(superblob_size), "blob_count": int(blob_count)}
    )
    if magic not in {CSMAGIC_EMBEDDED_SIGNATURE, CSMAGIC_DETACHED_SIGNATURE}:
        summary["parse_error"] = "not-a-signature-superblob"
        return summary, None, None
    if (
        superblob_size < 12
        or superblob_size > len(data)
        or blob_count > MAX_CODE_SIGNATURE_BLOBS
        or blob_count > (superblob_size - 12) // 8
    ):
        summary["parse_error"] = "invalid-superblob-bounds"
        return summary, None, None

    table_end = 12 + blob_count * 8
    slots: dict[int, tuple[int, int, bytes]] = {}
    for index in range(blob_count):
        slot, blob_offset = struct.unpack_from(">II", data, 12 + index * 8)
        if blob_offset < table_end or blob_offset > superblob_size - 8:
            summary["parse_error"] = "invalid-superblob-index"
            return summary, None, None
        blob_magic, blob_size = struct.unpack_from(">II", data, blob_offset)
        if blob_size < 8 or blob_size > superblob_size - blob_offset:
            summary["parse_error"] = "invalid-code-signature-blob"
            return summary, None, None
        if slot in {CSSLOT_ENTITLEMENTS, CSSLOT_DER_ENTITLEMENTS}:
            if slot in slots:
                summary["parse_error"] = "duplicate-entitlements-slot"
                return summary, None, None
            slots[slot] = (
                int(blob_magic),
                int(blob_size),
                data[blob_offset + 8 : blob_offset + blob_size],
            )

    decoded: dict[str, dict[str, Any]] = {}
    errors: dict[str, str] = {}
    xml_slot = slots.get(CSSLOT_ENTITLEMENTS)
    if xml_slot is not None:
        blob_magic, blob_size, payload = xml_slot
        if blob_magic != CSMAGIC_EMBEDDED_ENTITLEMENTS:
            errors["xml"] = "unexpected-blob-magic"
        elif blob_size - 8 > MAX_ENTITLEMENTS_BYTES:
            errors["xml"] = "oversized-entitlements"
        else:
            value = _parse_xml_entitlements(payload)
            if value is None:
                errors["xml"] = "invalid-plist"
            else:
                decoded["xml"] = value

    der_slot = slots.get(CSSLOT_DER_ENTITLEMENTS)
    if der_slot is not None:
        blob_magic, blob_size, payload = der_slot
        if blob_magic != CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:
            errors["der"] = "unexpected-blob-magic"
        elif blob_size - 8 > MAX_ENTITLEMENTS_BYTES:
            errors["der"] = "oversized-entitlements"
        else:
            value = parse_der_entitlements(payload)
            if value is None:
                errors["der"] = "invalid-der"
            else:
                decoded["der"] = value

    summary["entitlements_formats"] = list(decoded)
    if errors:
        summary["entitlements_errors"] = errors
    if "xml" in decoded and "der" in decoded:
        summary["entitlements_match"] = decoded["xml"] == decoded["der"]
    source = "xml" if "xml" in decoded else "der" if "der" in decoded else None
    return summary, decoded.get(source) if source else None, source


def _decode_uleb128(data: bytes, cursor: int, end: int) -> tuple[int, int] | None:
    """Decode one unsigned 64-bit LEB128 value inside ``[cursor, end)``."""

    value = 0
    shift = 0
    # A uint64 needs at most ten ULEB bytes.  The tenth may only carry bit 63.
    for _ in range(10):
        if cursor >= end:
            return None
        byte = data[cursor]
        cursor += 1
        payload = byte & 0x7F
        if shift == 63 and payload > 1:
            return None
        value |= payload << shift
        if not byte & 0x80:
            return value, cursor
        shift += 7
    return None


def parse_export_trie(
    data: bytes,
    *,
    sample_limit: int = 32,
    max_nodes: int = MAX_EXPORT_TRIE_NODES,
) -> dict[str, Any]:
    """Safely enumerate a Mach-O dyld export trie.

    The returned object intentionally contains a bounded sample rather than
    every export name.  ``symbol_count`` counts every terminal visited unless
    ``truncated`` is true.  Invalid offsets, unterminated edge strings, ULEB128
    overflow and cycles are reported through ``malformed`` and never raise.
    """

    sample_limit = max(0, min(int(sample_limit), 10_000))
    max_nodes = max(1, min(int(max_nodes), MAX_EXPORT_TRIE_NODES))
    result: dict[str, Any] = {
        "symbol_count": 0,
        "symbols_sample": [],
        "reexport_count": 0,
        "stub_and_resolver_count": 0,
        "has_main": False,
        "has_mh_execute_header": False,
        "malformed": False,
        "truncated": False,
    }
    if len(data) > MAX_EXPORT_TRIE_BYTES:
        result["malformed"] = True
        result["truncated"] = True
        result["parse_error"] = "oversized-trie"
        return result
    if not data:
        return result

    stack: list[tuple[int, bytes]] = [(0, b"")]
    visited_offsets: set[int] = set()
    node_spans: list[tuple[int, int]] = []
    samples: list[str] = []
    nodes_seen = 0

    while stack:
        if nodes_seen >= max_nodes:
            result["truncated"] = True
            break
        node_offset, prefix = stack.pop()
        if node_offset >= len(data) or node_offset in visited_offsets:
            result["malformed"] = True
            continue
        visited_offsets.add(node_offset)
        nodes_seen += 1

        decoded = _decode_uleb128(data, node_offset, len(data))
        if decoded is None:
            result["malformed"] = True
            continue
        terminal_size, cursor = decoded
        if terminal_size > len(data) - cursor:
            result["malformed"] = True
            continue
        terminal_end = cursor + terminal_size

        if terminal_size:
            flags_value = _decode_uleb128(data, cursor, terminal_end)
            if flags_value is None:
                result["malformed"] = True
            else:
                flags, payload_cursor = flags_value
                if flags & EXPORT_SYMBOL_FLAGS_REEXPORT:
                    ordinal = _decode_uleb128(data, payload_cursor, terminal_end)
                    if ordinal is None:
                        result["malformed"] = True
                    else:
                        _, payload_cursor = ordinal
                        nul = data.find(b"\0", payload_cursor, terminal_end)
                        if nul < 0:
                            result["malformed"] = True
                    result["reexport_count"] += 1
                else:
                    address = _decode_uleb128(data, payload_cursor, terminal_end)
                    if address is None:
                        result["malformed"] = True
                    else:
                        _, payload_cursor = address
                        if flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER:
                            resolver = _decode_uleb128(
                                data, payload_cursor, terminal_end
                            )
                            if resolver is None:
                                result["malformed"] = True
                            result["stub_and_resolver_count"] += 1

                name = prefix.decode("utf-8", "replace")
                result["symbol_count"] += 1
                if len(samples) < sample_limit:
                    samples.append(name)
                if name == "_main":
                    result["has_main"] = True
                elif name == "__mh_execute_header":
                    result["has_mh_execute_header"] = True

        cursor = terminal_end
        if cursor >= len(data):
            result["malformed"] = True
            continue
        child_count = data[cursor]
        cursor += 1
        children: list[tuple[int, bytes]] = []
        for _ in range(child_count):
            if cursor >= len(data):
                result["malformed"] = True
                break
            edge_limit = min(len(data), cursor + MAX_EXPORT_SYMBOL_BYTES + 1)
            nul = data.find(b"\0", cursor, edge_limit)
            if nul < 0:
                result["malformed"] = True
                break
            edge = data[cursor:nul]
            cursor = nul + 1
            child = _decode_uleb128(data, cursor, len(data))
            if child is None:
                result["malformed"] = True
                break
            child_offset, cursor = child
            if (
                child_offset >= len(data)
                or len(prefix) + len(edge) > MAX_EXPORT_SYMBOL_BYTES
            ):
                result["malformed"] = True
                continue
            children.append((child_offset, prefix + edge))

        node_spans.append((node_offset, cursor))

        # Reverse to preserve the on-disk child order under a LIFO traversal.
        stack.extend(reversed(children))

    result["symbols_sample"] = samples
    result["visited_node_count"] = nodes_seen
    result["reachable_byte_count"] = _interval_union_size(node_spans)
    result["reachable_extent"] = max((end for _, end in node_spans), default=0)
    result["trailing_byte_count"] = max(0, len(data) - result["reachable_extent"])
    result["nonzero_trailing_bytes"] = bool(
        data[result["reachable_extent"] :].strip(b"\0")
    )
    return result


def _interval_union_size(intervals: list[tuple[int, int]]) -> int:
    if not intervals:
        return 0
    total = 0
    start, end = sorted(intervals)[0]
    for next_start, next_end in sorted(intervals)[1:]:
        if next_start <= end:
            end = max(end, next_end)
        else:
            total += end - start
            start, end = next_start, next_end
    return total + end - start


def _valid_dysymtab_ranges(
    dynamic: dict[str, int] | None, symbol_count: int
) -> bool:
    if dynamic is None:
        return False
    ranges = [
        (dynamic["local_index"], dynamic["local_count"]),
        (dynamic["external_defined_index"], dynamic["external_defined_count"]),
        (dynamic["undefined_index"], dynamic["undefined_count"]),
    ]
    for index, count in ranges:
        if not _range_is_valid(index, count, symbol_count):
            return False
    local_index, local_count = ranges[0]
    external_index, external_count = ranges[1]
    undefined_index, undefined_count = ranges[2]
    return (
        local_index == 0
        and external_index == local_index + local_count
        and undefined_index == external_index + external_count
        and undefined_index + undefined_count == symbol_count
    )


def _parse_symbol_metadata(
    handle: BinaryIO,
    slice_offset: int,
    slice_size: int,
    header_and_commands_size: int,
    endian: str,
    is_64: bool,
    symtab: dict[str, int] | None,
    dysymtab: dict[str, int] | None,
    swift_abi_version: int | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    dynamic_result: dict[str, Any] | None = None
    if dysymtab is not None:
        dynamic_result = {
            **dysymtab,
            "valid": symtab is not None
            and _valid_dysymtab_ranges(dysymtab, symtab["count"]),
        }
    if symtab is None:
        return None, dynamic_result

    count = symtab["count"]
    entry_size = 16 if is_64 else 12
    entry_bytes = count * entry_size
    total_bytes = entry_bytes + symtab["string_size"]
    result: dict[str, Any] = {
        "offset": symtab["offset"],
        "count": count,
        "entry_size": entry_size,
        "entry_bytes": entry_bytes,
        "string_offset": symtab["string_offset"],
        "string_bytes": symtab["string_size"],
        "total_bytes": total_bytes,
        "valid": False,
        "parsed_count": 0,
    }

    symbol_range_valid = _range_is_valid(symtab["offset"], entry_bytes, slice_size)
    string_range_valid = _range_is_valid(
        symtab["string_offset"], symtab["string_size"], slice_size
    )
    table_regions_overlap = not (
        symtab["offset"] + entry_bytes <= symtab["string_offset"]
        or symtab["string_offset"] + symtab["string_size"] <= symtab["offset"]
    )
    starts_after_commands = (
        symtab["offset"] >= header_and_commands_size
        and symtab["string_offset"] >= header_and_commands_size
    )
    within_limits = (
        count <= MAX_SYMBOL_COUNT
        and entry_bytes <= MAX_SYMBOL_TABLE_BYTES
        and symtab["string_size"] <= MAX_STRING_TABLE_BYTES
    )
    if not (
        symbol_range_valid
        and string_range_valid
        and not table_regions_overlap
        and starts_after_commands
        and within_limits
    ):
        result["parse_error"] = "invalid-or-oversized-table"
        return result, dynamic_result

    symbol_data = _read_slice_range(
        handle,
        slice_offset,
        slice_size,
        symtab["offset"],
        entry_bytes,
        maximum=MAX_SYMBOL_TABLE_BYTES,
    )
    string_data = _read_slice_range(
        handle,
        slice_offset,
        slice_size,
        symtab["string_offset"],
        symtab["string_size"],
        maximum=MAX_STRING_TABLE_BYTES,
    )
    if symbol_data is None or string_data is None:
        result["parse_error"] = "short-read"
        return result, dynamic_result

    ranges_are_valid = bool(dynamic_result and dynamic_result["valid"])
    classifications = {
        name: {"count": 0, "entry_bytes": 0, "string_bytes": 0}
        for name in (
            "local",
            "external_defined",
            "undefined",
            "other",
            "debug",
            "swift",
            "dynamically_referenced",
        )
    }
    intervals: dict[str, list[tuple[int, int]]] = {
        name: [] for name in classifications
    }
    samples: dict[str, list[str]] = {name: [] for name in classifications}
    retained_intervals: list[tuple[int, int]] = []
    candidate_intervals: list[tuple[int, int]] = []
    candidate_count = 0
    invalid_name_count = 0

    for index in range(count):
        offset = index * entry_size
        if is_64:
            string_index, symbol_type, _, description, _ = struct.unpack_from(
                endian + "IBBHQ", symbol_data, offset
            )
        else:
            string_index, symbol_type, _, description, _ = struct.unpack_from(
                endian + "IBBHI", symbol_data, offset
            )

        name = ""
        name_interval: tuple[int, int] | None = None
        if string_index < len(string_data):
            nul = string_data.find(b"\0", string_index)
            if nul >= 0:
                name = string_data[string_index:nul].decode("utf-8", "replace")
                if string_index:
                    name_interval = (string_index, nul + 1)
            else:
                invalid_name_count += 1
        else:
            invalid_name_count += 1

        is_debug = bool(symbol_type & N_STAB)
        is_external = bool(symbol_type & N_EXT)
        dynamically_referenced = bool(description & REFERENCED_DYNAMICALLY)
        is_swift = name.startswith(("_$s", "_$S"))

        if ranges_are_valid:
            assert dysymtab is not None
            if dysymtab["local_index"] <= index < (
                dysymtab["local_index"] + dysymtab["local_count"]
            ):
                base_class = "local"
            elif dysymtab["external_defined_index"] <= index < (
                dysymtab["external_defined_index"]
                + dysymtab["external_defined_count"]
            ):
                base_class = "external_defined"
            elif dysymtab["undefined_index"] <= index < (
                dysymtab["undefined_index"] + dysymtab["undefined_count"]
            ):
                base_class = "undefined"
            else:
                base_class = "other"
        elif not is_external:
            base_class = "local"
        elif (symbol_type & N_TYPE) in {N_UNDF, N_PBUD}:
            base_class = "undefined"
        else:
            base_class = "external_defined"

        applicable = [base_class]
        if is_debug:
            applicable.append("debug")
        if is_swift:
            applicable.append("swift")
        if dynamically_referenced:
            applicable.append("dynamically_referenced")
        for classification in applicable:
            classifications[classification]["count"] += 1
            classifications[classification]["entry_bytes"] += entry_size
            if name_interval is not None:
                intervals[classification].append(name_interval)
            if name and len(samples[classification]) < SYMBOL_SAMPLE_LIMIT:
                samples[classification].append(name)

        # -S removes debug entries, -x removes locals, and -T targets Swift
        # names only for Swift-bearing images.  -r's dynamically referenced
        # symbols are conservatively retained so this remains an estimate and
        # does not promise savings Apple strip may need to preserve.
        strip_candidate = is_debug or (
            not dynamically_referenced
            and (
                base_class == "local"
                or (is_swift and swift_abi_version is not None)
            )
        )
        if strip_candidate:
            candidate_count += 1
            if name_interval is not None:
                candidate_intervals.append(name_interval)
        elif name_interval is not None:
            retained_intervals.append(name_interval)

    for classification, values in classifications.items():
        values["string_bytes"] = _interval_union_size(intervals[classification])

    # A rewritten string table needs a leading NUL plus strings still named by
    # retained entries.  Counting the union handles suffix-sharing safely.
    retained_string_bytes = min(
        len(string_data),
        (1 if string_data else 0) + _interval_union_size(retained_intervals),
    )
    estimated_string_savings = max(0, len(string_data) - retained_string_bytes)
    candidate_entry_bytes = candidate_count * entry_size
    result.update(
        {
            "valid": True,
            "parsed_count": count,
            "invalid_name_count": invalid_name_count,
            "classifications": classifications,
            "samples": samples,
            "strip_rSTx": {
                "candidate_count": candidate_count,
                "candidate_entry_bytes": candidate_entry_bytes,
                "candidate_named_string_bytes": _interval_union_size(
                    candidate_intervals
                ),
                "estimated_string_bytes": estimated_string_savings,
                "estimated_bytes": candidate_entry_bytes
                + estimated_string_savings,
                "retained_count": count - candidate_count,
                "swift_eligible": swift_abi_version is not None,
                "is_estimate": True,
            },
        }
    )
    return result, dynamic_result


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
    if not _range_is_valid(header_size, sizeofcmds, slice_size):
        return None
    commands = _read_at(handle, slice_offset + header_size, sizeofcmds)
    if len(commands) != sizeofcmds:
        return None

    segments: list[dict[str, Any]] = []
    claimed_segment_ranges: list[tuple[int, int]] = []
    dependencies: list[str] = []
    rpaths: list[str] = []
    seen_rpaths: set[str] = set()
    symbol_bytes = 0
    symtab: dict[str, int] | None = None
    dysymtab: dict[str, int] | None = None
    code_signature_command: tuple[int, int] | None = None
    duplicate_code_signature_command = False
    dedicated_export: tuple[int, int, str] | None = None
    legacy_export: tuple[int, int, str] | None = None
    encrypted = False
    uuid = None
    platform = None
    minimum_os = None
    sdk = None
    swift_abi_version: int | None = None
    cursor = 0
    commands_parsed = 0

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
            bounded_segment_size = _claim_bounded_file_range(
                int(file_offset),
                int(file_size),
                0,
                slice_size,
                claimed_segment_ranges,
            )
            if bounded_segment_size is None:
                bounded_segment_size = 0
            section_cursor = cursor + 72
            sections: list[dict[str, Any]] = []
            claimed_section_ranges: list[tuple[int, int]] = []
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
                decoded_section_name = _cstring(section_name)
                original_size = section_size
                if (section_flags & 0xFF) in ZEROFILL_TYPES:
                    section_size = 0
                else:
                    bounded_section_size = _claim_bounded_file_range(
                        int(section_offset),
                        int(section_size),
                        int(file_offset),
                        bounded_segment_size,
                        claimed_section_ranges,
                    )
                    if bounded_section_size is None:
                        section_cursor += 80
                        continue
                    section_size = bounded_section_size
                sections.append(
                    {
                        "name": decoded_section_name,
                        "segment": _cstring(section_segment),
                        "size": int(section_size),
                        "virtual_size": int(original_size),
                    }
                )
                if decoded_section_name == "__objc_imageinfo" and section_size >= 8:
                    image_info = _read_slice_range(
                        handle,
                        slice_offset,
                        slice_size,
                        section_offset,
                        8,
                    )
                    if image_info is not None:
                        _, image_flags = struct.unpack(endian + "II", image_info)
                        version = (image_flags >> 8) & 0xFF
                        if version:
                            swift_abi_version = version
                section_cursor += 80
            segments.append(
                {
                    "name": _cstring(segment_name),
                    "size": int(bounded_segment_size),
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
            bounded_segment_size = _claim_bounded_file_range(
                int(file_offset),
                int(file_size),
                0,
                slice_size,
                claimed_segment_ranges,
            )
            if bounded_segment_size is None:
                bounded_segment_size = 0
            section_cursor = cursor + 56
            sections = []
            claimed_section_ranges = []
            for _ in range(section_count):
                if section_cursor + 68 > cursor + command_size:
                    break
                section = struct.unpack_from(
                    endian + "16s16sIIIIIIIII", commands, section_cursor
                )
                section_size = section[3]
                section_offset = section[4]
                section_flags = section[8]
                decoded_section_name = _cstring(section[0])
                if (section_flags & 0xFF) in ZEROFILL_TYPES:
                    section_size = 0
                else:
                    bounded_section_size = _claim_bounded_file_range(
                        int(section_offset),
                        int(section_size),
                        int(file_offset),
                        bounded_segment_size,
                        claimed_section_ranges,
                    )
                    if bounded_section_size is None:
                        section_cursor += 68
                        continue
                    section_size = bounded_section_size
                sections.append(
                    {
                        "name": decoded_section_name,
                        "segment": _cstring(section[1]),
                        "size": int(section_size),
                        "virtual_size": int(section[3]),
                    }
                )
                if decoded_section_name == "__objc_imageinfo" and section_size >= 8:
                    image_info = _read_slice_range(
                        handle,
                        slice_offset,
                        slice_size,
                        section_offset,
                        8,
                    )
                    if image_info is not None:
                        _, image_flags = struct.unpack(endian + "II", image_info)
                        version = (image_flags >> 8) & 0xFF
                        if version:
                            swift_abi_version = version
                section_cursor += 68
            segments.append(
                {
                    "name": _cstring(segment_name),
                    "size": int(bounded_segment_size),
                    "virtual_size": int(virtual_size),
                    "file_offset": int(file_offset),
                    "sections": sections,
                }
            )

        elif command == LC_SYMTAB and command_size >= 24:
            (
                _,
                _,
                symbol_offset,
                symbol_count,
                string_offset,
                string_size,
            ) = struct.unpack_from(endian + "IIIIII", commands, cursor)
            symbol_bytes = int(symbol_count * (16 if is_64 else 12) + string_size)
            symtab = {
                "offset": int(symbol_offset),
                "count": int(symbol_count),
                "string_offset": int(string_offset),
                "string_size": int(string_size),
            }

        elif command == LC_DYSYMTAB and command_size >= 80:
            fields = struct.unpack_from(endian + "20I", commands, cursor)
            dysymtab = {
                "local_index": int(fields[2]),
                "local_count": int(fields[3]),
                "external_defined_index": int(fields[4]),
                "external_defined_count": int(fields[5]),
                "undefined_index": int(fields[6]),
                "undefined_count": int(fields[7]),
                "indirect_symbol_offset": int(fields[14]),
                "indirect_symbol_count": int(fields[15]),
                "external_relocation_offset": int(fields[16]),
                "external_relocation_count": int(fields[17]),
                "local_relocation_offset": int(fields[18]),
                "local_relocation_count": int(fields[19]),
            }

        elif command == LC_CODE_SIGNATURE and command_size >= 16:
            _, _, data_offset, data_size = struct.unpack_from(
                endian + "IIII", commands, cursor
            )
            if code_signature_command is None:
                code_signature_command = (int(data_offset), int(data_size))
            else:
                duplicate_code_signature_command = True

        elif command == LC_DYLD_EXPORTS_TRIE and command_size >= 16:
            _, _, data_offset, data_size = struct.unpack_from(
                endian + "IIII", commands, cursor
            )
            dedicated_export = (
                int(data_offset),
                int(data_size),
                "LC_DYLD_EXPORTS_TRIE",
            )

        elif command in {LC_DYLD_INFO, LC_DYLD_INFO_ONLY} and command_size >= 48:
            fields = struct.unpack_from(endian + "12I", commands, cursor)
            source = (
                "LC_DYLD_INFO_ONLY"
                if command == LC_DYLD_INFO_ONLY
                else "LC_DYLD_INFO"
            )
            legacy_export = (int(fields[10]), int(fields[11]), source)

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
                    name = _cstring(
                        commands[cursor + name_offset : cursor + command_size]
                    )
                    if name and command != LC_ID_DYLIB:
                        dependencies.append(name)

        elif command == LC_RPATH and command_size >= 12:
            path_offset = struct.unpack_from(
                endian + "I", commands, cursor + 8
            )[0]
            # ``lc_str`` is relative to the start of its load command.  Keep
            # the string inside that command and require a bounded NUL-terminated
            # UTF-8 path so malformed inputs cannot bleed into the next command.
            if 12 <= path_offset < command_size:
                path_start = cursor + path_offset
                path_limit = min(
                    cursor + command_size,
                    path_start + MAX_RPATH_BYTES + 1,
                )
                nul = commands.find(b"\0", path_start, path_limit)
                if nul >= 0:
                    try:
                        path = commands[path_start:nul].decode("utf-8")
                    except UnicodeDecodeError:
                        path = ""
                    if (
                        path
                        and path not in seen_rpaths
                        and len(rpaths) < MAX_RPATH_COUNT
                    ):
                        seen_rpaths.add(path)
                        rpaths.append(path)

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
        commands_parsed += 1

    if commands_parsed != ncmds:
        return None

    code_signature: dict[str, Any] | None = None
    entitlements: dict[str, Any] | None = None
    entitlements_source: str | None = None
    if duplicate_code_signature_command:
        code_signature = {"parse_error": "duplicate-code-signature-command"}
    elif code_signature_command is not None:
        signature_offset, signature_size = code_signature_command
        code_signature = {"offset": signature_offset, "size": signature_size}
        signature_data = _read_slice_range(
            handle,
            slice_offset,
            slice_size,
            signature_offset,
            signature_size,
            maximum=MAX_CODE_SIGNATURE_BYTES,
        )
        if signature_data is None:
            code_signature["parse_error"] = "invalid-or-oversized-signature"
        else:
            code_signature, entitlements, entitlements_source = (
                _parse_code_signature(
                    signature_data,
                    offset=signature_offset,
                    signature_size=signature_size,
                )
            )

    symbol_table, dynamic_symbol_table = _parse_symbol_metadata(
        handle,
        slice_offset,
        slice_size,
        header_size + sizeofcmds,
        endian,
        is_64,
        symtab,
        dysymtab,
        swift_abi_version,
    )

    export_trie: dict[str, Any] | None = None
    export_command = dedicated_export or legacy_export
    if export_command is not None:
        export_offset, export_size, export_source = export_command
        export_trie = {
            "source": export_source,
            "offset": export_offset,
            "size": export_size,
            "valid": False,
        }
        export_data = _read_slice_range(
            handle,
            slice_offset,
            slice_size,
            export_offset,
            export_size,
            maximum=MAX_EXPORT_TRIE_BYTES,
        )
        if export_data is None:
            export_trie["parse_error"] = "invalid-or-oversized-trie"
        else:
            trie_summary = parse_export_trie(export_data)
            export_trie.update(trie_summary)
            export_trie["valid"] = not (
                trie_summary["malformed"] or trie_summary["truncated"]
            )

    represented = sum(min(segment["size"], slice_size) for segment in segments)
    return {
        "architecture": _arch_name(cpu_type, cpu_subtype),
        "cpu_type": cpu_type,
        "cpu_subtype": cpu_subtype,
        "is_64": is_64,
        "file_type": FILE_TYPES.get(file_type, f"type-{file_type}"),
        "file_type_id": file_type,
        "is_executable": file_type == MH_EXECUTE,
        "flags": flags,
        "size": int(slice_size),
        "segments": segments,
        "dependencies": sorted(set(dependencies)),
        "rpaths": rpaths,
        "symbol_table_bytes": symbol_bytes,
        "symbol_table": symbol_table,
        "dynamic_symbol_table": dynamic_symbol_table,
        "export_trie": export_trie,
        "code_signature": code_signature,
        "entitlements": entitlements,
        "entitlements_source": entitlements_source,
        "swift_abi_version": swift_abi_version,
        "encrypted": encrypted,
        "uuid": uuid,
        "platform": platform,
        "minimum_os": minimum_os,
        "sdk": sdk,
        "unattributed_bytes": max(0, int(slice_size - min(represented, slice_size))),
    }


def _unique_entitlements(
    architectures: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    for architecture in architectures:
        value = architecture.get("entitlements")
        if isinstance(value, dict) and not any(value == item for item in unique):
            unique.append(value)
    return unique


def parse_macho(path: Path) -> dict[str, Any] | None:
    """Return a JSON-serializable description, or ``None`` for non Mach-O.

    Each architecture exposes one decoded ``entitlements`` dictionary when
    present.  The top-level ``entitlements`` list deduplicates those values
    across universal-binary slices.
    """

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
                    "entitlements": _unique_entitlements([slice_info]),
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
            if len(entries) != architecture_count * entry_size:
                return None
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
                "entitlements": _unique_entitlements(slices),
                "container_overhead": max(
                    0, file_size - sum(item["size"] for item in slices)
                ),
            }
    except (OSError, struct.error, ValueError):
        return None
