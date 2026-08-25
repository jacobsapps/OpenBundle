"""Host-neutral iOS bundle analysis and recommendation engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable
import base64
import hashlib
import json
import math
import os
import plistlib
import re
import tempfile
import zlib

from .artifact import PreparedArtifact, prepare_artifact
from .linkmap import parse_linkmap
from .macho import is_macho, parse_macho
from .platform import AnalysisPlatform, NativeAnalysisPlatform


Progress = Callable[[str], None]

IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".heic", ".heif", ".gif", ".webp"}
VECTOR_SUFFIXES = {".svg", ".pdf"}
VIDEO_SUFFIXES = {".mp4", ".mov", ".m4v", ".webm"}
AUDIO_SUFFIXES = {".mp3", ".m4a", ".aac", ".wav", ".caf", ".flac", ".ogg"}
FONT_SUFFIXES = {".ttf", ".otf", ".ttc", ".woff", ".woff2"}
COREML_SUFFIXES = {".mlmodel", ".mlmodelc", ".mlpackage"}
INTERFACE_SUFFIXES = {".nib", ".storyboardc"}
LOCALIZATION_SUFFIXES = {".strings", ".stringsdict", ".xcstrings"}
MIN_RECOMMENDATION_SAVINGS = 100_000
LARGE_IMAGE_REVIEW_BYTES = 1_000_000
LARGE_IMAGE_REVIEW_EDGE = 3_000
MAX_INSIGHT_ITEMS = 500
MAX_INSIGHT_PATHS = 1_000
MIN_LINKING_REVIEW_BYTES = 2_000_000
MAX_LINKING_REVIEWS = 3

CATEGORY_LABELS = {
    "binary": "Binaries",
    "asset_catalog": "Asset catalogs",
    "image": "Images",
    "video": "Videos",
    "audio": "Audio",
    "animation": "Animations",
    "localization": "Localizations",
    "font": "Fonts",
    "coreml": "CoreML models",
    "interface": "Interface Builder",
    "signature": "Signing",
    "metadata": "Metadata",
    "other": "Other",
    "binary_section": "Binary sections",
}

UNNECESSARY_NAMES = {
    ".ds_store",
    "authors",
    "authors.txt",
    "changelog",
    "changelog.md",
    "changelog.txt",
    "contributors",
    "contributors.md",
    "readme",
    "readme.md",
    "readme.txt",
}
UNNECESSARY_SUFFIXES = {
    ".bcsymbolmap",
    ".command",
    ".h",
    ".hpp",
    ".map",
    ".pch",
    ".sh",
    ".swift",
    ".swiftdoc",
    ".swiftinterface",
    ".swiftmodule",
    ".xcconfig",
}


@dataclass
class Record:
    relative_path: str
    absolute_path: Path
    size: int
    compressed_size: int
    allocated_size: int
    category: str
    sha256: str
    kind: str = "file"
    metadata: dict[str, Any] = field(default_factory=dict)
    macho: dict[str, Any] | None = None
    virtual_children: list[dict[str, Any]] = field(default_factory=list)
    duplicate_group: str | None = None
    insight_ids: list[str] = field(default_factory=list)
    install_size: int | None = None
    download_size: int | None = None

    @property
    def name(self) -> str:
        return Path(self.relative_path).name

    @property
    def delivered_install_size(self) -> int:
        return self.size if self.install_size is None else self.install_size

    @property
    def delivered_download_size(self) -> int:
        return (
            self.compressed_size
            if self.download_size is None
            else self.download_size
        )


def _progress(callback: Progress | None, message: str) -> None:
    if callback:
        callback(message)


def _ceil(value: int, block: int) -> int:
    return ((value + block - 1) // block) * block if value else 0


def _stream_facts(path: Path, compressed_hint: int | None) -> tuple[str, int]:
    digest = hashlib.sha256()
    compressor = None if compressed_hint is not None else zlib.compressobj(6, zlib.DEFLATED, -15)
    compressed_size = compressed_hint or 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
            if compressor:
                compressed_size += len(compressor.compress(chunk))
    if compressor:
        compressed_size += len(compressor.flush())
    return digest.hexdigest(), int(compressed_size)


def _is_inside_component(path: str, suffix: str) -> bool:
    return any(part.lower().endswith(suffix) for part in Path(path).parts)


def _classify(path: str, macho: dict[str, Any] | None) -> str:
    lower = path.lower()
    suffix = Path(lower).suffix
    if macho:
        return "binary"
    if suffix == ".car":
        return "asset_catalog"
    if "/_codesignature/" in f"/{lower}/" or lower.endswith("/coderesources"):
        return "signature"
    if ".lproj/" in lower or suffix in LOCALIZATION_SUFFIXES:
        return "localization"
    if suffix in FONT_SUFFIXES:
        return "font"
    if suffix in VIDEO_SUFFIXES:
        return "video"
    if suffix in AUDIO_SUFFIXES:
        return "audio"
    if suffix in IMAGE_SUFFIXES | VECTOR_SUFFIXES:
        return "image"
    if suffix in COREML_SUFFIXES or _is_inside_component(path, ".mlmodelc"):
        return "coreml"
    if suffix in INTERFACE_SUFFIXES or _is_inside_component(path, ".storyboardc"):
        return "interface"
    if suffix in {".plist", ".mobileprovision", ".entitlements"}:
        return "metadata"
    return "other"


def _read_plist(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            value = plistlib.load(handle)
        return value if isinstance(value, dict) else {}
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}


_USAGE_DESCRIPTION_LABELS = {
    "NSAppleMusicUsageDescription": "Media library",
    "NSBluetoothAlwaysUsageDescription": "Bluetooth",
    "NSBluetoothPeripheralUsageDescription": "Bluetooth peripherals",
    "NSCalendarsFullAccessUsageDescription": "Calendars",
    "NSCalendarsUsageDescription": "Calendars",
    "NSCameraUsageDescription": "Camera",
    "NSContactsUsageDescription": "Contacts",
    "NSFaceIDUsageDescription": "Face ID",
    "NSHealthClinicalHealthRecordsShareUsageDescription": "Clinical records",
    "NSHealthShareUsageDescription": "Health data",
    "NSHealthUpdateUsageDescription": "Health data updates",
    "NSHomeKitUsageDescription": "Home",
    "NSLocalNetworkUsageDescription": "Local network",
    "NSLocationAlwaysAndWhenInUseUsageDescription": "Background location",
    "NSLocationAlwaysUsageDescription": "Background location",
    "NSLocationWhenInUseUsageDescription": "Location",
    "NSMicrophoneUsageDescription": "Microphone",
    "NSMotionUsageDescription": "Motion",
    "NSNearbyInteractionUsageDescription": "Nearby interaction",
    "NFCReaderUsageDescription": "NFC",
    "NSPhotoLibraryAddUsageDescription": "Add to Photos",
    "NSPhotoLibraryUsageDescription": "Photos",
    "NSRemindersFullAccessUsageDescription": "Reminders",
    "NSRemindersUsageDescription": "Reminders",
    "NSSpeechRecognitionUsageDescription": "Speech recognition",
    "NSUserTrackingUsageDescription": "Tracking",
}

_ENTITLEMENT_LABELS = {
    "aps-environment": "Push notifications",
    "com.apple.developer.applesignin": "Sign in with Apple",
    "com.apple.developer.associated-domains": "Associated domains",
    "com.apple.developer.healthkit": "HealthKit",
    "com.apple.developer.homekit": "HomeKit",
    "com.apple.developer.icloud-container-identifiers": "iCloud containers",
    "com.apple.developer.icloud-services": "iCloud services",
    "com.apple.developer.in-app-payments": "Apple Pay",
    "com.apple.developer.networking.HotspotConfiguration": "Hotspot configuration",
    "com.apple.developer.networking.multicast": "Multicast networking",
    "com.apple.developer.networking.multipath": "Multipath networking",
    "com.apple.developer.networking.networkextension": "Network extensions",
    "com.apple.developer.networking.vpn.api": "VPN",
    "com.apple.developer.networking.wifi-info": "Wi-Fi information",
    "com.apple.developer.nfc.readersession.formats": "NFC",
    "com.apple.developer.pass-type-identifiers": "Wallet passes",
    "com.apple.developer.siri": "Siri",
    "com.apple.developer.ubiquity-container-identifiers": "iCloud document containers",
    "com.apple.developer.ubiquity-kvstore-identifier": "iCloud key-value storage",
    "com.apple.security.application-groups": "App Groups",
    "keychain-access-groups": "Keychain groups",
}

_BUNDLE_SUFFIXES = (".app", ".appex", ".framework", ".bundle")
_TARGET_SUFFIXES = (".app", ".appex")


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple, set)):
        return sorted(
            {
                str(item)
                for item in value
                if isinstance(item, (str, int, float)) and str(item)
            }
        )
    if isinstance(value, bool):
        return ["Enabled"] if value else []
    if isinstance(value, (int, float)):
        return [str(value)]
    return []


def _humanize_identifier(value: str) -> str:
    text = value
    for prefix in (
        "NSPrivacyAccessedAPICategory",
        "NSPrivacyCollectedDataTypePurpose",
        "NSPrivacyCollectedDataType",
        "NSPrivacy",
        "NS",
    ):
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    return text.replace("_", " ").strip() or value


def _target_scope(relative_path: str) -> str:
    parts = relative_path.split("/")
    indexes = [
        index
        for index, part in enumerate(parts)
        if part.lower().endswith(_TARGET_SUFFIXES)
    ]
    return "/".join(parts[: indexes[-1] + 1]) if indexes else "."


def _bundle_context(relative_path: str, app_bundle_name: str) -> dict[str, str]:
    parts = relative_path.split("/")
    bundle_indexes = [
        index
        for index, part in enumerate(parts)
        if part.lower().endswith(_BUNDLE_SUFFIXES)
    ]
    target_indexes = [
        index
        for index, part in enumerate(parts)
        if part.lower().endswith(_TARGET_SUFFIXES)
    ]
    bundle_index = bundle_indexes[-1] if bundle_indexes else None
    target_index = target_indexes[-1] if target_indexes else None
    bundle_path = (
        "/".join(parts[: bundle_index + 1]) if bundle_index is not None else "."
    )
    target_path = (
        "/".join(parts[: target_index + 1]) if target_index is not None else "."
    )
    bundle_name = parts[bundle_index] if bundle_index is not None else app_bundle_name
    target_name = parts[target_index] if target_index is not None else app_bundle_name
    source = (
        "component"
        if bundle_index is not None
        and parts[bundle_index].lower().endswith((".framework", ".bundle"))
        else "app"
    )
    return {
        "bundle": bundle_name,
        "bundlePath": bundle_path,
        "target": target_name,
        "targetPath": target_path,
        "source": source,
    }


def _embedded_profile_plist(path: Path) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
    except OSError:
        return {}
    start = payload.find(b"<?xml")
    end = payload.find(b"</plist>", start)
    if start < 0 or end < 0:
        return {}
    try:
        value = plistlib.loads(payload[start : end + len(b"</plist>")])
    except (plistlib.InvalidFileException, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _privacy_manifest(record: Record, app_bundle_name: str) -> dict[str, Any] | None:
    if record.name.lower() != "privacyinfo.xcprivacy":
        return None
    value = _read_plist(record.absolute_path)
    if not value:
        return None
    context = _bundle_context(record.relative_path, app_bundle_name)
    accessed: list[dict[str, Any]] = []
    for item in value.get("NSPrivacyAccessedAPITypes", []):
        if not isinstance(item, dict):
            continue
        category = str(item.get("NSPrivacyAccessedAPIType") or "")
        if category:
            accessed.append(
                {
                    "category": category,
                    "label": _humanize_identifier(category),
                    "reasons": _string_values(item.get("NSPrivacyAccessedAPITypeReasons")),
                }
            )
    collected: list[dict[str, Any]] = []
    for item in value.get("NSPrivacyCollectedDataTypes", []):
        if not isinstance(item, dict):
            continue
        category = str(item.get("NSPrivacyCollectedDataType") or "")
        if category:
            collected.append(
                {
                    "category": category,
                    "label": _humanize_identifier(category),
                    "purposes": _string_values(item.get("NSPrivacyCollectedDataTypePurposes")),
                    "linked": bool(item.get("NSPrivacyCollectedDataTypeLinked")),
                    "tracking": bool(item.get("NSPrivacyCollectedDataTypeTracking")),
                }
            )
    domains = _string_values(value.get("NSPrivacyTrackingDomains"))
    return {
        "path": record.relative_path,
        **context,
        "tracking": bool(value.get("NSPrivacyTracking")),
        "trackingDomains": domains,
        "accessedAPIs": sorted(accessed, key=lambda item: item["label"]),
        "collectedData": sorted(collected, key=lambda item: item["label"]),
    }


def _collect_capability_declarations(
    app_root: Path,
    app_bundle_name: str,
    main_info: dict[str, Any],
    records: list[Record],
) -> dict[str, Any]:
    target_plists: dict[str, tuple[dict[str, Any], str]] = {
        ".": (main_info, app_root.name)
    }
    for record in records:
        if record.name.lower() != "info.plist":
            continue
        parent = str(Path(record.relative_path).parent.as_posix())
        if parent == "." or not parent.lower().endswith(_TARGET_SUFFIXES):
            continue
        value = _read_plist(record.absolute_path)
        if value:
            target_plists[parent] = (value, Path(parent).name)

    entitlements_by_target: dict[str, dict[str, list[str]]] = {}

    def merge_entitlements(scope: str, value: dict[str, Any]) -> None:
        declarations = entitlements_by_target.setdefault(scope, {})
        for key in _ENTITLEMENT_LABELS:
            values = _string_values(value.get(key))
            if values:
                declarations.setdefault(key, []).extend(values)

    for record in records:
        lower = record.relative_path.lower()
        value: dict[str, Any] = {}
        if lower.endswith((".entitlements", ".xcent")):
            value = _read_plist(record.absolute_path)
        elif record.name.lower() == "embedded.mobileprovision":
            profile = _embedded_profile_plist(record.absolute_path)
            candidate = profile.get("Entitlements")
            value = candidate if isinstance(candidate, dict) else {}
        if not value:
            continue
        scope = _target_scope(record.relative_path)
        merge_entitlements(scope, value)

    records_by_path = {record.relative_path: record for record in records}
    for scope, (info, _) in target_plists.items():
        executable = str(info.get("CFBundleExecutable") or "")
        if not executable:
            continue
        executable_path = executable if scope == "." else f"{scope}/{executable}"
        binary = records_by_path.get(executable_path)
        if binary is None or not binary.macho:
            continue
        for value in binary.macho.get("entitlements", []):
            if isinstance(value, dict):
                merge_entitlements(scope, value)

    targets: list[dict[str, Any]] = []
    for path, (info, fallback_name) in sorted(
        target_plists.items(), key=lambda item: (item[0] != ".", item[0].lower())
    ):
        extension = info.get("NSExtension")
        extension = extension if isinstance(extension, dict) else {}
        permissions = [
            {
                "key": key,
                "label": _USAGE_DESCRIPTION_LABELS.get(key, _humanize_identifier(key.replace("UsageDescription", ""))),
                "value": value,
            }
            for key, value in info.items()
            if key.endswith("UsageDescription") and isinstance(value, str) and value
        ]
        url_schemes: set[str] = set()
        for url_type in info.get("CFBundleURLTypes", []):
            if isinstance(url_type, dict):
                url_schemes.update(_string_values(url_type.get("CFBundleURLSchemes")))
        transport = info.get("NSAppTransportSecurity")
        transport = transport if isinstance(transport, dict) else {}
        exception_domains = transport.get("NSExceptionDomains")
        transport_domains = (
            sorted(str(key) for key in exception_domains)
            if isinstance(exception_domains, dict)
            else []
        )
        entitlement_items = []
        for key, values in sorted(entitlements_by_target.get(path, {}).items()):
            entitlement_items.append(
                {
                    "key": key,
                    "label": _ENTITLEMENT_LABELS[key],
                    "values": sorted(set(values)),
                }
            )
        required = info.get("UIRequiredDeviceCapabilities")
        if isinstance(required, dict):
            required_capabilities = sorted(
                str(key) for key, enabled in required.items() if enabled is not False
            )
        else:
            required_capabilities = _string_values(required)
        required_capabilities = [
            value for value in required_capabilities if value.lower() != "arm64"
        ]
        kind = "App"
        if path.lower().endswith(".appex"):
            kind = "Extension"
        elif path != ".":
            kind = "Embedded app"
        targets.append(
            {
                "path": path,
                "name": str(
                    info.get("CFBundleDisplayName")
                    or info.get("CFBundleName")
                    or fallback_name
                ),
                "bundleID": str(info.get("CFBundleIdentifier") or ""),
                "kind": kind,
                "extensionPoint": str(extension.get("NSExtensionPointIdentifier") or ""),
                "permissions": sorted(permissions, key=lambda item: item["label"]),
                "backgroundModes": _string_values(info.get("UIBackgroundModes")),
                "backgroundTasks": _string_values(info.get("BGTaskSchedulerPermittedIdentifiers")),
                "urlSchemes": sorted(url_schemes),
                "queriedSchemes": _string_values(info.get("LSApplicationQueriesSchemes")),
                "bonjourServices": _string_values(info.get("NSBonjourServices")),
                "transportDomains": transport_domains,
                "requiredDeviceCapabilities": required_capabilities,
                "entitlements": entitlement_items,
            }
        )

    target_name_counts: dict[str, int] = {}
    for target in targets:
        key = str(target["name"]).casefold()
        target_name_counts[key] = target_name_counts.get(key, 0) + 1
    for target in targets:
        if target["path"] == "." or target_name_counts[str(target["name"]).casefold()] < 2:
            continue
        target["name"] = Path(str(target["path"])).stem

    manifests = [
        manifest
        for record in records
        if (manifest := _privacy_manifest(record, app_bundle_name)) is not None
    ]
    manifests.sort(key=lambda item: (item["source"] != "app", item["path"].lower()))
    declaration_count = sum(
        len(target["permissions"])
        + len(target["backgroundModes"])
        + len(target["backgroundTasks"])
        + len(target["urlSchemes"])
        + len(target["queriedSchemes"])
        + len(target["bonjourServices"])
        + len(target["transportDomains"])
        + len(target["requiredDeviceCapabilities"])
        + len(target["entitlements"])
        + bool(target["extensionPoint"])
        for target in targets
    )
    return {
        "targets": targets,
        "privacyManifests": manifests,
        "declarationCount": declaration_count,
    }


def _strip_strings_comments(value: str) -> str:
    output: list[str] = []
    index = 0
    quoted = False
    while index < len(value):
        character = value[index]
        if quoted:
            output.append(character)
            if character == "\\" and index + 1 < len(value):
                index += 1
                output.append(value[index])
            elif character == '"':
                quoted = False
            index += 1
            continue
        if character == '"':
            quoted = True
            output.append(character)
            index += 1
            continue
        if value.startswith("//", index):
            newline = value.find("\n", index + 2)
            index = len(value) if newline < 0 else newline
            continue
        if value.startswith("/*", index):
            end = value.find("*/", index + 2)
            index = len(value) if end < 0 else end + 2
            continue
        output.append(character)
        index += 1
    return "".join(output)


def _unescape_strings_token(value: str) -> str:
    value = value[1:-1] if value.startswith('"') and value.endswith('"') else value

    def unicode_escape(match: re.Match[str]) -> str:
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)

    value = re.sub(r"\\U([0-9a-fA-F]{4,8})", unicode_escape, value)
    replacements = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
    return re.sub(r"\\(.)", lambda match: replacements.get(match.group(1), match.group(1)), value)


def _localized_value(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return repr(value)


def _read_localized_table(path: Path) -> dict[str, str] | None:
    if path.suffix.lower() not in {".strings", ".stringsdict"}:
        return None
    try:
        payload = path.read_bytes()
    except OSError:
        return None
    try:
        value = plistlib.loads(payload)
    except (plistlib.InvalidFileException, ValueError):
        value = None
    if isinstance(value, dict):
        return {str(key): _localized_value(item) for key, item in value.items()}
    if path.suffix.lower() != ".strings":
        return None
    text: str | None = None
    for encoding in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"):
        try:
            text = payload.decode(encoding)
            break
        except (UnicodeDecodeError, UnicodeError):
            continue
    if text is None:
        return None
    text = _strip_strings_comments(text)
    pairs = re.finditer(
        r'(?P<key>"(?:\\.|[^"\\])*"|[A-Za-z0-9_.-]+)\s*=\s*'
        r'(?P<value>"(?:\\.|[^"\\])*")\s*;',
        text,
        re.DOTALL,
    )
    values = {
        _unescape_strings_token(match.group("key")): _unescape_strings_token(match.group("value"))
        for match in pairs
    }
    return values or None


def _locale_from_path(relative_path: str) -> tuple[str, int] | None:
    parts = relative_path.split("/")
    for index, part in enumerate(parts):
        if part.lower().endswith(".lproj") and len(part) > len(".lproj"):
            return part[: -len(".lproj")], index
    return None


def _locale_preference(locale: str) -> int:
    lowered = locale.lower().replace("_", "-")
    if lowered == "en":
        return 3
    if lowered == "base":
        return 2
    if lowered.startswith("en-"):
        return 1
    return 0


def _collect_localizations(
    records: list[Record], app_bundle_name: str
) -> dict[str, Any]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    tables: dict[tuple[str, str], dict[str, dict[str, str]]] = {}
    for record in records:
        localized = _locale_from_path(record.relative_path)
        if localized is None:
            continue
        locale, locale_index = localized
        context = _bundle_context(record.relative_path, app_bundle_name)
        row_key = (context["bundlePath"], locale)
        row = rows.setdefault(
            row_key,
            {
                **context,
                "locale": locale,
                "fileCount": 0,
                "size": 0,
                "parsedFileCount": 0,
                "keyCount": 0,
                "referenceLocale": None,
                "comparedKeyCount": None,
                "missingKeyCount": None,
                "identicalValueCount": None,
            },
        )
        row["fileCount"] += 1
        row["size"] += record.size
        parsed = _read_localized_table(record.absolute_path)
        if parsed is None:
            continue
        row["parsedFileCount"] += 1
        row["keyCount"] += len(parsed)
        parts = record.relative_path.split("/")
        table_path = "/".join(parts[locale_index + 1 :])
        tables.setdefault((context["bundlePath"], table_path), {})[locale] = parsed

    rows_by_bundle: dict[str, list[dict[str, Any]]] = {}
    for row in rows.values():
        rows_by_bundle.setdefault(row["bundlePath"], []).append(row)
    for bundle_path, bundle_rows in rows_by_bundle.items():
        coverage: dict[str, tuple[int, int]] = {}
        for (table_bundle, _), localized_tables in tables.items():
            if table_bundle != bundle_path:
                continue
            for locale, values in localized_tables.items():
                files, keys = coverage.get(locale, (0, 0))
                coverage[locale] = (files + 1, keys + len(values))
        if not coverage:
            continue
        maximum_file_coverage = max(files for files, _ in coverage.values())
        reference_candidates = [
            locale
            for locale, (files, _) in coverage.items()
            if files == maximum_file_coverage and _locale_preference(locale) > 0
        ]
        if not reference_candidates:
            continue
        reference = max(
            reference_candidates,
            key=lambda locale: (
                _locale_preference(locale),
                coverage[locale][1],
                locale.lower(),
            ),
        )
        reference_tables = {
            table_path: localized_tables[reference]
            for (table_bundle, table_path), localized_tables in tables.items()
            if table_bundle == bundle_path and reference in localized_tables
        }
        for row in bundle_rows:
            if row["locale"].lower() == "base":
                continue
            row["referenceLocale"] = reference
            if (
                row["locale"] == reference
                or not reference_tables
            ):
                continue
            compared = 0
            missing = 0
            identical = 0
            for table_path, reference_values in reference_tables.items():
                current = tables.get((bundle_path, table_path), {}).get(row["locale"], {})
                compared += len(reference_values)
                missing += len(set(reference_values) - set(current))
                identical += sum(
                    current.get(key) == value
                    for key, value in reference_values.items()
                    if key in current
                )
            row["comparedKeyCount"] = compared
            row["missingKeyCount"] = missing
            row["identicalValueCount"] = identical

    output_rows = sorted(
        rows.values(),
        key=lambda row: (
            row["source"] != "app",
            row["target"].lower(),
            row["bundle"].lower(),
            row["locale"].lower(),
        ),
    )
    return {
        "rows": output_rows,
        "localeCount": len({row["locale"] for row in output_rows}),
        "bundleCount": len({row["bundlePath"] for row in output_rows}),
        "fileCount": sum(row["fileCount"] for row in output_rows),
        "size": sum(row["size"] for row in output_rows),
    }


def _app_icon_data_url(
    app_root: Path,
    info_plist: dict[str, Any],
    platform: AnalysisPlatform,
) -> str | None:
    """Embed one small shipped icon so the offline report feels app-specific."""

    stems: list[str] = []
    for key in ("CFBundleIcons", "CFBundleIcons~ipad"):
        icons = info_plist.get(key)
        primary = icons.get("CFBundlePrimaryIcon") if isinstance(icons, dict) else None
        files = primary.get("CFBundleIconFiles") if isinstance(primary, dict) else None
        if isinstance(files, list):
            stems.extend(str(item) for item in files if item)
    candidates: set[Path] = set()
    for stem in stems:
        path = app_root / stem
        if path.is_file():
            candidates.add(path)
        if not path.suffix:
            candidates.update(app_root.glob(f"{path.name}*.png"))
    candidates.update(app_root.glob("AppIcon*.png"))
    usable = [
        path
        for path in candidates
        if path.is_file() and 0 < path.stat().st_size <= 2 * 1024 * 1024
    ]
    # Browser catalog analysis may have produced a normalized preview even
    # when the app ships no loose icon. Native platforms simply return None
    # for this sentinel path.
    icon = (
        max(usable, key=lambda path: path.stat().st_size)
        if usable
        else app_root / "Assets.car"
    )
    payload = platform.icon_png(icon)
    if payload is None:
        return None
    try:
        encoded = base64.b64encode(payload).decode("ascii")
    except (TypeError, ValueError):
        return None
    return f"data:image/png;base64,{encoded}"


def _looks_like_lottie(path: Path, size: int) -> dict[str, Any] | None:
    if path.suffix.lower() != ".json" or size > 30 * 1024 * 1024:
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or not {"layers", "fr", "ip", "op"}.issubset(value):
        return None
    layers = value.get("layers")
    assets = value.get("assets")
    layer_types = []
    if isinstance(layers, list):
        for layer in layers:
            if isinstance(layer, dict):
                layer_types.append(
                    (
                        int(layer.get("ty", -1)) if isinstance(layer.get("ty"), int) else -1,
                        str(layer.get("nm", "")).lower().strip(),
                    )
                )
    signature_value = {
        "w": value.get("w"),
        "h": value.get("h"),
        "fr": value.get("fr"),
        "duration": (
            float(value.get("op", 0)) - float(value.get("ip", 0))
            if isinstance(value.get("op"), (int, float))
            and isinstance(value.get("ip"), (int, float))
            else None
        ),
        "types": [item[0] for item in layer_types],
        "names": [re.sub(r"\d+", "#", item[1]) for item in layer_types],
    }
    signature = hashlib.sha256(
        json.dumps(signature_value, sort_keys=True).encode()
    ).hexdigest()
    return {
        "version": value.get("v"),
        "width": value.get("w"),
        "height": value.get("h"),
        "frameRate": value.get("fr"),
        "layerCount": len(layers) if isinstance(layers, list) else 0,
        "assetCount": len(assets) if isinstance(assets, list) else 0,
        "structureSignature": signature,
    }


def _normalize_virtual_sizes(
    children: list[dict[str, Any]], file_size: int, overhead_name: str
) -> list[dict[str, Any]]:
    total = sum(max(0, int(child.get("size", 0))) for child in children)
    if total > file_size and total:
        scale = file_size / total
        consumed = 0
        for index, child in enumerate(children):
            original = int(child.get("size", 0))
            child.setdefault("metadata", {})["reportedSize"] = original
            if index == len(children) - 1:
                adjusted = max(0, file_size - consumed)
            else:
                adjusted = max(1, int(original * scale))
                consumed += adjusted
            child["size"] = adjusted
            child["compressedSize"] = adjusted
            child["allocatedSize"] = adjusted
        return children
    if total < file_size:
        remainder = file_size - total
        children.append(
            {
                "name": overhead_name,
                "path": "",
                "kind": "virtual",
                "category": "metadata",
                "size": remainder,
                "compressedSize": remainder,
                "allocatedSize": remainder,
                "children": [],
                "metadata": {},
                "insights": [],
            }
        )
    return children


def _assign_virtual_delivery_sizes(
    children: list[dict[str, Any]], install_size: int, download_size: int
) -> None:
    if not children:
        return
    universal_size = sum(max(0, int(child.get("size", 0))) for child in children)
    if universal_size <= 0:
        return

    def assign(metric: str, total: int) -> None:
        consumed = 0
        for index, child in enumerate(children):
            if index == len(children) - 1:
                value = max(0, total - consumed)
            else:
                value = max(
                    0,
                    total * int(child.get("size", 0)) // universal_size,
                )
                consumed += value
            child[metric] = value

    assign("installSize", install_size)
    assign("downloadSize", download_size)
    for child in children:
        nested = child.get("children", [])
        if isinstance(nested, list) and nested:
            _assign_virtual_delivery_sizes(
                nested,
                int(child.get("installSize", 0)),
                int(child.get("downloadSize", 0)),
            )


def _integer(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return 0


def _claim_segment_ranges(
    ranges: Iterable[tuple[int, int]],
    segment_offset: int,
    segment_size: int,
    claimed: list[tuple[int, int]],
) -> list[tuple[int, int]]:
    """Claim the still-unattributed portions of slice-relative file ranges."""

    segment_end = segment_offset + max(0, segment_size)
    fragments: list[tuple[int, int]] = []
    for raw_offset, raw_size in ranges:
        offset = _integer(raw_offset)
        size = _integer(raw_size)
        if offset < 0 or size <= 0:
            continue
        start = max(segment_offset, offset)
        end = min(segment_end, offset + size)
        if end <= start:
            continue

        available = [(start, end)]
        for claimed_start, claimed_end in sorted(claimed):
            remaining: list[tuple[int, int]] = []
            for available_start, available_end in available:
                if (
                    claimed_end <= available_start
                    or claimed_start >= available_end
                ):
                    remaining.append((available_start, available_end))
                    continue
                if available_start < claimed_start:
                    remaining.append((available_start, claimed_start))
                if claimed_end < available_end:
                    remaining.append((claimed_end, available_end))
            available = remaining
            if not available:
                break
        fragments.extend(available)
        claimed.extend(available)
    return fragments


def _mach_o_metadata_regions(
    slice_info: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return named file regions described by non-section Mach-O commands."""

    regions: list[dict[str, Any]] = []
    symbol_table = slice_info.get("symbol_table") or {}
    if isinstance(symbol_table, dict):
        symbol_count = max(0, _integer(symbol_table.get("count")))
        entry_size = max(0, _integer(symbol_table.get("entry_size")))
        strip = symbol_table.get("strip_rSTx") or {}
        regions.extend(
            (
                {
                    "name": "Symbol records",
                    "kind": "symbol-records",
                    "ranges": [
                        (
                            _integer(symbol_table.get("offset")),
                            _integer(symbol_table.get("entry_bytes")),
                        )
                    ],
                    "metadata": {
                        "loadCommand": "LC_SYMTAB",
                        "symbolCount": symbol_count,
                        "entrySize": entry_size,
                        "removableEstimate": max(
                            0, _integer(strip.get("candidate_entry_bytes"))
                        ),
                    },
                },
                {
                    "name": "Symbol string table",
                    "kind": "symbol-strings",
                    "ranges": [
                        (
                            _integer(symbol_table.get("string_offset")),
                            _integer(symbol_table.get("string_bytes")),
                        )
                    ],
                    "metadata": {
                        "loadCommand": "LC_SYMTAB",
                        "symbolCount": symbol_count,
                        "removableEstimate": max(
                            0, _integer(strip.get("estimated_string_bytes"))
                        ),
                    },
                },
            )
        )

    export_trie = slice_info.get("export_trie") or {}
    if isinstance(export_trie, dict):
        regions.append(
            {
                "name": "Dyld export trie",
                "kind": "export-trie",
                "ranges": [
                    (
                        _integer(export_trie.get("offset")),
                        _integer(export_trie.get("size")),
                    )
                ],
                "metadata": {
                    "loadCommand": str(export_trie.get("source") or "dyld-info"),
                    "symbolCount": max(
                        0, _integer(export_trie.get("symbol_count"))
                    ),
                },
            }
        )

    def command_regions(key: str) -> list[dict[str, Any]]:
        value = slice_info.get(key)
        if not isinstance(value, list):
            return []
        return [
            item
            for item in value
            if isinstance(item, dict) and item.get("valid") is not False
        ]

    fixups = command_regions("fixup_regions")
    if fixups:
        regions.append(
            {
                "name": "Fixups",
                "kind": "fixups",
                "ranges": [
                    (_integer(item.get("offset")), _integer(item.get("size")))
                    for item in fixups
                ],
                "metadata": {
                    "loadCommands": sorted(
                        {str(item.get("source") or "dyld-info") for item in fixups}
                    )
                },
            }
        )

    dynamic_tables = command_regions("dynamic_linking_regions")
    if dynamic_tables:
        regions.append(
            {
                "name": "Dynamic linking tables",
                "kind": "dynamic-linking",
                "ranges": [
                    (_integer(item.get("offset")), _integer(item.get("size")))
                    for item in dynamic_tables
                ],
                "metadata": {
                    "loadCommands": sorted(
                        {
                            str(item.get("source") or "LC_DYSYMTAB")
                            for item in dynamic_tables
                        }
                    )
                },
            }
        )

    code_signature = slice_info.get("code_signature") or {}
    if isinstance(code_signature, dict):
        regions.append(
            {
                "name": "Code signature",
                "kind": "code-signature",
                "ranges": [
                    (
                        _integer(code_signature.get("offset")),
                        _integer(code_signature.get("size")),
                    )
                ],
                "metadata": {"loadCommand": "LC_CODE_SIGNATURE"},
            }
        )
    return regions


def _binary_segment_parts(
    slice_info: dict[str, Any], segment: dict[str, Any]
) -> list[dict[str, Any]]:
    """Partition one file-backed segment without double-counting regions."""

    segment_offset = _integer(segment.get("file_offset"))
    segment_size = max(0, _integer(segment.get("size")))
    raw_sections = [
        section
        for section in segment.get("sections", [])
        if isinstance(section, dict) and _integer(section.get("size")) > 0
    ]
    precise_sections = all("file_offset" in section for section in raw_sections)
    if not precise_sections:
        return [
            {
                "name": str(section.get("name") or "Unnamed section"),
                "kind": "section",
                "size": max(0, _integer(section.get("size"))),
                "virtualSize": max(
                    0, _integer(section.get("virtual_size"))
                ),
                "fileOffset": None,
                "metadata": {},
            }
            for section in raw_sections
        ]

    claimed: list[tuple[int, int]] = []
    parts: list[dict[str, Any]] = []
    for section in raw_sections:
        fragments = _claim_segment_ranges(
            [
                (
                    _integer(section.get("file_offset")),
                    _integer(section.get("size")),
                )
            ],
            segment_offset,
            segment_size,
            claimed,
        )
        size = sum(end - start for start, end in fragments)
        if size <= 0:
            continue
        reported_size = max(0, _integer(section.get("size")))
        metadata: dict[str, Any] = {}
        if size != reported_size:
            metadata["reportedSize"] = reported_size
        parts.append(
            {
                "name": str(section.get("name") or "Unnamed section"),
                "kind": "section",
                "size": size,
                "virtualSize": max(
                    0, _integer(section.get("virtual_size"))
                ),
                "fileOffset": min(start for start, _ in fragments),
                "metadata": metadata,
            }
        )

    for region in _mach_o_metadata_regions(slice_info):
        ranges = list(region.get("ranges") or [])
        fragments = _claim_segment_ranges(
            ranges, segment_offset, segment_size, claimed
        )
        size = sum(end - start for start, end in fragments)
        if size <= 0:
            continue
        reported_size = sum(max(0, _integer(item[1])) for item in ranges)
        metadata = {
            "attribution": "load-command",
            **dict(region.get("metadata") or {}),
            "fileRanges": [
                {"offset": start, "size": end - start}
                for start, end in fragments
            ],
        }
        if size != reported_size:
            metadata["reportedSize"] = reported_size
        parts.append(
            {
                "name": str(region["name"]),
                "kind": str(region["kind"]),
                "size": size,
                "virtualSize": size,
                "fileOffset": min(start for start, _ in fragments),
                "metadata": metadata,
            }
        )
    return parts


def _binary_children(
    info: dict[str, Any],
    file_size: int,
    relative_path: str,
    compile_units: list[dict[str, int | str]] | None,
) -> list[dict[str, Any]]:
    if compile_units:
        children = [
            {
                "name": str(unit["name"]),
                "path": f"{relative_path}::{unit['name']}",
                "kind": "compile-unit",
                "category": "binary_section",
                "size": int(unit["size"]),
                "compressedSize": int(unit["size"]),
                "allocatedSize": int(unit["size"]),
                "children": [],
                "metadata": {"attribution": "linkmap"},
                "insights": [],
            }
            for unit in compile_units
            if int(unit["size"]) > 0
        ]
        return _normalize_virtual_sizes(children, file_size, "Unattributed binary data")

    def slice_children(slice_info: dict[str, Any], prefix: str) -> list[dict[str, Any]]:
        nodes: list[dict[str, Any]] = []
        for segment in slice_info.get("segments", []):
            segment_size = int(segment.get("size", 0))
            if segment_size <= 0:
                continue
            section_nodes = [
                {
                    "name": str(part.get("name") or "Unnamed section"),
                    "path": f"{prefix}::{segment.get('name')}::{part.get('name')}",
                    "kind": str(part.get("kind") or "section"),
                    "category": "binary_section",
                    "size": int(part.get("size", 0)),
                    "compressedSize": int(part.get("size", 0)),
                    "allocatedSize": int(part.get("size", 0)),
                    "children": [],
                    "metadata": {
                        "segment": segment.get("name"),
                        "virtualSize": part.get("virtualSize", 0),
                        "fileOffset": part.get("fileOffset"),
                        **dict(part.get("metadata") or {}),
                    },
                    "insights": [],
                }
                for part in _binary_segment_parts(slice_info, segment)
                if int(part.get("size", 0)) > 0
            ]
            other_name = (
                "Other __LINKEDIT data"
                if str(segment.get("name") or "") == "__LINKEDIT"
                else "Other segment data"
            )
            section_nodes = _normalize_virtual_sizes(
                section_nodes, segment_size, other_name
            )
            for child in section_nodes:
                if not child.get("path"):
                    child["path"] = (
                        f"{prefix}::{segment.get('name')}::{child.get('name')}"
                    )
            nodes.append(
                {
                    "name": str(segment.get("name") or "Unnamed segment"),
                    "path": f"{prefix}::{segment.get('name')}",
                    "kind": "segment",
                    "category": "binary_section",
                    "size": segment_size,
                    "compressedSize": segment_size,
                    "allocatedSize": segment_size,
                    "children": section_nodes,
                    "metadata": {
                        "virtualSize": segment.get("virtual_size", 0),
                        "fileOffset": segment.get("file_offset", 0),
                    },
                    "insights": [],
                }
            )
        return _normalize_virtual_sizes(
            nodes, int(slice_info.get("size", file_size)), "Mach-O headers & padding"
        )

    architectures = info.get("architectures", [])
    if info.get("is_fat"):
        slices = []
        for architecture in architectures:
            arch_name = str(architecture.get("architecture", "Architecture"))
            arch_size = int(architecture.get("size", 0))
            slices.append(
                {
                    "name": arch_name,
                    "path": f"{relative_path}::{arch_name}",
                    "kind": "architecture",
                    "category": "binary_section",
                    "size": arch_size,
                    "compressedSize": arch_size,
                    "allocatedSize": arch_size,
                    "children": slice_children(
                        architecture, f"{relative_path}::{arch_name}"
                    ),
                    "metadata": {
                        "platform": architecture.get("platform"),
                        "minimumOS": architecture.get("minimum_os"),
                        "sdk": architecture.get("sdk"),
                    },
                    "insights": [],
                }
            )
        return _normalize_virtual_sizes(slices, file_size, "Fat binary headers & alignment")
    if architectures:
        return slice_children(architectures[0], relative_path)
    return []


def _linkmap_for_binary(binary: Record, linkmaps: Iterable[Path]) -> list[dict[str, int | str]]:
    name = binary.name.lower()
    candidates = [item for item in linkmaps if name in item.stem.lower()]
    if not candidates:
        return []
    candidates.sort(key=lambda item: (len(item.name), str(item)))
    return parse_linkmap(candidates[0])


def _safe_version_at_least(value: str | None, major: int) -> bool:
    if not value:
        return True
    try:
        return int(str(value).split(".", 1)[0]) >= major
    except ValueError:
        return True


def _is_duplicate_candidate(record: Record) -> bool:
    lower = record.relative_path.lower()
    if record.size < 1024 or record.category in {
        "signature",
        "metadata",
        "localization",
        "interface",
    }:
        return False
    # Multiple required app-icon slots commonly contain identical bytes but
    # cannot be collapsed safely. Treating them as removable is a large and
    # misleading false positive in real App Store IPAs.
    if "appicon" in lower:
        return False
    if record.category == "binary":
        return False
    if Path(lower).name in {"info.plist", "coderesources"}:
        return False
    return True


def _is_unnecessary(record: Record) -> bool:
    path = Path(record.relative_path)
    lower_name = path.name.lower()
    lower_parts = {part.lower() for part in path.parts}
    if lower_name in UNNECESSARY_NAMES or path.suffix.lower() in UNNECESSARY_SUFFIXES:
        return True
    if "__macosx" in lower_parts or "headers" in lower_parts:
        return True
    return False


def _framework_name(path: str) -> str | None:
    for part in Path(path).parts:
        if part.lower().endswith(".framework"):
            return part[: -len(".framework")]
    return None


def _framework_binary_identity(path: str) -> tuple[str, str] | None:
    """Return the innermost framework and binary names from a bundle path."""

    parts = Path(path).parts
    framework = next(
        (
            part[: -len(".framework")]
            for part in reversed(parts[:-1])
            if part.lower().endswith(".framework")
        ),
        None,
    )
    if not framework or not parts:
        return None
    return framework, parts[-1]


def _framework_bundle_path(path: str) -> str | None:
    """Return the innermost framework bundle containing a relative path."""

    parts = Path(path).parts
    index = next(
        (
            index
            for index in range(len(parts) - 1, -1, -1)
            if parts[index].lower().endswith(".framework")
        ),
        None,
    )
    return Path(*parts[: index + 1]).as_posix() if index is not None else None


def _embedded_bundle_root(path: str) -> str:
    """Return the app, extension, or XPC directory containing ``path``."""

    parts = PurePosixPath(path).parts
    boundary = 0
    for index, part in enumerate(parts[:-1], start=1):
        if part.lower().endswith((".app", ".appex", ".xpc")):
            boundary = index
    return PurePosixPath(*parts[:boundary]).as_posix() if boundary else ""


def _embedded_bundle_scope(path: str) -> str:
    """Identify the app/extension containing a relative bundle path."""

    return _embedded_bundle_root(path).casefold()


def _normalized_bundle_path(base: str, suffix: str) -> str | None:
    """Join two bundle-relative paths without allowing an escape above root."""

    suffix_path = PurePosixPath(suffix)
    if suffix_path.is_absolute():
        return None
    parts: list[str] = []
    for part in (*PurePosixPath(base).parts, *suffix_path.parts):
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
            continue
        parts.append(part)
    return PurePosixPath(*parts).as_posix() if parts else ""


def _expand_loader_path(value: str, consumer_path: str) -> str | None:
    """Expand one LC_RPATH or dependency loader token inside the app bundle."""

    loader_root = PurePosixPath(consumer_path).parent.as_posix()
    if loader_root == ".":
        loader_root = ""
    executable_root = _embedded_bundle_root(consumer_path)
    for token, base in (
        ("@loader_path", loader_root),
        ("@executable_path", executable_root),
    ):
        if value == token:
            return base
        if value.startswith(f"{token}/"):
            return _normalized_bundle_path(base, value[len(token) + 1 :])
    return None


def _resolved_dependency_paths(
    dependency: str,
    rpaths: Iterable[str],
    consumer_path: str,
    inherited_rpaths: Iterable[tuple[str, str]] = (),
) -> set[str]:
    """Resolve supported dyld tokens to exact paths in the extracted bundle."""

    if dependency.startswith(("@loader_path/", "@executable_path/")):
        resolved = _expand_loader_path(dependency, consumer_path)
        return {resolved} if resolved is not None else set()
    if not dependency.startswith("@rpath/"):
        return set()

    suffix = dependency[len("@rpath/") :]
    resolved_paths: set[str] = set()
    runpaths = [
        (raw_rpath, consumer_path)
        for raw_rpath in rpaths
        if isinstance(raw_rpath, str)
    ]
    runpaths.extend(inherited_rpaths)
    for raw_rpath, origin_path in runpaths:
        if not isinstance(raw_rpath, str):
            continue
        expanded = _expand_loader_path(raw_rpath.strip(), origin_path)
        if expanded is None:
            continue
        resolved = _normalized_bundle_path(expanded, suffix)
        if resolved is not None:
            resolved_paths.add(resolved)
    return resolved_paths


def _framework_consumers(
    records: Iterable[Record],
    dynamic_frameworks: Iterable[Record],
    target_executables: dict[str, str],
) -> tuple[dict[str, list[str]], set[str]]:
    """Resolve embedded framework load commands to their bundled consumers."""

    all_records = list(records)
    frameworks = list(dynamic_frameworks)
    by_identity: dict[tuple[str, str], list[Record]] = {}
    by_path: dict[str, Record] = {}
    for framework in frameworks:
        by_path[framework.relative_path] = framework
        identity = _framework_binary_identity(framework.relative_path)
        if identity is None:
            continue
        by_identity.setdefault(identity, []).append(framework)

    consumers: dict[str, set[str]] = {
        framework.relative_path: set() for framework in frameworks
    }
    unresolved: set[str] = (
        {framework.relative_path for framework in frameworks}
        if any(record.metadata.get("machoParseFailed") for record in all_records)
        else set()
    )

    # dyld's @rpath lookup carries the process executable's run paths down the
    # dependency chain. A framework often lists only /usr/lib/swift itself,
    # while its app or extension executable supplies @executable_path/Frameworks.
    executable_rpaths: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for record in all_records:
        if not record.macho:
            continue
        scope = _embedded_bundle_scope(record.relative_path)
        if target_executables.get(scope) != record.relative_path:
            continue
        for architecture in record.macho.get("architectures", []):
            if not (
                architecture.get("is_executable")
                or architecture.get("file_type") == "executable"
            ):
                continue
            architecture_name = str(architecture.get("architecture") or "")
            values = executable_rpaths.setdefault((scope, architecture_name), [])
            for rpath in architecture.get("rpaths", []):
                pair = (rpath, record.relative_path)
                if isinstance(rpath, str) and pair not in values:
                    values.append(pair)

    for consumer in all_records:
        if not consumer.macho:
            continue
        architectures = list(consumer.macho.get("architectures", []))
        if not any("dependencies" in architecture for architecture in architectures):
            # Record metadata keeps older fixtures/reports readable. Since it
            # has no per-architecture run paths, @rpath dependencies remain
            # incomplete rather than becoming guessed consumers.
            architectures = [
                {
                    "dependencies": consumer.metadata.get("dependencies", []),
                    "rpaths": consumer.metadata.get("rpaths", []),
                }
            ]

        for architecture in architectures:
            raw_dependencies = architecture.get("dependencies", [])
            raw_rpaths = architecture.get("rpaths", [])
            if not isinstance(raw_dependencies, (list, tuple, set)):
                continue
            if not isinstance(raw_rpaths, (list, tuple, set)):
                raw_rpaths = []
            architecture_name = str(architecture.get("architecture") or "")
            inherited_rpaths = executable_rpaths.get(
                (_embedded_bundle_scope(consumer.relative_path), architecture_name),
                [],
            )
            for raw_dependency in raw_dependencies:
                if not isinstance(raw_dependency, str):
                    continue
                dependency = raw_dependency.strip()
                if not dependency or dependency.startswith("/"):
                    continue
                if dependency.startswith("@") and not dependency.startswith(
                    ("@rpath/", "@loader_path/", "@executable_path/")
                ):
                    continue
                identity = _framework_binary_identity(dependency)
                if identity is None:
                    continue
                candidates = by_identity.get(identity, [])
                resolved = {
                    path
                    for path in _resolved_dependency_paths(
                        dependency,
                        raw_rpaths,
                        consumer.relative_path,
                        inherited_rpaths,
                    )
                    if path in by_path
                }
                if len(resolved) != 1:
                    unresolved.update(
                        framework.relative_path for framework in candidates
                    )
                    continue
                target = by_path[resolved.pop()]
                if target.relative_path != consumer.relative_path:
                    consumers[target.relative_path].add(consumer.relative_path)

    return (
        {
            path: sorted(paths, key=lambda value: (value.casefold(), value))
            for path, paths in consumers.items()
        },
        unresolved,
    )


def _component_duplicate_groups(
    records: list[Record],
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    """Fingerprint complete embedded components, ignoring signing-only files."""

    manifests: dict[str, list[tuple[str, int, str]]] = {}
    component_kind: dict[str, str] = {}
    component_suffixes = (".framework", ".bundle", ".appex", ".app")
    for record in records:
        parts = Path(record.relative_path).parts
        for index, part in enumerate(parts[:-1]):
            lower = part.lower()
            suffix = next(
                (candidate for candidate in component_suffixes if lower.endswith(candidate)),
                None,
            )
            if not suffix:
                continue
            component_path = Path(*parts[: index + 1]).as_posix()
            within = Path(*parts[index + 1 :]).as_posix()
            within_lower = within.lower()
            if (
                "__codesignature" in {item.lower() for item in Path(within).parts}
                or Path(within_lower).name == "coderesources"
                or Path(within_lower).name == "embedded.mobileprovision"
            ):
                continue
            manifests.setdefault(component_path, []).append(
                (within, record.size, record.sha256)
            )
            component_kind[component_path] = suffix[1:]

    fingerprints: dict[tuple[str, int, str], list[str]] = {}
    component_sizes: dict[str, int] = {}
    for component_path, entries in manifests.items():
        if not entries:
            continue
        total = sum(size for _, size, _ in entries)
        if total < 4 * 1024:
            continue
        digest = hashlib.sha256()
        for relative, size, file_digest in sorted(entries):
            digest.update(relative.encode("utf-8", "surrogateescape"))
            digest.update(b"\0")
            digest.update(str(size).encode())
            digest.update(b"\0")
            digest.update(file_digest.encode())
            digest.update(b"\n")
        key = (component_kind[component_path], total, digest.hexdigest())
        fingerprints.setdefault(key, []).append(component_path)
        component_sizes[component_path] = total

    group_map: dict[str, str] = {}
    items: list[dict[str, Any]] = []
    group_index = 1
    for (kind, size, _), paths in sorted(
        fingerprints.items(), key=lambda item: item[0][1], reverse=True
    ):
        if len(paths) < 2:
            continue
        group_id = f"C{group_index}"
        group_index += 1
        for path in paths:
            group_map[path] = group_id
        # Component paths end at the bundle directory, while the scope helper
        # normally receives a file below that directory. Add an inert child so
        # an .appex/.app component is recognized as its own runtime boundary.
        scopes = {_embedded_bundle_scope(f"{path}/_") for path in paths}
        items.append(
            {
                "group": group_id,
                "name": Path(paths[0]).name,
                "kind": kind,
                "duplicateType": "component",
                "scope": "cross-target" if len(scopes) > 1 else "same-runtime",
                "actionability": "review",
                "size": size,
                "copies": len(paths),
                "pathCount": len(paths),
                "paths": paths,
            }
        )
    return group_map, items


def _cross_target_asset_catalog_items(
    records: list[Record],
    asset_renditions: Iterable[dict[str, Any]],
    exact_catalog_sets: Iterable[frozenset[str]] = (),
) -> list[dict[str, Any]]:
    """Find exact rendition overlap across independently loaded targets.

    Same-runtime catalog overlap is an actionable recommendation and is handled
    by :meth:`BundleAnalyzer._duplicate_insight`.  An extension cannot be
    assumed to load the containing app's resources, but identical compiled
    renditions still represent shipped duplication and useful target-membership
    evidence.  Keep that separate from claimed recommendation savings while
    annotating the catalogs and assets so the treemap remains honest.
    """

    record_by_path = {record.relative_path: record for record in records}
    covered_catalog_sets = [set(paths) for paths in exact_catalog_sets if paths]
    grouped: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for rendition in asset_renditions:
        rendition_path = str(
            rendition.get("displayPath") or rendition.get("path") or ""
        ).lower()
        digest = rendition.get("digest")
        size = int(rendition.get("size", 0) or 0)
        if "appicon" in rendition_path or not digest or size < 1024:
            continue
        grouped.setdefault((str(digest), size), []).append(rendition)

    asset_groups: list[dict[str, Any]] = []
    for values in sorted(
        grouped.values(),
        key=lambda group: (
            -(int(group[0].get("size", 0) or 0)),
            tuple(
                sorted(
                    str(item.get("displayPath") or item.get("path") or "")
                    for item in group
                )
            ),
        ),
    ):
        catalog_paths = sorted(
            {
                str(item.get("path") or "").split("::", 1)[0]
                for item in values
                if str(item.get("path") or "").split("::", 1)[0]
            },
            key=lambda value: (value.casefold(), value),
        )
        scopes = {_embedded_bundle_scope(path) for path in catalog_paths}
        if len(catalog_paths) < 2 or len(scopes) < 2:
            continue
        if any(set(catalog_paths).issubset(paths) for paths in covered_catalog_sets):
            # An exact cross-target Assets.car match is already clearer and
            # cheaper to represent as one whole-file row.
            continue

        group_id = f"XA{len(asset_groups) + 1}"
        size = int(values[0].get("size", 0) or 0)
        display_paths = sorted(
            {
                str(item.get("displayPath") or item.get("path") or "")
                for item in values
                if str(item.get("displayPath") or item.get("path") or "")
            },
            key=lambda value: (value.casefold(), value),
        )
        repeated_size = size * (len(scopes) - 1)
        asset_group = {
            "group": group_id,
            "name": str(values[0].get("name") or "Asset rendition"),
            "kind": "asset catalog rendition",
            "duplicateType": "asset",
            "scope": "cross-target",
            "actionability": "review",
            "size": size,
            "repeatedSize": repeated_size,
            "targetCount": len(scopes),
            "pathCount": len(display_paths),
            "paths": display_paths[:50],
            "pathsOmitted": max(0, len(display_paths) - 50),
            "catalogCount": len(catalog_paths),
            "catalogPaths": catalog_paths[:50],
            "catalogPathsOmitted": max(0, len(catalog_paths) - 50),
        }
        asset_groups.append(asset_group)
        for rendition in values:
            rendition_groups = rendition.setdefault("duplicateGroups", [])
            if group_id not in rendition_groups:
                rendition_groups.append(group_id)
            rendition["crossTargetDuplicateGroup"] = group_id
            if not rendition.get("duplicateGroup"):
                rendition["duplicateGroup"] = group_id
                rendition["duplicateType"] = "asset"
                rendition["scope"] = "cross-target"
                rendition["actionability"] = "review"

            entry = rendition.get("entry")
            if not isinstance(entry, dict):
                continue
            entry_groups = entry.setdefault("metadata", {}).setdefault(
                "duplicateGroups", []
            )
            if group_id not in entry_groups:
                entry_groups.append(group_id)
            entry_metadata = entry["metadata"]
            cross_groups = entry_metadata.setdefault(
                "crossTargetDuplicateGroups", []
            )
            if group_id not in cross_groups:
                cross_groups.append(group_id)
            entry_metadata["crossTargetDuplicateCount"] = len(cross_groups)
            entry_metadata["duplicateCount"] = len(entry_groups)
            if not entry.get("duplicateGroup"):
                entry["duplicateGroup"] = group_id
                entry["duplicateType"] = "asset"
                entry["scope"] = "cross-target"
                entry["actionability"] = "review"
            if "catalog-target-membership" not in entry.setdefault(
                "insights", []
            ):
                entry["insights"].append("catalog-target-membership")

    catalog_clusters: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for asset_group in asset_groups:
        catalog_paths = tuple(str(path) for path in asset_group["catalogPaths"])
        catalog_clusters.setdefault(catalog_paths, []).append(asset_group)

    items: list[dict[str, Any]] = []
    catalog_cluster_ids: dict[str, set[str]] = {}
    catalog_asset_counts: dict[str, int] = {}
    for index, (catalog_paths, groups) in enumerate(
        sorted(
            catalog_clusters.items(),
            key=lambda item: (
                -sum(int(group["repeatedSize"]) for group in item[1]),
                item[0],
            ),
        ),
        start=1,
    ):
        groups.sort(
            key=lambda item: (
                -int(item["repeatedSize"]),
                str(item["name"]).casefold(),
                str(item["group"]),
            )
        )
        group_id = f"XC{index}"
        scopes = {_embedded_bundle_scope(path) for path in catalog_paths}
        catalog_names = {Path(path).name for path in catalog_paths}
        items.append(
            {
                "group": group_id,
                "name": (
                    Path(catalog_paths[0]).name
                    if len(catalog_names) == 1
                    else "Asset catalog overlap"
                ),
                "kind": "asset catalog",
                "duplicateType": "catalog",
                "scope": "cross-target",
                "actionability": "review",
                "size": max(int(group["size"]) for group in groups),
                "repeatedSize": sum(
                    int(group["repeatedSize"]) for group in groups
                ),
                "targetCount": len(scopes),
                "pathCount": len(catalog_paths),
                "paths": list(catalog_paths[:50]),
                "pathsOmitted": max(0, len(catalog_paths) - 50),
                "catalogCount": len(catalog_paths),
                "catalogPaths": list(catalog_paths[:50]),
                "catalogPathsOmitted": max(0, len(catalog_paths) - 50),
                "repeatedAssetCount": len(groups),
                "repeatedRenditionCount": len(groups),
                "repeatedAssetNameCount": len(
                    {
                        str(group.get("name") or "").casefold()
                        for group in groups
                        if str(group.get("name") or "")
                    }
                ),
                "assetGroupCount": len(groups),
                "assetGroups": groups[:MAX_INSIGHT_ITEMS],
                "assetGroupsOmitted": max(0, len(groups) - MAX_INSIGHT_ITEMS),
                "exactMatch": False,
            }
        )
        for catalog_path in catalog_paths:
            catalog_cluster_ids.setdefault(catalog_path, set()).add(group_id)
            catalog_asset_counts[catalog_path] = (
                catalog_asset_counts.get(catalog_path, 0) + len(groups)
            )

    for catalog_path, cluster_ids in catalog_cluster_ids.items():
        catalog = record_by_path.get(catalog_path)
        if catalog is None:
            continue
        ordered_ids = sorted(cluster_ids, key=lambda value: (len(value), value))
        metadata = catalog.metadata
        all_groups = metadata.setdefault("duplicateGroups", [])
        for group_id in ordered_ids:
            if group_id not in all_groups:
                all_groups.append(group_id)
        cross_groups = metadata.setdefault("crossTargetDuplicateGroups", [])
        for group_id in ordered_ids:
            if group_id not in cross_groups:
                cross_groups.append(group_id)
        metadata["duplicateCount"] = len(all_groups)
        metadata["crossTargetDuplicateCount"] = len(cross_groups)
        metadata["crossTargetRepeatedAssetCount"] = catalog_asset_counts[
            catalog_path
        ]
        metadata["crossTargetRepeatedRenditionCount"] = catalog_asset_counts[
            catalog_path
        ]
        metadata.setdefault("duplicateType", "catalog")
        metadata.setdefault("duplicateGroup", ordered_ids[0])
        metadata.setdefault("duplicateCatalogGroup", ordered_ids[0])
        metadata.setdefault("scope", "cross-target")
        metadata.setdefault("actionability", "review")
        metadata.setdefault("exactMatch", False)
        if "catalog-target-membership" not in catalog.insight_ids:
            catalog.insight_ids.append("catalog-target-membership")

    return items


def _cross_target_duplicate_inventory(
    records: list[Record],
    component_duplicate_items: Iterable[dict[str, Any]] = (),
    asset_renditions: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Return exact repetition that spans independent runtime bundles."""

    groups: dict[tuple[str, int], list[Record]] = {}
    for record in records:
        if _is_duplicate_candidate(record):
            groups.setdefault((record.sha256, record.size), []).append(record)

    grouped_items: list[tuple[dict[str, Any], list[Record]]] = []
    exact_catalog_sets: set[frozenset[str]] = set()
    component_roots = {
        str(path): str(item.get("group") or "")
        for item in component_duplicate_items
        for path in item.get("paths", [])
    }

    def covering_component(path: str) -> str:
        matches = [
            (root, group_id)
            for root, group_id in component_roots.items()
            if path == root or path.startswith(f"{root}/")
        ]
        if not matches:
            return ""
        return max(matches, key=lambda value: len(value[0]))[1]

    for group in groups.values():
        scopes = {
            _embedded_bundle_scope(record.relative_path) for record in group
        }
        if len(scopes) < 2:
            continue
        covering_groups = {
            covering_component(record.relative_path) for record in group
        }
        if len(covering_groups) == 1 and "" not in covering_groups:
            continue
        paths = sorted(
            (record.relative_path for record in group),
            key=lambda path: (path.casefold(), path),
        )
        names = {record.name for record in group}
        first_name = Path(paths[0]).name
        repeated_size = group[0].size * (len(scopes) - 1)
        grouped_items.append(
            (
                {
                    "name": (
                        first_name
                        if len(names) == 1
                        else f"{first_name} +{len(paths) - 1} more"
                    ),
                    "kind": group[0].category,
                    "duplicateType": (
                        "catalog"
                        if group[0].category == "asset_catalog"
                        else "file"
                    ),
                    "scope": "cross-target",
                    "actionability": "review",
                    "size": group[0].size,
                    "copies": len(group),
                    "targetCount": len(scopes),
                    "repeatedSize": repeated_size,
                    "pathCount": len(paths),
                    "paths": paths[:50],
                    "pathsOmitted": max(0, len(paths) - 50),
                },
                group,
            )
        )
        if group[0].category == "asset_catalog":
            exact_catalog_sets.add(frozenset(paths))

    grouped_items.sort(
        key=lambda value: (
            -int(value[0]["repeatedSize"]),
            str(value[0]["name"]).casefold(),
            tuple(str(path) for path in value[0].get("paths", [])),
        )
    )
    items: list[dict[str, Any]] = []
    for index, (item, group) in enumerate(grouped_items, start=1):
        group_id = f"X{index}"
        item["group"] = group_id
        items.append(item)
    items.extend(
        _cross_target_asset_catalog_items(
            records,
            asset_renditions,
            exact_catalog_sets,
        )
    )
    items.sort(
        key=lambda item: (
            -int(item.get("repeatedSize", 0)),
            str(item.get("name", "")).casefold(),
            str(item.get("group", "")),
        )
    )
    return {
        "count": len(items),
        "totalRepeatedSize": sum(int(item["repeatedSize"]) for item in items),
        "items": items[:MAX_INSIGHT_ITEMS],
        "itemsOmitted": max(0, len(items) - MAX_INSIGHT_ITEMS),
    }


def _target_kind(path: str, info: dict[str, Any]) -> str:
    lower_path = path.casefold()
    if not path:
        return "App"
    if lower_path.endswith(".xpc"):
        return "XPC service"
    if lower_path.endswith(".app"):
        if "appclips/" in f"{lower_path}/":
            return "App Clip"
        if "watch/" in f"{lower_path}/":
            return "Watch app"
        return "App"

    extension = info.get("NSExtension")
    extension_point = (
        str(extension.get("NSExtensionPointIdentifier") or "")
        if isinstance(extension, dict)
        else ""
    )
    known_points = {
        "com.apple.widgetkit-extension": "Widget",
        "com.apple.usernotifications.service": "Notification service",
        "com.apple.usernotifications.content-extension": "Notification UI",
        "com.apple.share-services": "Share extension",
        "com.apple.intents-service": "Intents extension",
        "com.apple.callkit.call-directory": "Call directory",
        "com.apple.keyboard-service": "Keyboard",
        "com.apple.safari.content-blocker": "Content blocker",
        "com.apple.fileprovider-nonui": "File provider",
    }
    return known_points.get(extension_point.casefold(), "Extension")


def _architecture_inventory(
    records: list[Record],
    app_info: dict[str, Any],
    root_name: str,
    component_duplicate_items: list[dict[str, Any]],
    cross_target_duplicates: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a stable architecture inventory independent of recommendations."""

    target_suffixes = (".appex", ".app", ".xpc")
    target_paths: set[str] = {""}
    for record in records:
        parts = Path(record.relative_path).parts
        for index, part in enumerate(parts[:-1]):
            if part.casefold().endswith(target_suffixes):
                target_paths.add(Path(*parts[: index + 1]).as_posix())

    records_by_path = {
        record.relative_path.casefold(): record for record in records
    }
    nested_target_paths = sorted(
        (path for path in target_paths if path), key=len, reverse=True
    )

    def record_target(record: Record) -> str:
        return next(
            (
                path
                for path in nested_target_paths
                if record.relative_path.startswith(f"{path}/")
            ),
            "",
        )

    targets: list[dict[str, Any]] = []
    target_executables: dict[str, str] = {}
    for target_path in sorted(
        target_paths, key=lambda value: (value.count("/"), value.casefold(), value)
    ):
        plist_path = f"{target_path}/Info.plist".lstrip("/")
        plist_record = records_by_path.get(plist_path.casefold())
        info = (
            app_info
            if not target_path
            else _read_plist(plist_record.absolute_path)
            if plist_record
            else {}
        )
        scoped_records = [
            record
            for record in records
            if record_target(record) == target_path
        ]
        executable = str(info.get("CFBundleExecutable") or "")
        name = str(
            info.get("CFBundleDisplayName")
            or info.get("CFBundleName")
            or (Path(target_path).stem if target_path else Path(root_name).stem)
        )
        if executable:
            executable_path = (
                f"{target_path}/{executable}" if target_path else executable
            )
            target_executables[target_path.casefold()] = executable_path
        targets.append(
            {
                "name": name,
                "path": target_path,
                "kind": _target_kind(target_path, info),
                "bundleID": str(info.get("CFBundleIdentifier") or ""),
                "version": str(info.get("CFBundleShortVersionString") or ""),
                "build": str(info.get("CFBundleVersion") or ""),
                "executable": executable,
                "size": sum(record.size for record in scoped_records),
                "compressedSize": sum(
                    record.compressed_size for record in scoped_records
                ),
                "fileCount": len(scoped_records),
            }
        )

    framework_roots = sorted(
        {
            root
            for record in records
            if (root := _framework_bundle_path(record.relative_path))
        },
        key=lambda value: (value.casefold(), value),
    )
    framework_records: dict[str, list[Record]] = {
        root: [] for root in framework_roots
    }
    for record in records:
        root = _framework_bundle_path(record.relative_path)
        if root in framework_records:
            framework_records[root].append(record)

    dynamic_binaries = [
        record
        for record in records
        if _framework_bundle_path(record.relative_path) in framework_records
        and record.macho
        and any(
            architecture.get("file_type") == "dynamic-library"
            for architecture in record.macho.get("architectures", [])
        )
    ]
    consumers_by_path, unresolved_consumers = _framework_consumers(
        records, dynamic_binaries, target_executables
    )
    component_duplicate_by_path = {
        str(path): str(item.get("group") or "")
        for item in component_duplicate_items
        for path in item.get("paths", [])
    }

    frameworks: list[dict[str, Any]] = []
    for root in framework_roots:
        bundled_records = framework_records[root]
        binaries = [
            record
            for record in bundled_records
            if record in dynamic_binaries
            and _framework_bundle_path(record.relative_path) == root
        ]
        binary = max(binaries, key=lambda record: record.size) if binaries else None
        consumers = consumers_by_path.get(binary.relative_path, []) if binary else []
        unresolved = bool(binary and binary.relative_path in unresolved_consumers)
        owner = next(
            (
                target_path
                for target_path in nested_target_paths
                if root.startswith(f"{target_path}/")
            ),
            "",
        )
        size = sum(record.size for record in bundled_records)
        compressed_size = sum(record.compressed_size for record in bundled_records)
        architectures = (
            list(binary.macho.get("architectures", []))
            if binary and binary.macho
            else []
        )
        all_slices_dynamic = bool(architectures) and all(
            architecture.get("file_type") == "dynamic-library"
            for architecture in architectures
        )
        frameworks.append(
            {
                "name": Path(root).name.removesuffix(".framework"),
                "path": root,
                "owner": owner,
                "linking": "Dynamic" if binary else "Unknown",
                "size": size,
                "compressedSize": compressed_size,
                "binarySize": binary.size if binary else 0,
                "binaryCompressedSize": binary.compressed_size if binary else 0,
                "resourceSize": max(0, size - (binary.size if binary else 0)),
                "consumerCount": len(consumers),
                "consumers": consumers,
                "consumerResolution": "Incomplete" if unresolved else "Resolved",
                "staticCandidate": bool(binary and len(consumers) == 1 and not unresolved),
                "allSlicesDynamic": all_slices_dynamic,
                "duplicateGroup": component_duplicate_by_path.get(root) or None,
            }
        )
    frameworks.sort(
        key=lambda item: (-int(item["size"]), str(item["path"]).casefold())
    )

    duplicates = []
    for item in component_duplicate_items:
        repeated_size = int(item.get("size", 0)) * max(
            0, int(item.get("copies", 0)) - 1
        )
        duplicates.append({**item, "repeatedSize": repeated_size})
    duplicates.sort(
        key=lambda item: (-int(item["repeatedSize"]), str(item.get("name", "")))
    )

    target_by_executable: dict[str, dict[str, Any]] = {}
    for target in targets:
        executable = str(target.get("executable") or "")
        if not executable:
            continue
        target_path = str(target.get("path") or "")
        executable_path = f"{target_path}/{executable}" if target_path else executable
        target_by_executable[executable_path] = target

    linking_review_threshold = max(
        MIN_LINKING_REVIEW_BYTES,
        math.ceil(sum(record.size for record in records) * 0.005),
    )
    linking_reviews: list[dict[str, Any]] = []
    for framework in frameworks:
        consumers = list(framework.get("consumers") or [])
        consumer = consumers[0] if len(consumers) == 1 else ""
        target = target_by_executable.get(consumer)
        if not (
            framework.get("staticCandidate")
            and framework.get("allSlicesDynamic")
            and framework.get("consumerResolution") == "Resolved"
            and target is not None
            and not framework.get("duplicateGroup")
            and int(framework.get("binarySize", 0)) >= linking_review_threshold
        ):
            continue
        linking_reviews.append(
            {
                "id": f"static-or-mergeable:{framework['path']}",
                "kind": "static-or-mergeable",
                "name": framework["name"],
                "path": framework["path"],
                "frameworkSize": int(framework["size"]),
                "binarySize": int(framework["binarySize"]),
                "binaryCompressedSize": int(framework["binaryCompressedSize"]),
                "resourceSize": int(framework["resourceSize"]),
                "reviewScopeBytes": int(framework["binarySize"]),
                "consumer": consumer,
                "consumerName": str(target.get("name") or consumer),
                "consumerKind": str(target.get("kind") or "Target"),
                "action": "Test a static product or mergeable Release build, then compare archives.",
            }
        )
    linking_reviews.sort(
        key=lambda item: (-int(item["reviewScopeBytes"]), str(item["path"]).casefold())
    )
    linking_reviews = linking_reviews[:MAX_LINKING_REVIEWS]

    return {
        "targets": targets,
        "frameworks": frameworks,
        "linkingReviews": linking_reviews,
        "linkingReviewThresholdBytes": linking_review_threshold,
        "duplicateComponents": duplicates,
        "crossTargetDuplicates": (
            cross_target_duplicates
            if cross_target_duplicates is not None
            else _cross_target_duplicate_inventory(
                records,
                component_duplicate_items,
            )
        ),
    }


def _binary_inventory(
    records: list[Record],
    targets: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return a portable, report-ready inventory of parsed Mach-O binaries."""

    binary_records = [
        record
        for record in records
        if record.macho or record.metadata.get("machoCandidate")
    ]
    target_rows = sorted(
        targets,
        key=lambda target: len(str(target.get("path") or "")),
        reverse=True,
    )

    def target_for(path: str) -> dict[str, Any]:
        for target in target_rows:
            target_path = str(target.get("path") or "")
            if not target_path or path == target_path or path.startswith(
                f"{target_path}/"
            ):
                return target
        return {}

    def owner_for(path: str, target: dict[str, Any]) -> tuple[str, str]:
        parts = Path(path).parts[:-1]
        component_path = ""
        for index, part in enumerate(parts):
            if part.casefold().endswith((".framework", ".bundle", ".xpc")):
                component_path = Path(*parts[: index + 1]).as_posix()
        if component_path:
            component = Path(component_path).name
            return Path(component).stem, component_path
        return (
            str(target.get("name") or Path(path).name),
            str(target.get("path") or ""),
        )

    def export_metadata_estimate(architecture: dict[str, Any]) -> int:
        if not architecture.get("is_executable"):
            return 0
        export_trie = architecture.get("export_trie") or {}
        if not export_trie.get("valid") or export_trie.get("malformed"):
            return 0
        count = int(export_trie.get("symbol_count", 0) or 0)
        allowlist_count = int(bool(export_trie.get("has_main"))) + int(
            bool(export_trie.get("has_mh_execute_header"))
        )
        if max(0, count - allowlist_count) < 32:
            return 0
        trie_bytes = int(export_trie.get("size", 0) or 0)
        external = (
            ((architecture.get("symbol_table") or {}).get("classifications") or {}).get(
                "external_defined"
            )
            or {}
        )
        external_bytes = int(external.get("entry_bytes", 0) or 0) + int(
            external.get("string_bytes", 0) or 0
        )
        retained_external = (
            math.ceil(external_bytes * allowlist_count / count)
            if count and external_bytes
            else 0
        )
        estimate = trie_bytes + max(0, external_bytes - retained_external)
        return estimate if estimate >= 4 * 1024 else 0

    items: list[dict[str, Any]] = []
    for record in binary_records:
        target = target_for(record.relative_path)
        owner, owner_path = owner_for(record.relative_path, target)
        architecture_rows: list[dict[str, Any]] = []
        macho = record.macho or {}
        for architecture in macho.get("architectures", []):
            segment_rows = []
            for segment in architecture.get("segments", []):
                segment_size = max(0, int(segment.get("size", 0) or 0))
                if not segment_size:
                    continue
                segment_parts = _binary_segment_parts(architecture, segment)
                section_rows = sorted(
                    (
                        {
                            "name": str(part.get("name") or "Unnamed section"),
                            "kind": str(part.get("kind") or "section"),
                            "size": max(0, int(part.get("size", 0) or 0)),
                            "virtualSize": max(
                                0, int(part.get("virtualSize", 0) or 0)
                            ),
                            "fileOffset": part.get("fileOffset"),
                            "metadata": dict(part.get("metadata") or {}),
                        }
                        for part in segment_parts
                        if int(part.get("size", 0) or 0) > 0
                    ),
                    key=lambda section: (-int(section["size"]), section["name"]),
                )
                segment_name = str(segment.get("name") or "Unnamed segment")
                segment_rows.append(
                    {
                        "name": segment_name,
                        "size": segment_size,
                        "virtualSize": max(
                            0, int(segment.get("virtual_size", 0) or 0)
                        ),
                        "fileOffset": max(
                            0, int(segment.get("file_offset", 0) or 0)
                        ),
                        "sections": section_rows,
                        "unattributedSize": max(
                            0,
                            segment_size
                            - sum(int(section["size"]) for section in section_rows),
                        ),
                        "unattributedName": (
                            "Other __LINKEDIT data"
                            if segment_name == "__LINKEDIT"
                            else "Other file data"
                        ),
                    }
                )
            segment_rows.sort(
                key=lambda segment: (-int(segment["size"]), segment["name"])
            )

            symbol_table = architecture.get("symbol_table") or {}
            strip_data = symbol_table.get("strip_rSTx") or {}
            architecture_rows.append(
                {
                    "name": str(architecture.get("architecture") or "Unknown"),
                    "size": max(0, int(architecture.get("size", 0) or 0)),
                    "fileType": str(architecture.get("file_type") or "Unknown"),
                    "platform": str(architecture.get("platform") or ""),
                    "minimumOS": str(architecture.get("minimum_os") or ""),
                    "sdk": str(architecture.get("sdk") or ""),
                    "encrypted": bool(architecture.get("encrypted")),
                    "stripSymbolsBytes": max(
                        0, int(strip_data.get("estimated_bytes", 0) or 0)
                    ),
                    "exportedSymbolMetadataBytes": export_metadata_estimate(
                        architecture
                    ),
                    "segments": segment_rows,
                }
            )

        raw_strip_estimate = sum(
            int(architecture["stripSymbolsBytes"])
            for architecture in architecture_rows
        )
        stripped_size = record.metadata.get("strippedSizeEstimate")
        strip_estimate = (
            max(0, record.size - int(stripped_size))
            if isinstance(stripped_size, int)
            else raw_strip_estimate
        )
        export_estimate = int(
            record.metadata.get("exportedSymbolMetadataEstimate", 0) or 0
        ) or sum(
            int(architecture["exportedSymbolMetadataBytes"])
            for architecture in architecture_rows
        )
        items.append(
            {
                "name": record.name,
                "path": record.relative_path,
                "size": record.size,
                "compressedSize": record.compressed_size,
                "parsed": bool(record.macho),
                "fileType": str(record.metadata.get("fileType") or "Unknown"),
                "target": str(target.get("name") or "Main target"),
                "targetPath": str(target.get("path") or ""),
                "targetKind": str(target.get("kind") or "Target"),
                "owner": owner,
                "ownerPath": owner_path,
                "architectureNames": [
                    str(architecture["name"]) for architecture in architecture_rows
                ],
                "platforms": sorted(
                    {
                        str(architecture["platform"])
                        for architecture in architecture_rows
                        if architecture["platform"]
                    }
                ),
                "minimumOSVersions": sorted(
                    {
                        str(architecture["minimumOS"])
                        for architecture in architecture_rows
                        if architecture["minimumOS"]
                    }
                ),
                "sdkVersions": sorted(
                    {
                        str(architecture["sdk"])
                        for architecture in architecture_rows
                        if architecture["sdk"]
                    }
                ),
                "encrypted": any(
                    bool(architecture["encrypted"])
                    for architecture in architecture_rows
                ),
                "stripSymbolsBytes": strip_estimate,
                "exportedSymbolMetadataBytes": export_estimate,
                "architectures": architecture_rows,
            }
        )

    items.sort(key=lambda item: (-int(item["size"]), str(item["path"]).casefold()))
    return {
        "count": len(items),
        "totalSize": sum(int(item["size"]) for item in items),
        "items": items,
    }


def _lottie_similarity_groups(records: list[Record]) -> list[list[Record]]:
    groups: dict[str, list[Record]] = {}
    for record in records:
        signature = record.metadata.get("structureSignature")
        if signature:
            groups.setdefault(str(signature), []).append(record)
    return [group for group in groups.values() if len(group) > 1]


def _insight(
    insight_id: str,
    title: str,
    summary: str,
    *,
    detail: str,
    action: str,
    severity: str = "medium",
    confidence: str = "high",
    savings: int | None = None,
    paths: list[str] | None = None,
    items: list[dict[str, Any]] | None = None,
    category: str = "other",
    review_only: bool = False,
) -> dict[str, Any]:
    all_paths = list(paths or [])
    all_items = list(items or [])
    return {
        "id": insight_id,
        "title": title,
        "summary": summary,
        "detail": detail,
        "action": action,
        "severity": severity,
        "confidence": confidence,
        "savings": savings,
        "paths": all_paths[:MAX_INSIGHT_PATHS],
        "pathCount": len(all_paths),
        "pathsOmitted": max(0, len(all_paths) - MAX_INSIGHT_PATHS),
        "items": all_items[:MAX_INSIGHT_ITEMS],
        "itemCount": len(all_items),
        "itemsOmitted": max(0, len(all_items) - MAX_INSIGHT_ITEMS),
        "category": category,
        "reviewOnly": review_only,
    }


def _mark(records: Iterable[Record], insight_id: str) -> None:
    for record in records:
        if insight_id not in record.insight_ids:
            record.insight_ids.append(insight_id)


def _rank_recommendations(
    insights: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep material savings plus explicitly curated review-only checks."""

    qualifying: list[dict[str, Any]] = []
    for insight in insights:
        if insight.get("reviewOnly") is True:
            qualifying.append(insight)
            continue
        savings = insight.get("savings")
        if (
            isinstance(savings, bool)
            or not isinstance(savings, (int, float))
            or not math.isfinite(float(savings))
            or savings < MIN_RECOMMENDATION_SAVINGS
        ):
            continue
        qualifying.append(insight)
    qualifying.sort(
        key=lambda item: (
            item.get("reviewOnly") is True,
            -float(item.get("savings") or 0),
            str(item.get("title") or item.get("id") or ""),
        )
    )
    return qualifying


def _representative_asset_rendition(
    renditions: Iterable[dict[str, Any]],
) -> dict[str, Any] | None:
    """Choose one 3x rendition when present, preferring physical storage."""

    all_candidates = [
        rendition
        for rendition in renditions
        if int(rendition.get("size", 0) or 0) > 0
    ]
    if not all_candidates:
        return None
    physical_candidates = [
        rendition
        for rendition in all_candidates
        if rendition.get("physical") is not False
    ]
    candidates = physical_candidates or all_candidates

    def scale_priority(rendition: dict[str, Any]) -> tuple[int, int]:
        scale = int(rendition.get("scale", 0) or 0)
        if scale == 3:
            return (3, 0)
        if 0 < scale < 3:
            return (2, scale)
        if scale > 3:
            return (1, -scale)
        return (0, 0)

    return max(
        candidates,
        key=lambda rendition: (
            scale_priority(rendition),
            int(rendition.get("pixelWidth", rendition.get("width", 0)) or 0)
            * int(rendition.get("pixelHeight", rendition.get("height", 0)) or 0),
            int(rendition.get("size", 0) or 0),
            str(
                rendition.get("displayPath")
                or rendition.get("name")
                or rendition.get("renditionName")
                or ""
            ),
        ),
    )


def _scaled_compressed_size(
    compressed_size: int, universal_size: int, delivered_size: int
) -> int:
    if universal_size <= 0 or delivered_size >= universal_size:
        return compressed_size
    return max(0, round(compressed_size * delivered_size / universal_size))


def _apply_catalog_delivery_estimate(
    record: Record, diagnostics: dict[str, Any]
) -> bool:
    estimate = diagnostics.get("deliveryEstimate")
    if not isinstance(estimate, dict) or estimate.get("complete") is not True:
        return False
    delivered_size = estimate.get("estimatedSize")
    if (
        not isinstance(delivered_size, int)
        or isinstance(delivered_size, bool)
        or delivered_size <= 0
        or delivered_size > record.size
    ):
        return False

    record.install_size = delivered_size
    record.download_size = _scaled_compressed_size(
        record.compressed_size, record.size, delivered_size
    )
    record.metadata["deliveryEstimate"] = {
        "target": "latest-iphone",
        "universalSize": record.size,
        "installSize": delivered_size,
        "entryCount": int(estimate.get("entryCount", 0) or 0),
        "selectedEntryCount": int(
            estimate.get("selectedEntryCount", 0) or 0
        ),
    }
    return True


def _apply_macho_delivery_estimate(record: Record) -> bool:
    if not record.macho or not record.macho.get("is_fat"):
        return False
    architectures = record.macho.get("architectures", [])
    selected: dict[str, Any] | None = None
    for preferred in ("arm64e", "arm64"):
        selected = next(
            (
                architecture
                for architecture in architectures
                if architecture.get("architecture") == preferred
            ),
            None,
        )
        if selected is not None:
            break
    if selected is None:
        return False
    delivered_size = int(selected.get("size", 0) or 0)
    if delivered_size <= 0 or delivered_size >= record.size:
        return False

    record.install_size = delivered_size
    record.download_size = _scaled_compressed_size(
        record.compressed_size, record.size, delivered_size
    )
    record.metadata["deliveryEstimate"] = {
        "target": "latest-iphone",
        "universalSize": record.size,
        "installSize": delivered_size,
        "architecture": str(selected.get("architecture") or "arm64"),
    }
    return True


class BundleAnalyzer:
    """Analyze one iOS artifact and return report-ready JSON data."""

    def __init__(
        self,
        progress: Progress | None = None,
        platform: AnalysisPlatform | None = None,
    ) -> None:
        self.progress = progress
        self.platform = platform or NativeAnalysisPlatform()

    def _scan(self, prepared: PreparedArtifact) -> list[Record]:
        root = prepared.app_root
        paths = sorted(
            (
                path
                for path in root.rglob("*")
                if path.is_file() and not path.is_symlink()
            ),
            key=lambda path: str(path.relative_to(root)).lower(),
        )
        records: list[Record] = []
        for index, path in enumerate(paths, start=1):
            relative = path.relative_to(root).as_posix()
            if index == 1 or index % 250 == 0:
                _progress(
                    self.progress,
                    f"Reading bundle files ({index:,}/{len(paths):,})…",
                )
            try:
                size = path.stat().st_size
                macho_candidate = is_macho(path)
                macho = parse_macho(path) if macho_candidate else None
                digest, compressed = _stream_facts(
                    path, prepared.zip_sizes.get(path)
                )
            except OSError:
                continue
            category = _classify(relative, macho)
            if macho_candidate and macho is None:
                category = "binary"
            metadata: dict[str, Any] = {
                "extension": path.suffix.lower(),
                "machoCandidate": macho_candidate,
                "machoParseFailed": macho_candidate and macho is None,
            }
            lottie = _looks_like_lottie(path, size)
            if lottie:
                category = "animation"
                metadata.update(lottie)
            if macho:
                architectures = macho.get("architectures", [])
                first = architectures[0] if architectures else {}
                metadata.update(
                    {
                        "architectures": [
                            architecture.get("architecture")
                            for architecture in architectures
                        ],
                        "fileType": first.get("file_type"),
                        "dependencies": sorted(
                            {
                                dependency
                                for architecture in architectures
                                for dependency in architecture.get("dependencies", [])
                            }
                        ),
                        "encrypted": any(
                            bool(architecture.get("encrypted"))
                            for architecture in architectures
                        ),
                        "platform": first.get("platform"),
                        "minimumOS": first.get("minimum_os"),
                        "sdk": first.get("sdk"),
                        "symbolTableBytes": sum(
                            int(architecture.get("symbol_table_bytes", 0))
                            for architecture in architectures
                        ),
                        "stripSymbolEstimateBytes": sum(
                            int(
                                (architecture.get("symbol_table") or {})
                                .get("strip_rSTx", {})
                                .get("estimated_bytes", 0)
                            )
                            for architecture in architectures
                        ),
                        "exportTrieBytes": sum(
                            int((architecture.get("export_trie") or {}).get("size", 0))
                            for architecture in architectures
                            if (architecture.get("export_trie") or {}).get("valid")
                        ),
                        "exportedSymbolCount": sum(
                            int(
                                (architecture.get("export_trie") or {}).get(
                                    "symbol_count", 0
                                )
                            )
                            for architecture in architectures
                            if (architecture.get("export_trie") or {}).get("valid")
                        ),
                    }
                )
            records.append(
                Record(
                    relative_path=relative,
                    absolute_path=path,
                    size=size,
                    compressed_size=compressed,
                    allocated_size=_ceil(size, 4096),
                    category=category,
                    sha256=digest,
                    macho=macho,
                    metadata=metadata,
                )
            )
        return records

    def analyze(
        self,
        input_path: str | Path,
        *,
        prepared: PreparedArtifact | None = None,
    ) -> dict[str, Any]:
        _progress(self.progress, "Preparing artifact…")
        artifact = prepared if prepared is not None else prepare_artifact(input_path)
        with artifact as prepared:
            info_plist = _read_plist(prepared.app_root / "Info.plist")
            records = self._scan(prepared)
            _progress(self.progress, "Expanding asset catalogs and Mach-O binaries…")

            asset_renditions: list[dict[str, Any]] = []
            expanded_catalogs = 0
            delivery_catalog_count = 0
            asset_catalog_coverage = {
                "catalogCount": 0,
                "parsedCatalogCount": 0,
                "entryCount": 0,
                "supportedOutputCount": 0,
                "unsupportedOutputCount": 0,
                "decodeFailureCount": 0,
                "decodeSkippedCount": 0,
                "duplicateCandidateCount": 0,
                "duplicateDigestCount": 0,
                "imageCandidateCount": 0,
                "imageMeasuredCount": 0,
            }
            for record in records:
                if record.category != "asset_catalog":
                    continue
                asset_catalog_coverage["catalogCount"] += 1
                children, renditions = self.platform.asset_catalog(
                    record.absolute_path, record.relative_path
                )
                diagnostics = self.platform.asset_catalog_diagnostics(
                    record.relative_path
                )
                if diagnostics:
                    record.metadata["assetAnalysis"] = diagnostics
                    if _apply_catalog_delivery_estimate(record, diagnostics):
                        delivery_catalog_count += 1
                    if not diagnostics.get("failed"):
                        asset_catalog_coverage["parsedCatalogCount"] += 1
                    asset_catalog_coverage["entryCount"] += int(
                        diagnostics.get("entries", 0) or 0
                    )
                    asset_catalog_coverage["supportedOutputCount"] += int(
                        diagnostics.get("supportedOutputs", 0) or 0
                    )
                    asset_catalog_coverage["unsupportedOutputCount"] += int(
                        diagnostics.get("unsupportedOutputs", 0) or 0
                    )
                    asset_catalog_coverage["decodeFailureCount"] += int(
                        diagnostics.get("decodeFailureCount", 0) or 0
                    )
                    asset_catalog_coverage["decodeSkippedCount"] += int(
                        diagnostics.get("decodeSkippedCount", 0) or 0
                    )
                    asset_catalog_coverage["duplicateCandidateCount"] += int(
                        diagnostics.get("duplicateCandidateCount", 0) or 0
                    )
                    asset_catalog_coverage["duplicateDigestCount"] += int(
                        diagnostics.get("duplicateDigestCount", 0) or 0
                    )
                    asset_catalog_coverage["imageCandidateCount"] += int(
                        diagnostics.get("conversionCandidateCount", 0) or 0
                    )
                    asset_catalog_coverage["imageMeasuredCount"] += int(
                        diagnostics.get("conversionMeasuredCount", 0) or 0
                    )
                if children:
                    expanded_catalogs += 1
                    record.metadata["assetCount"] = len(children)
                    record.metadata["renditionCount"] = len(renditions)
                    record.virtual_children = _normalize_virtual_sizes(
                        children, record.size, "Catalog metadata & packing"
                    )
                    _assign_virtual_delivery_sizes(
                        record.virtual_children,
                        record.delivered_install_size,
                        record.delivered_download_size,
                    )
                    for child in record.virtual_children:
                        if not child.get("path"):
                            child["path"] = f"{record.relative_path}::catalog-overhead"
                    asset_renditions.extend(renditions)

            linkmaps_used = 0
            delivery_binary_count = 0
            for record in records:
                if not record.macho:
                    continue
                if _apply_macho_delivery_estimate(record):
                    delivery_binary_count += 1
                compile_units = _linkmap_for_binary(record, prepared.linkmaps)
                if compile_units:
                    linkmaps_used += 1
                    record.metadata["attribution"] = "linkmap"
                    record.metadata["compileUnitCount"] = len(compile_units)
                else:
                    record.metadata["attribution"] = "mach-o-sections"
                record.virtual_children = _binary_children(
                    record.macho,
                    record.size,
                    record.relative_path,
                    compile_units or None,
                )
                _assign_virtual_delivery_sizes(
                    record.virtual_children,
                    record.delivered_install_size,
                    record.delivered_download_size,
                )

            component_duplicates, component_duplicate_items = (
                _component_duplicate_groups(records)
            )
            insights = self._recommend(
                records,
                asset_renditions,
                str(info_plist.get("MinimumOSVersion") or ""),
                info_plist,
                component_duplicate_items,
            )
            cross_target_duplicates = _cross_target_duplicate_inventory(
                records,
                component_duplicate_items,
                asset_renditions,
            )
            self._attach_asset_rendition_metadata(asset_renditions)
            tree = self._build_tree(
                prepared.app_root.name, records, component_duplicates
            )
            categories = self._category_breakdown(records)
            architecture = _architecture_inventory(
                records,
                info_plist,
                prepared.app_root.name,
                component_duplicate_items,
                cross_target_duplicates,
            )
            binaries = _binary_inventory(records, architecture["targets"])
            capability_declarations = _collect_capability_declarations(
                prepared.app_root,
                prepared.app_root.name,
                info_plist,
                records,
            )
            localizations = _collect_localizations(records, prepared.app_root.name)

            total_size = sum(record.size for record in records)
            compressed_size = sum(record.compressed_size for record in records)
            allocated_size = sum(record.allocated_size for record in records)
            install_size = sum(
                record.delivered_install_size for record in records
            )
            download_size = (
                sum(record.delivered_download_size for record in records)
                + prepared.archive_overhead_size
            )
            executable = str(info_plist.get("CFBundleExecutable") or "")
            binary = next(
                (
                    record
                    for record in records
                    if record.relative_path == executable and record.macho
                ),
                None,
            )
            architectures = (
                binary.metadata.get("architectures", []) if binary else []
            )
            macho_candidates = [
                record for record in records if record.metadata.get("machoCandidate")
            ]
            parsed_machos = [record for record in macho_candidates if record.macho]
            parsed_architectures = [
                architecture
                for record in parsed_machos
                for architecture in record.macho.get("architectures", [])
            ]
            symbol_tables = [
                architecture.get("symbol_table")
                for architecture in parsed_architectures
                if architecture.get("symbol_table") is not None
            ]
            executable_architectures = [
                architecture
                for architecture in parsed_architectures
                if architecture.get("is_executable")
            ]
            export_tries = [
                architecture.get("export_trie")
                for architecture in executable_architectures
                if architecture.get("export_trie") is not None
            ]
            binary_analysis_coverage = {
                "candidateCount": len(macho_candidates),
                "parsedCount": len(parsed_machos),
                "architectureCount": len(parsed_architectures),
                "symbolTableCount": len(symbol_tables),
                "invalidSymbolTableCount": sum(
                    not bool(table.get("valid")) for table in symbol_tables
                ),
                "executableArchitectureCount": len(executable_architectures),
                "exportTrieCount": len(export_tries),
                "invalidExportTrieCount": sum(
                    not bool(trie.get("valid")) for trie in export_tries
                ),
            }

            app = {
                "name": str(
                    info_plist.get("CFBundleDisplayName")
                    or info_plist.get("CFBundleName")
                    or prepared.app_root.stem
                ),
                "bundleID": str(info_plist.get("CFBundleIdentifier") or "Unknown"),
                "version": str(info_plist.get("CFBundleShortVersionString") or "—"),
                "build": str(info_plist.get("CFBundleVersion") or "—"),
                "minimumOS": str(info_plist.get("MinimumOSVersion") or "Unknown"),
                "executable": executable or "Unknown",
                "architectures": architectures,
                "iconDataURL": _app_icon_data_url(
                    prepared.app_root, info_plist, self.platform
                ),
                "artifactName": prepared.artifact_name,
                "artifactKind": prepared.artifact_kind,
                "modifiedAt": datetime.fromtimestamp(
                    prepared.artifact_modified_at or 0, timezone.utc
                ).isoformat(),
            }
            metrics = {
                "installSize": install_size,
                "downloadSize": download_size,
                "logicalSize": total_size,
                "compressedSize": compressed_size,
                "allocatedSize": allocated_size,
                "artifactSize": prepared.artifact_size,
                "delivery": {
                    "kind": "latest-iphone-thinning-estimate",
                    "target": "Latest iPhone (3x, P3, arm64)",
                    "estimated": True,
                    "installDefinition": "Uncompressed bytes delivered in the thinned app bundle",
                    "downloadDefinition": "Compressed bytes delivered for the thinned app bundle",
                    "assetCatalogCount": asset_catalog_coverage["catalogCount"],
                    "assetCatalogEstimateCount": delivery_catalog_count,
                    "assetCatalogFallbackCount": max(
                        0,
                        asset_catalog_coverage["catalogCount"]
                        - delivery_catalog_count,
                    ),
                    "binarySliceEstimateCount": delivery_binary_count,
                    "archiveOverheadSize": prepared.archive_overhead_size,
                },
                "fileCount": len(records),
                "smallFileCount": sum(record.size < 4096 for record in records),
                "frameworkCount": len(
                    {
                        name
                        for record in records
                        if (name := _framework_name(record.relative_path))
                    }
                ),
                "dynamicFrameworkCount": sum(
                    1
                    for record in records
                    if _framework_name(record.relative_path)
                    and record.macho
                    and any(
                        arch.get("file_type") == "dynamic-library"
                        for arch in record.macho.get("architectures", [])
                    )
                ),
                # Recommendations are deliberately independent. Duplicate
                # removal, image conversion, symbol stripping and export
                # allowlisting may overlap, so presenting their sum would be
                # a false precision.
                "opportunityBytes": None,
                "independentRecommendations": True,
                "insightCount": len(insights),
            }

            return {
                "schemaVersion": 2,
                "generatedAt": datetime.now(timezone.utc).isoformat(),
                "generator": {"name": "OpenBundle", "version": "0.1.0"},
                "app": app,
                "metrics": metrics,
                "categories": categories,
                "tree": tree,
                "insights": insights,
                "architecture": architecture,
                "binaries": binaries,
                "locales": localizations,
                "capabilities": {
                    "environment": self.platform.environment,
                    "declarations": capability_declarations,
                    "assetutilAvailable": self.platform.asset_catalogs_available,
                    "assetCatalogsExpanded": expanded_catalogs,
                    "assetCatalogCoverage": asset_catalog_coverage,
                    "binaryAnalysisCoverage": binary_analysis_coverage,
                    "linkmapsFound": len(prepared.linkmaps),
                    "linkmapsUsed": linkmaps_used,
                    "symbolAnalysisAvailable": True,
                    "exportedSymbolAnalysisAvailable": True,
                    "assetCatalogAnalysisAvailable": self.platform.asset_catalogs_available,
                    "imageConversionAvailable": self.platform.image_conversion_available,
                    # Kept for report-schema compatibility: this specifically
                    # means a host can invoke Apple's strip tool for validation,
                    # not that portable symbol analysis is unavailable.
                    "symbolStripSimulation": self.platform.symbol_strip_available,
                    "imageConversionSimulation": self.platform.image_conversion_available,
                    "hostDiagnostics": self.platform.host_diagnostics,
                    "privacy": self.platform.privacy_message,
                },
            }

    def _recommend(
        self,
        records: list[Record],
        asset_renditions: list[dict[str, Any]],
        minimum_os: str,
        info_plist: dict[str, Any],
        component_duplicate_items: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        insights: list[dict[str, Any]] = []
        self._duplicate_insight(records, asset_renditions, insights)
        self._component_duplicate_insight(component_duplicate_items, insights)
        self._unnecessary_insight(records, insights)
        self._provisioning_profile_insight(records, insights)
        self._small_files_insight(records, insights)
        self._asset_catalog_insights(records, insights)
        self._image_insights(records, asset_renditions, minimum_os, insights)
        self._alternate_icon_insight(records, info_plist, insights)
        self._coverage_instrumentation_insight(records, insights)
        self._bitcode_insight(records, insights)
        self._symbol_insight(records, insights)
        self._exported_symbols_insight(records, insights)
        self._architecture_insight(records, insights)
        self._framework_insights(records, insights)
        self._embedded_target_insight(records, insights)
        self._linkmap_insight(records, insights)
        self._swift_reflection_insight(records, insights)
        self._embedded_string_data_insight(records, insights)
        self._localization_insights(records, insights)
        self._media_insights(records, insights)
        self._lottie_insights(records, insights)
        return _rank_recommendations(insights)

    def _duplicate_insight(
        self,
        records: list[Record],
        asset_renditions: list[dict[str, Any]],
        insights: list[dict[str, Any]],
    ) -> None:
        record_by_path = {record.relative_path: record for record in records}
        groups: dict[tuple[str, str, int], list[Record]] = {}
        for record in records:
            if _is_duplicate_candidate(record):
                groups.setdefault(
                    (
                        _embedded_bundle_scope(record.relative_path),
                        record.sha256,
                        record.size,
                    ),
                    [],
                ).append(record)
        duplicate_groups = [
            group for group in groups.values() if len(group) > 1
        ]
        items: list[dict[str, Any]] = []
        insight_paths: list[str] = []
        group_index = 1
        for group in sorted(
            duplicate_groups,
            key=lambda values: (
                -(values[0].size * (len(values) - 1)),
                tuple(
                    sorted(
                        (record.relative_path for record in values),
                        key=lambda path: (path.casefold(), path),
                    )
                ),
            ),
        ):
            group_savings = group[0].size * (len(group) - 1)
            if group_savings < 1024:
                continue
            group_id = f"D{group_index}"
            group_index += 1
            for record in group:
                record.duplicate_group = group_id
            _mark(group, "duplicates")
            group_paths = sorted(
                (record.relative_path for record in group),
                key=lambda path: (path.casefold(), path),
            )
            insight_paths.extend(group_paths)
            group_names = {record.name for record in group}
            first_name = Path(sorted(group_paths, key=str.casefold)[0]).name
            duplicate_type = (
                "catalog"
                if all(record.category == "asset_catalog" for record in group)
                else "file"
            )
            for record in group:
                record.metadata.update(
                    {
                        "duplicateType": duplicate_type,
                        "duplicateGroup": group_id,
                        "duplicateGroups": [group_id],
                        "duplicateCount": 1,
                        "scope": "same-runtime",
                        "actionability": "candidate",
                        "exactMatch": True,
                    }
                )
            items.append(
                {
                    "group": group_id,
                    "name": (
                        first_name
                        if len(group_names) == 1
                        else f"{first_name} +{len(group_paths) - 1} more"
                    ),
                    "size": group[0].size,
                    "savings": group_savings,
                    "pathCount": len(group_paths),
                    "paths": group_paths[:50],
                    "pathsOmitted": max(0, len(group_paths) - 50),
                    "kind": "file",
                    "duplicateType": duplicate_type,
                    "scope": "same-runtime",
                    "actionability": "candidate",
                    "exactMatch": True,
                }
            )

        rendition_groups: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
        for rendition in asset_renditions:
            rendition_path = str(
                rendition.get("displayPath") or rendition.get("path") or ""
            ).lower()
            catalog_path = str(rendition.get("path") or "").split("::", 1)[0]
            catalog_record = record_by_path.get(catalog_path)
            if (
                "appicon" not in rendition_path
                and rendition.get("digest")
                and int(rendition.get("size", 0)) >= 1024
                and not (catalog_record and catalog_record.duplicate_group)
            ):
                key = (
                    _embedded_bundle_scope(catalog_path),
                    str(rendition["digest"]),
                    int(rendition["size"]),
                )
                rendition_groups.setdefault(key, []).append(rendition)

        catalog_clusters: dict[
            tuple[str, ...], list[dict[str, Any]]
        ] = {}
        standalone_asset_groups: list[dict[str, Any]] = []
        asset_group_all_paths: dict[str, list[str]] = {}
        catalog_asset_group_ids: dict[str, set[str]] = {}
        catalog_evidence_group_ids: dict[str, set[str]] = {}
        for group in sorted(
            (values for values in rendition_groups.values() if len(values) > 1),
            key=lambda values: (
                -(int(values[0]["size"]) * (len(values) - 1)),
                tuple(
                    sorted(
                        str(item.get("displayPath") or item.get("path") or "")
                        for item in values
                    )
                ),
            ),
        ):
            group_savings = int(group[0]["size"]) * (len(group) - 1)
            group_id = f"D{group_index}"
            group_index += 1
            group_paths = sorted(
                {
                    str(item.get("displayPath") or item["path"])
                    for item in group
                }
            )
            catalog_paths = sorted(
                {
                    str(item.get("path") or "").split("::", 1)[0]
                    for item in group
                    if str(item.get("path") or "").split("::", 1)[0]
                },
                key=lambda value: (value.casefold(), value),
            )
            for rendition in group:
                entry = rendition["entry"]
                rendition["duplicateGroup"] = group_id
                rendition["duplicateType"] = "asset"
                rendition["scope"] = "same-runtime"
                rendition["actionability"] = "candidate"
                if not entry.get("duplicateGroup"):
                    entry["duplicateGroup"] = group_id
                entry["duplicateType"] = "asset"
                entry["scope"] = "same-runtime"
                entry["actionability"] = "candidate"
                if "duplicates" not in entry.setdefault("insights", []):
                    entry["insights"].append("duplicates")
                entry_metadata = entry.setdefault("metadata", {})
                entry_groups = entry_metadata.setdefault("duplicateGroups", [])
                if group_id not in entry_groups:
                    entry_groups.append(group_id)
                entry_metadata["duplicateCount"] = len(entry_groups)
                entry_metadata["duplicateType"] = "asset"
                entry_metadata["scope"] = "same-runtime"
                entry_metadata["actionability"] = "candidate"
                catalog_path = str(rendition["path"]).split("::", 1)[0]
                catalog = record_by_path.get(catalog_path)
                if catalog:
                    _mark([catalog], "duplicates")
                    catalog_asset_group_ids.setdefault(catalog_path, set()).add(
                        group_id
                    )
            asset_group = {
                "group": group_id,
                "name": str(group[0]["name"]),
                "size": int(group[0]["size"]),
                "savings": group_savings,
                "pathCount": len(group_paths),
                "paths": group_paths[:50],
                "pathsOmitted": max(0, len(group_paths) - 50),
                "catalogCount": len(catalog_paths),
                "catalogPaths": catalog_paths[:50],
                "catalogPathsOmitted": max(0, len(catalog_paths) - 50),
                "kind": "asset rendition",
                "duplicateType": "asset",
                "scope": "same-runtime",
                "actionability": "candidate",
            }
            asset_group_all_paths[group_id] = group_paths
            if len(catalog_paths) > 1:
                catalog_clusters.setdefault(tuple(catalog_paths), []).append(
                    asset_group
                )
            else:
                standalone_asset_groups.append(asset_group)

        for asset_group in standalone_asset_groups:
            items.append(asset_group)
            insight_paths.extend(
                asset_group_all_paths.get(str(asset_group["group"]), [])
            )
            for catalog_path in asset_group.get("catalogPaths", []):
                catalog_evidence_group_ids.setdefault(catalog_path, set()).add(
                    str(asset_group["group"])
                )

        for catalog_paths, asset_groups in sorted(
            catalog_clusters.items(),
            key=lambda item: (
                -sum(int(group.get("savings", 0)) for group in item[1]),
                item[0],
            ),
        ):
            # A single repeated asset remains useful asset-level evidence. Two
            # or more groups with the same catalog path set are one catalog
            # relationship, not a wall of unrelated duplicate-file rows.
            if len(asset_groups) == 1:
                asset_group = asset_groups[0]
                items.append(asset_group)
                insight_paths.extend(
                    asset_group_all_paths.get(str(asset_group["group"]), [])
                )
                for catalog_path in catalog_paths:
                    catalog_evidence_group_ids.setdefault(
                        catalog_path, set()
                    ).add(str(asset_group["group"]))
                continue

            catalog_group_id = f"D{group_index}"
            group_index += 1
            asset_groups.sort(
                key=lambda item: (
                    -int(item.get("savings", 0)),
                    str(item.get("name", "")).casefold(),
                    str(item.get("group", "")),
                )
            )
            catalog_names = {Path(path).name for path in catalog_paths}
            first_catalog_name = Path(catalog_paths[0]).name
            catalog_savings = sum(
                int(item.get("savings", 0)) for item in asset_groups
            )
            items.append(
                {
                    "group": catalog_group_id,
                    "name": (
                        first_catalog_name
                        if len(catalog_names) == 1
                        else "Asset catalog overlap"
                    ),
                    "savings": catalog_savings,
                    "pathCount": len(catalog_paths),
                    "paths": list(catalog_paths[:50]),
                    "pathsOmitted": max(0, len(catalog_paths) - 50),
                    "catalogCount": len(catalog_paths),
                    "catalogPaths": list(catalog_paths[:50]),
                    "catalogPathsOmitted": max(0, len(catalog_paths) - 50),
                    "repeatedAssetCount": len(asset_groups),
                    "repeatedRenditionCount": len(asset_groups),
                    "repeatedAssetNameCount": len(
                        {
                            str(group.get("name") or "").casefold()
                            for group in asset_groups
                            if str(group.get("name") or "")
                        }
                    ),
                    "assetGroupCount": len(asset_groups),
                    "assetGroups": asset_groups[:MAX_INSIGHT_ITEMS],
                    "assetGroupsOmitted": max(
                        0, len(asset_groups) - MAX_INSIGHT_ITEMS
                    ),
                    "kind": "asset catalog",
                    "duplicateType": "catalog",
                    "scope": "same-runtime",
                    "actionability": "candidate",
                    "exactMatch": False,
                }
            )
            insight_paths.extend(catalog_paths)
            for catalog_path in catalog_paths:
                catalog_evidence_group_ids.setdefault(catalog_path, set()).add(
                    catalog_group_id
                )

        for catalog_path, asset_group_ids in catalog_asset_group_ids.items():
            catalog = record_by_path.get(catalog_path)
            if catalog is None:
                continue
            evidence_group_ids = sorted(
                catalog_evidence_group_ids.get(catalog_path, asset_group_ids),
                key=lambda value: (len(value), value),
            )
            catalog.metadata.update(
                {
                    "duplicateType": "catalog",
                    "duplicateGroup": evidence_group_ids[0],
                    "duplicateCatalogGroup": evidence_group_ids[0],
                    "duplicateGroups": evidence_group_ids,
                    "duplicateCount": len(evidence_group_ids),
                    "repeatedAssetCount": len(asset_group_ids),
                    "scope": "same-runtime",
                    "actionability": "candidate",
                    "exactMatch": False,
                }
            )

        if items:
            items.sort(
                key=lambda item: (
                    -int(item.get("savings", 0)),
                    str(item.get("name", "")).casefold(),
                    str(item.get("group", "")),
                )
            )
            savings = sum(int(item.get("savings", 0)) for item in items)
            insights.append(
                _insight(
                    "duplicates",
                    "Duplication",
                    f"{len(items)} finding{'s' if len(items) != 1 else ''} within individual targets.",
                    detail=(
                        "Matches are scoped to one executable target. Loose files "
                        "use SHA-256 and size; catalog renditions also bind dimensions, "
                        "scale, and serialized CoreUI size."
                    ),
                    action=(
                        "Confirm bundle lookup behavior, keep one canonical resource, "
                        "and update callers that currently load from another framework bundle."
                    ),
                    severity="high",
                    confidence="review",
                    savings=savings,
                    paths=insight_paths,
                    items=items,
                    category="duplicates",
                )
            )

    def _component_duplicate_insight(
        self,
        items: list[dict[str, Any]],
        insights: list[dict[str, Any]],
    ) -> None:
        if not items:
            return
        repeated_bytes = sum(
            int(item["size"]) * (int(item["copies"]) - 1) for item in items
        )
        paths = [path for item in items for path in item["paths"]]
        insights.append(
            _insight(
                "duplicate-components",
                f"Review {len(items)} exactly repeated embedded component group{'s' if len(items) != 1 else ''}",
                f"Byte-identical framework, bundle, extension, or nested-app contents repeat about {repeated_bytes:,} bytes.",
                detail=(
                    "Each component was fingerprinted from its complete unsigned payload; "
                    "code signatures and provisioning profiles were ignored. Repetition across "
                    "the main app, widgets, and Watch app can be required because those processes "
                    "cannot load code or resources from one another."
                ),
                action=(
                    "For every red component, verify whether both targets truly use it. Remove "
                    "unneeded target membership; otherwise keep required copies and treat the "
                    "number as an audit size, not guaranteed savings."
                ),
                severity="high",
                confidence="review",
                savings=None,
                paths=paths[:100],
                items=items[:100],
                category="duplicates",
            )
        )

    def _unnecessary_insight(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        candidates = [record for record in records if _is_unnecessary(record)]
        if not candidates:
            return
        savings = sum(record.size for record in candidates)
        _mark(candidates, "unnecessary-files")
        insights.append(
            _insight(
                "unnecessary-files",
                f"Remove {len(candidates)} build-time or informational file{'s' if len(candidates) != 1 else ''}",
                "Headers, scripts, module interfaces, source files, or repository docs are present in the shipped bundle.",
                detail=(
                    "These files are normally used while building or documenting a module, "
                    "not while the app is running. OpenBundle reports provisioning profiles "
                    "separately because their necessity depends on the distribution method."
                ),
                action="Remove target membership or exclude these paths from Copy Bundle Resources.",
                severity="high" if savings >= 100 * 1024 else "medium",
                confidence="high",
                savings=savings,
                paths=[record.relative_path for record in candidates],
                items=[
                    {"path": record.relative_path, "size": record.size}
                    for record in sorted(candidates, key=lambda item: item.size, reverse=True)
                ],
                category="files",
            )
        )

    def _small_files_insight(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        small = [
            record
            for record in records
            if 0 < record.size < 4096
            and record.category not in {"signature", "metadata"}
        ]
        overhead = sum(record.allocated_size - record.size for record in small)
        if len(small) < 250 and overhead < 512 * 1024:
            return
        _mark(small, "small-files")
        insights.append(
            _insight(
                "small-files",
                f"Pack {len(small):,} small loose files",
                f"Files below 4 KB create roughly {overhead:,} bytes of allocation slack before code-signing metadata.",
                detail=(
                    "Each loose file also receives an entry in CodeResources. Asset catalogs "
                    "or a deliberately packed data file can remove much of this per-file overhead."
                ),
                action="Move appropriate images/data into asset catalogs and merge tiny string or JSON resources.",
                severity="medium",
                confidence="medium",
                savings=None,
                paths=[record.relative_path for record in small[:100]],
                category="files",
            )
        )

    def _provisioning_profile_insight(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        profiles = [
            record
            for record in records
            if record.name.lower() == "embedded.mobileprovision"
        ]
        if not profiles:
            return
        _mark(profiles, "embedded-provisioning")
        total = sum(record.size for record in profiles)
        insights.append(
            _insight(
                "embedded-provisioning",
                f"Verify {len(profiles)} embedded provisioning profile{'s' if len(profiles) != 1 else ''} at export",
                f"Profiles occupy {total:,} bytes in this signed build, but may be expected for direct device installation.",
                detail=(
                    "A DerivedData .app, development build, or ad hoc export commonly needs "
                    "embedded.mobileprovision. Store processing and the final distribution "
                    "artifact can differ, so these bytes are not counted as guaranteed savings."
                ),
                action=(
                    "Do not delete profiles manually from a signed app. Export an App Store IPA "
                    "and compare that artifact; investigate only profiles that remain where the "
                    "selected distribution method does not require them."
                ),
                severity="info",
                confidence="review",
                savings=None,
                paths=[record.relative_path for record in profiles],
                items=[
                    {"path": record.relative_path, "size": record.size}
                    for record in sorted(
                        profiles, key=lambda record: record.size, reverse=True
                    )
                ],
                category="signing",
            )
        )

    def _asset_catalog_insights(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        loose_scaled: dict[str, dict[str, Any]] = {}
        for record in records:
            if record.category != "image" or ".car::" in record.relative_path:
                continue
            match = re.match(
                r"(?i)\A(.*?)(?:@([123])x)?(~(?:iphone|ipad))?(\.[^./]+)\Z",
                record.relative_path,
            )
            if not match:
                continue
            key = f"{match.group(1)}{match.group(3) or ''}{match.group(4)}"
            bucket = loose_scaled.setdefault(
                key,
                {"path": key, "variants": [], "hasExplicitScale": False},
            )
            explicit_scale = match.group(2) is not None
            bucket["hasExplicitScale"] = bool(
                bucket["hasExplicitScale"] or explicit_scale
            )
            bucket["variants"].append(
                (int(match.group(2) or 1), record, explicit_scale)
            )
        scale_groups = [
            (str(bucket["path"]), list(bucket["variants"]))
            for bucket in loose_scaled.values()
            if bucket["hasExplicitScale"]
            and len({scale for scale, _, _ in bucket["variants"]}) > 1
        ]
        if scale_groups:
            candidates = [
                record for _, group in scale_groups for _, record, _ in group
            ]
            items: list[dict[str, Any]] = []
            for key, group in scale_groups:
                variants = sorted(
                    group,
                    key=lambda item: (item[0], item[1].relative_path.casefold()),
                )
                total_size = sum(record.size for _, record, _ in variants)
                by_scale: dict[int, list[Record]] = {}
                for scale, record, _ in variants:
                    by_scale.setdefault(scale, []).append(record)

                def retained_for(target_scale: int) -> tuple[int, int]:
                    selected_scale = min(
                        by_scale,
                        key=lambda scale: (abs(scale - target_scale), -scale),
                    )
                    return selected_scale, sum(
                        record.size for record in by_scale[selected_scale]
                    )

                latest_scale, latest_retained_size = retained_for(3)
                two_x_scale, two_x_retained_size = retained_for(2)
                latest_savings = max(0, total_size - latest_retained_size)
                two_x_savings = max(0, total_size - two_x_retained_size)
                items.append(
                    {
                        "name": Path(key).name,
                        "path": key,
                        "kind": "loose image scale set",
                        "size": total_size,
                        "retainedSize": latest_retained_size,
                        "retainedScale": latest_scale,
                        "savings": latest_savings,
                        "twoXSavings": two_x_savings,
                        "twoXRetainedSize": two_x_retained_size,
                        "twoXRetainedScale": two_x_scale,
                        "paths": [
                            record.relative_path for _, record, _ in variants
                        ],
                        "variants": [
                            {
                                "path": record.relative_path,
                                "scale": scale,
                                "size": record.size,
                                "implicitScale": not explicit_scale,
                            }
                            for scale, record, explicit_scale in variants
                        ],
                        "deviceEstimates": [
                            {
                                "device": "Latest 3x iPhone",
                                "retainedScale": latest_scale,
                                "retainedSize": latest_retained_size,
                                "savings": latest_savings,
                            },
                            {
                                "device": "2x iPhone",
                                "retainedScale": two_x_scale,
                                "retainedSize": two_x_retained_size,
                                "savings": two_x_savings,
                            },
                        ],
                    }
                )
            items.sort(
                key=lambda item: (-int(item["savings"]), str(item["path"]).casefold())
            )
            savings = sum(int(item["savings"]) for item in items)
            _mark(candidates, "asset-catalog-scales")
            insights.append(
                _insight(
                    "asset-catalog-scales",
                    f"Enable thinning for {len(scale_groups)} loose image set{'s' if len(scale_groups) != 1 else ''}",
                    "Loose scale variants cannot be removed per device by asset-catalog thinning.",
                    detail=(
                        "The headline estimate models a latest 3x iPhone. Each row also shows "
                        "the 2x-device result. An unsuffixed image is treated as 1x only when "
                        "it has an explicit @2x or @3x sibling; singleton images are not "
                        "claimed as thinning savings."
                    ),
                    action="Create image sets in an .xcassets catalog and remove the loose copies from bundle resources.",
                    severity="medium",
                    confidence="medium",
                    savings=savings,
                    paths=[record.relative_path for record in candidates],
                    items=items,
                    category="assets",
                )
            )

        catalogs = [
            record
            for record in records
            if record.category == "asset_catalog"
            and record.size >= 512 * 1024
            and (
                ".framework/" in record.relative_path.lower()
                or ".appex/" in record.relative_path.lower()
                or ".bundle/" in record.relative_path.lower()
            )
        ]
        if len(catalogs) >= 2:
            _mark(catalogs, "catalog-target-membership")
            insights.append(
                _insight(
                    "catalog-target-membership",
                    f"Audit {len(catalogs)} large embedded asset catalogs",
                    "The same source asset library may have target membership in multiple bundles.",
                    detail=(
                        "A catalog in every feature framework or extension is not automatically "
                        "wrong, but it is a common source of repeated onboarding art and branding."
                    ),
                    action="Check each .xcassets target membership and keep resources only in bundles that load them.",
                    severity="medium",
                    confidence="review",
                    savings=None,
                    paths=[record.relative_path for record in catalogs],
                    category="assets",
                )
            )

    def _embedded_target_insight(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        total_size = sum(record.size for record in records)
        grouped: dict[str, list[Record]] = {}
        for record in records:
            parts = Path(record.relative_path).parts
            for index, part in enumerate(parts[:-1]):
                if part.lower().endswith((".app", ".appex")):
                    prefix = Path(*parts[: index + 1]).as_posix()
                    grouped.setdefault(prefix, []).append(record)
                    break
        items: list[dict[str, Any]] = []
        affected: list[Record] = []
        for path, target_records in grouped.items():
            size = sum(record.size for record in target_records)
            share = size / total_size if total_size else 0
            if size < 10 * 1024 * 1024 and share < 0.15:
                continue
            items.append(
                {
                    "name": Path(path).name,
                    "path": path,
                    "size": size,
                    "bundleShare": round(share * 100, 1),
                    "fileCount": len(target_records),
                }
            )
            affected.extend(target_records)
        if not items:
            return
        _mark(affected, "large-embedded-targets")
        largest = max(items, key=lambda item: int(item["size"]))
        insights.append(
            _insight(
                "large-embedded-targets",
                "Shrink oversized embedded targets",
                f"{largest['name']} contributes {largest['bundleShare']}% of the complete bundle.",
                detail=(
                    "Watch apps and extensions ship their own binaries, frameworks, and "
                    "resources. Their target membership can quietly reproduce dependencies "
                    "already present in the main app."
                ),
                action=(
                    "Open the target’s dependency and resource phases, remove products it does "
                    "not use, then compare its exported size independently."
                ),
                severity="high",
                confidence="review",
                savings=None,
                paths=[str(item["path"]) for item in items],
                items=sorted(
                    items, key=lambda item: int(item["size"]), reverse=True
                ),
                category="targets",
            )
        )

    def _linkmap_insight(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        candidates = [
            record
            for record in records
            if record.macho
            and record.size >= 10 * 1024 * 1024
            and record.metadata.get("attribution") != "linkmap"
        ]
        if not candidates:
            return
        _mark(candidates, "missing-linkmaps")
        insights.append(
            _insight(
                "missing-linkmaps",
                "Generate Link Maps for large binaries",
                f"{len(candidates)} large binaries can only be split by Mach-O section, not source module.",
                detail=(
                    "A Link Map attributes linked bytes to object files and compile units, "
                    "turning a large __text region into concrete modules and source targets."
                ),
                action=(
                    "Set LD_GENERATE_MAP_FILE=YES for Release and copy the resulting Linkmaps "
                    "directory into the .xcarchive before running OpenBundle again."
                ),
                severity="info",
                confidence="high",
                savings=None,
                paths=[record.relative_path for record in candidates],
                items=[
                    {"path": record.relative_path, "size": record.size}
                    for record in sorted(
                        candidates, key=lambda record: record.size, reverse=True
                    )
                ],
                category="attribution",
            )
        )

    def _swift_reflection_insight(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        items: list[dict[str, Any]] = []
        affected: list[Record] = []
        total = 0
        for record in records:
            if not record.macho:
                continue
            names = 0
            metadata = 0
            for architecture in record.macho.get("architectures", []):
                for segment in architecture.get("segments", []):
                    for section in segment.get("sections", []):
                        name = str(section.get("name") or "")
                        size = int(section.get("size", 0))
                        if name == "__swift5_reflstr":
                            names += size
                        if name in {"__swift5_reflstr", "__swift5_fieldmd"}:
                            metadata += size
            if not names:
                continue
            total += names
            affected.append(record)
            items.append(
                {
                    "path": record.relative_path,
                    "reflectionNameBytes": names,
                    "reflectionMetadataBytes": metadata,
                }
            )
        if total < 128 * 1024:
            return
        _mark(affected, "swift-reflection")
        insights.append(
            _insight(
                "swift-reflection",
                "Trim Swift reflection names",
                f"Stored property and enum-case names occupy about {total:,} bytes.",
                detail=(
                    "SWIFT_REFLECTION_METADATA_LEVEL=without-names removes names while "
                    "retaining type metadata. Reflection, debugging, crash tooling, and the "
                    "Memory Graph can lose useful information."
                ),
                action=(
                    "Trial “Reflection Metadata Level: Without Names” in Release, exercise "
                    "Mirror-driven and diagnostic code, then compare the rebuilt archive."
                ),
                severity="low",
                confidence="review",
                savings=None,
                paths=[record.relative_path for record in affected],
                items=sorted(
                    items,
                    key=lambda item: int(item["reflectionNameBytes"]),
                    reverse=True,
                ),
                category="binaries",
            )
        )

    def _embedded_string_data_insight(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        items: list[dict[str, Any]] = []
        affected: list[Record] = []
        total = 0
        for record in records:
            if not record.macho:
                continue
            size = sum(
                int(section.get("size", 0))
                for architecture in record.macho.get("architectures", [])
                for segment in architecture.get("segments", [])
                for section in segment.get("sections", [])
                if str(section.get("name") or "") == "__cstring"
            )
            if size < 256 * 1024:
                continue
            total += size
            affected.append(record)
            items.append({"path": record.relative_path, "cstringBytes": size})
        if total < 1024 * 1024:
            return
        _mark(affected, "embedded-string-data")
        insights.append(
            _insight(
                "embedded-string-data",
                "Move static payloads out of code",
                f"C string sections occupy about {total:,} bytes across large binaries.",
                detail=(
                    "Normal code contributes strings too, so this is an audit rather than a "
                    "saving. Generated JSON, base64, lookup tables, and other large literals "
                    "compress and thin better as resource files."
                ),
                action=(
                    "Search generated sources and large literals first; move true payload data "
                    "into appropriately compressed asset or resource files."
                ),
                severity="low",
                confidence="review",
                savings=None,
                paths=[record.relative_path for record in affected],
                items=sorted(
                    items, key=lambda item: int(item["cstringBytes"]), reverse=True
                ),
                category="binaries",
            )
        )

    def _image_insights(
        self,
        records: list[Record],
        asset_renditions: list[dict[str, Any]],
        minimum_os: str,
        insights: list[dict[str, Any]],
    ) -> None:
        candidates = [
            record
            for record in records
            if record.category == "image"
            and record.absolute_path.suffix.lower() in IMAGE_SUFFIXES
            and record.absolute_path.suffix.lower() not in {".heic", ".heif"}
            and record.size >= 64 * 1024
            and "appicon" not in record.relative_path.lower()
        ]
        candidates.sort(key=lambda record: record.size, reverse=True)
        optimization_items: list[dict[str, Any]] = []
        total_savings = 0
        optimized_records: list[Record] = []
        image_review_items: list[dict[str, Any]] = []
        image_review_records: list[Record] = []
        reviewed_image_paths: set[str] = set()

        def add_image_review(
            *,
            name: str,
            path: str,
            asset_path: str,
            size: int,
            width: int,
            height: int,
            kind: str,
            record: Record | None = None,
            entry: dict[str, Any] | None = None,
        ) -> None:
            if not asset_path or asset_path in reviewed_image_paths:
                return
            if "appicon" in f"{name} {path}".lower():
                return
            reasons: list[str] = []
            if size >= LARGE_IMAGE_REVIEW_BYTES:
                reasons.append(f"{size:,} stored bytes")
            if max(width, height) >= LARGE_IMAGE_REVIEW_EDGE:
                reasons.append(f"{width:,}×{height:,} pixels")
            if not reasons:
                return
            reviewed_image_paths.add(asset_path)
            item = {
                "name": name,
                "path": path,
                "assetPath": asset_path,
                "size": size,
                "dimensions": f"{width}×{height}" if width and height else "Unknown",
                "reason": " and ".join(reasons),
                "kind": kind,
            }
            image_review_items.append(item)
            if record is not None and record not in image_review_records:
                image_review_records.append(record)
            if entry is not None and "oversized-images" not in entry.setdefault(
                "insights", []
            ):
                entry["insights"].append("oversized-images")

        if candidates and self.platform.image_conversion_available:
            _progress(self.progress, "Simulating image compression (largest images first)…")
            with tempfile.TemporaryDirectory(prefix="openbundle-images-") as directory:
                output = Path(directory)
                for record in candidates[:80]:
                    properties = self.platform.image_properties(record.absolute_path)
                    thumbnail = properties.get("thumbnailDataURL")
                    if not (
                        isinstance(thumbnail, str)
                        and len(thumbnail) <= 96 * 1024
                        and re.fullmatch(
                            r"data:image/(?:png|webp);base64,[A-Za-z0-9+/]+={0,2}",
                            thumbnail,
                        )
                    ):
                        properties.pop("thumbnailDataURL", None)
                    record.metadata.update(properties)
                    width = int(properties.get("pixelWidth", 0))
                    height = int(properties.get("pixelHeight", 0))
                    add_image_review(
                        name=record.name,
                        path=record.relative_path,
                        asset_path=record.relative_path,
                        size=record.size,
                        width=width,
                        height=height,
                        kind="loose image",
                        record=record,
                    )

                    attempts: list[tuple[str, int]] = []
                    if _safe_version_at_least(minimum_os, 12):
                        heic_size = self.platform.converted_image_size(
                            record.absolute_path, output, "heic", 85
                        )
                        if heic_size:
                            attempts.append(("HEIC quality 85", heic_size))
                    if (
                        not bool(properties.get("hasAlpha"))
                        and record.absolute_path.suffix.lower()
                        in {".png", ".jpg", ".jpeg"}
                    ):
                        jpeg_size = self.platform.converted_image_size(
                            record.absolute_path, output, "jpeg", 85
                        )
                        if jpeg_size:
                            attempts.append(("JPEG quality 85", jpeg_size))
                    if not attempts:
                        continue
                    method, optimized_size = min(attempts, key=lambda item: item[1])
                    saving = record.size - optimized_size
                    if saving < 4 * 1024:
                        continue
                    record.metadata["optimizedSizeEstimate"] = optimized_size
                    record.metadata["optimizationSavingsEstimate"] = saving
                    record.metadata["optimizedRenditionCount"] = 1
                    record.metadata["optimizationMethod"] = method
                    optimization_items.append(
                        {
                            "name": record.name,
                            "path": record.relative_path,
                            "assetPath": record.relative_path,
                            "size": record.size,
                            "optimizedSize": optimized_size,
                            "savings": saving,
                            "method": method,
                            "dimensions": (
                                f"{width}×{height}" if width and height else "Unknown"
                            ),
                            "kind": "loose image",
                        }
                    )
                    total_savings += saving
                    optimized_records.append(record)

        # Size alone is enough to warrant a review, even when a browser cannot
        # decode the format or the file falls outside the bounded conversion
        # batch. No saving is claimed until the app's rendered size is known.
        for record in records:
            if (
                record.category == "image"
                and record.size >= LARGE_IMAGE_REVIEW_BYTES
                and ".car::" not in record.relative_path
            ):
                add_image_review(
                    name=record.name,
                    path=record.relative_path,
                    asset_path=record.relative_path,
                    size=record.size,
                    width=int(record.metadata.get("pixelWidth", 0) or 0),
                    height=int(record.metadata.get("pixelHeight", 0) or 0),
                    kind="loose image",
                    record=record,
                )

        # Browser/WASM catalog analysis supplies actual conversion byte counts.
        # A logical image can contain 1x, 2x and 3x renditions, so represent it
        # with only its highest-scale physical rendition instead of adding the
        # device alternatives together.
        records_by_path = {record.relative_path: record for record in records}
        catalog_paths: list[str] = []
        grouped_renditions: dict[
            int, tuple[dict[str, Any], list[dict[str, Any]]]
        ] = {}
        for rendition in asset_renditions:
            entry = rendition.get("entry")
            if not isinstance(entry, dict):
                continue
            metadata = entry.setdefault("metadata", {})
            if (
                metadata.get("assetType") != "image"
                and rendition.get("assetType") != "image"
            ):
                continue
            grouped_renditions.setdefault(id(entry), (entry, []))[1].append(rendition)

        for entry, renditions in grouped_renditions.values():
            rendition = _representative_asset_rendition(renditions)
            if rendition is None:
                continue
            size = int(rendition.get("size", 0) or 0)
            metadata = entry.setdefault("metadata", {})
            catalog_path = str(rendition.get("path", "")).split("::", 1)[0]
            catalog_record = records_by_path.get(catalog_path)
            item_path = str(
                rendition.get("displayPath")
                or rendition.get("path")
                or catalog_path
            )
            asset_path = str(
                entry.get("path") or rendition.get("path") or item_path
            )
            asset_name = str(
                entry.get("name") or rendition.get("name") or "Image"
            )
            rendition_name = str(rendition.get("renditionName") or asset_name)
            width = int(rendition.get("pixelWidth", 0) or 0)
            height = int(rendition.get("pixelHeight", 0) or 0)
            add_image_review(
                name=asset_name,
                path=item_path,
                asset_path=asset_path,
                size=size,
                width=width,
                height=height,
                kind="asset catalog rendition",
                record=catalog_record,
                entry=entry,
            )

            optimized_size = int(rendition.get("optimizedSize", 0) or 0)
            saving = size - optimized_size
            if not optimized_size or saving < 4 * 1024:
                continue
            method = str(rendition.get("optimizationMethod") or "quality-85")
            metadata["optimizedSizeEstimate"] = optimized_size
            metadata["optimizedOriginalSize"] = size
            metadata["optimizationSavingsEstimate"] = saving
            metadata["optimizedRenditionCount"] = 1
            metadata["optimizationMethod"] = method
            if "optimize-images" not in entry.setdefault("insights", []):
                entry["insights"].append("optimize-images")
            if catalog_record is not None:
                _mark([catalog_record], "optimize-images")
                if catalog_record not in optimized_records:
                    optimized_records.append(catalog_record)
            catalog_paths.append(item_path)
            optimization_items.append(
                {
                    "name": asset_name,
                    "path": item_path,
                    "assetPath": asset_path,
                    "renditionName": rendition_name,
                    "size": size,
                    "optimizedSize": optimized_size,
                    "savings": saving,
                    "method": method,
                    "dimensions": f"{width}×{height}" if width and height else "Unknown",
                    "kind": "asset catalog rendition",
                }
            )
            total_savings += saving

        if optimization_items:
            _mark(optimized_records, "optimize-images")
            optimization_items.sort(key=lambda item: int(item["savings"]), reverse=True)
            paths = list(
                dict.fromkeys(
                    [record.relative_path for record in optimized_records] + catalog_paths
                )
            )
            insights.append(
                _insight(
                    "optimize-images",
                    f"Optimize {len(optimization_items)} image{'s' if len(optimization_items) != 1 else ''}",
                    f"Measured quality-85 conversions estimate about {total_savings:,} bytes of savings.",
                    detail=(
                        "The arrow on each image is an actual quality-85 re-encode measured "
                        "in this browser, not a ratio guess. HEIC is tested when the app's "
                        "minimum iOS version supports it; opaque artwork can fall back to "
                        "JPEG. Conversion can change colour or fine detail."
                    ),
                    action=(
                        "Use the method shown on each row: convert the source to HEIC at "
                        "quality 85 when HEIC wins (iOS 12+), or to quality-85 JPEG only "
                        "when the artwork is opaque. Replace the source in .xcassets, compare "
                        "it visually, then rebuild and measure the IPA again."
                    ),
                    severity="high" if total_savings >= 1024 * 1024 else "medium",
                    confidence="medium",
                    savings=total_savings,
                    paths=paths,
                    items=optimization_items,
                    category="images",
                )
            )

        if image_review_items:
            _mark(image_review_records, "oversized-images")
            image_review_items.sort(
                key=lambda item: (-int(item["size"]), str(item["path"]).casefold())
            )
            insights.append(
                _insight(
                    "oversized-images",
                    f"Review {len(image_review_items)} large image{'s' if len(image_review_items) != 1 else ''}",
                    "These images occupy at least 1 MB in the bundle or have an edge of 3,000 px or more.",
                    detail=(
                        "This is a review flag, not a claimed saving. A large source can be "
                        "correct for a full-screen, zoomable, cropped, or iPad layout. The "
                        "decoded pixel buffer can also be much larger than the encoded file."
                    ),
                    action=(
                        "Check the largest rendered point size for each image and multiply it "
                        "by the highest display scale you support. If the source exceeds that "
                        "without a zoom or crop requirement, downscale it before applying the "
                        "measured HEIC or JPEG compression recommendation."
                    ),
                    severity="medium",
                    confidence="review",
                    savings=None,
                    paths=[str(item["path"]) for item in image_review_items],
                    items=image_review_items,
                    category="images",
                    review_only=True,
                )
            )

    @staticmethod
    def _attach_asset_rendition_metadata(
        asset_renditions: list[dict[str, Any]],
    ) -> None:
        """Keep compact, inspectable rendition facts without retaining pixel data."""

        max_renditions_per_asset = 24
        max_thumbnail_url_bytes = 96 * 1024
        thumbnail_pattern = re.compile(
            r"\Adata:image/(?:png|webp);base64,[A-Za-z0-9+/]+={0,2}\Z"
        )
        grouped: dict[int, tuple[dict[str, Any], list[dict[str, Any]]]] = {}

        for rendition in asset_renditions:
            entry = rendition.get("entry")
            if not isinstance(entry, dict):
                continue
            metadata = entry.setdefault("metadata", {})
            if (
                metadata.get("assetType") != "image"
                and rendition.get("assetType") != "image"
            ):
                continue
            size = int(rendition.get("size", 0) or 0)
            optimized_size = int(rendition.get("optimizedSize", 0) or 0)
            item: dict[str, Any] = {
                "name": str(
                    rendition.get("renditionName")
                    or rendition.get("name")
                    or "Rendition"
                ),
                "size": size,
            }
            optional = {
                "width": int(rendition.get("pixelWidth", 0) or 0),
                "height": int(rendition.get("pixelHeight", 0) or 0),
                "scale": int(rendition.get("scale", 0) or 0),
                "encoding": str(rendition.get("encoding") or ""),
                "opaque": rendition.get("opaque"),
                "physical": rendition.get("physical"),
                "optimizedSize": optimized_size,
                "optimizationMethod": str(
                    rendition.get("optimizationMethod") or ""
                ),
                "duplicateGroup": str(rendition.get("duplicateGroup") or ""),
                "duplicateType": str(rendition.get("duplicateType") or ""),
                "scope": str(rendition.get("scope") or ""),
                "actionability": str(rendition.get("actionability") or ""),
            }
            for key, value in optional.items():
                if key in {"opaque", "physical"} and isinstance(value, bool):
                    item[key] = value
                elif value not in (None, "", 0):
                    item[key] = value
            if optimized_size and optimized_size < size:
                item["savings"] = size - optimized_size
            grouped.setdefault(id(entry), (entry, []))[1].append(item)

            thumbnail = rendition.get("thumbnailDataURL")
            if (
                isinstance(thumbnail, str)
                and len(thumbnail) <= max_thumbnail_url_bytes
                and thumbnail_pattern.fullmatch(thumbnail)
                and "thumbnailDataURL" not in metadata
            ):
                metadata["thumbnailDataURL"] = thumbnail

        for entry, items in grouped.values():
            items.sort(
                key=lambda item: (
                    bool(item.get("savings") or item.get("duplicateGroup")),
                    int(item.get("savings", 0) or 0),
                    int(item.get("size", 0) or 0),
                ),
                reverse=True,
            )
            metadata = entry.setdefault("metadata", {})
            representative = _representative_asset_rendition(items)
            if representative is not None:
                headline_keys = (
                    "name",
                    "size",
                    "width",
                    "height",
                    "scale",
                    "encoding",
                    "opaque",
                    "optimizedSize",
                    "savings",
                    "optimizationMethod",
                )
                metadata["headlineRendition"] = {
                    key: representative[key]
                    for key in headline_keys
                    if key in representative
                }
            metadata["renditions"] = items[:max_renditions_per_asset]
            omitted = len(items) - max_renditions_per_asset
            if omitted > 0:
                metadata["renditionsOmitted"] = omitted

    def _alternate_icon_insight(
        self,
        records: list[Record],
        info_plist: dict[str, Any],
        insights: list[dict[str, Any]],
    ) -> None:
        icon_names: set[str] = set()
        for key in ("CFBundleIcons", "CFBundleIcons~ipad"):
            icon_root = info_plist.get(key)
            if not isinstance(icon_root, dict):
                continue
            alternate = icon_root.get("CFBundleAlternateIcons")
            if not isinstance(alternate, dict):
                continue
            for value in alternate.values():
                if not isinstance(value, dict):
                    continue
                files = value.get("CFBundleIconFiles")
                if isinstance(files, list):
                    icon_names.update(
                        Path(str(name)).stem.lower() for name in files if name
                    )
        if not icon_names or not self.platform.image_conversion_available:
            return
        candidates = [
            record
            for record in records
            if record.category == "image"
            and (
                record.absolute_path.stem.lower() in icon_names
                or any(
                    record.absolute_path.stem.lower().startswith(f"{name}@")
                    for name in icon_names
                )
            )
        ]
        items: list[dict[str, Any]] = []
        affected: list[Record] = []
        savings = 0
        with tempfile.TemporaryDirectory(prefix="openbundle-icons-") as directory:
            output = Path(directory)
            for record in candidates:
                properties = self.platform.image_properties(record.absolute_path)
                record.metadata.update(properties)
                if (
                    int(properties.get("pixelWidth", 0)) != 1024
                    or int(properties.get("pixelHeight", 0)) != 1024
                ):
                    continue
                optimized_size = self.platform.alternate_icon_size(
                    record.absolute_path, output
                )
                if optimized_size is None or optimized_size >= record.size:
                    continue
                item_savings = record.size - optimized_size
                if item_savings < 4 * 1024:
                    continue
                savings += item_savings
                affected.append(record)
                items.append(
                    {
                        "path": record.relative_path,
                        "size": record.size,
                        "optimizedSize": optimized_size,
                        "savings": item_savings,
                    }
                )
        if affected:
            _mark(affected, "alternate-icons")
            insights.append(
                _insight(
                    "alternate-icons",
                    f"Reduce detail in {len(affected)} alternate app icon{'s' if len(affected) != 1 else ''}",
                    f"A local 180 px downscale followed by the required 1024 px export saved about {savings:,} bytes.",
                    detail=(
                        "The primary App Store icon needs full 1024 px detail. Alternate "
                        "icons are displayed at much smaller sizes, so full-resolution detail "
                        "can add bytes without improving the on-device result."
                    ),
                    action="Visually compare the simulated-detail export and replace only alternate icons; leave the primary marketing icon unchanged.",
                    severity="low",
                    confidence="medium",
                    savings=savings,
                    paths=[record.relative_path for record in affected],
                    items=items,
                    category="images",
                )
            )

    def _coverage_instrumentation_insight(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        affected: list[Record] = []
        items: list[dict[str, Any]] = []
        savings = 0
        for record in records:
            if not record.macho:
                continue
            record_bytes = 0
            section_names: set[str] = set()
            architectures: list[str] = []
            for architecture in record.macho.get("architectures", []):
                arch_bytes = 0
                for segment in architecture.get("segments", []):
                    segment_name = str(segment.get("name") or "")
                    matching_sections = [
                        section
                        for section in segment.get("sections", [])
                        if str(section.get("name") or "").startswith(
                            ("__llvm_prf", "__llvm_cov")
                        )
                    ]
                    if segment_name == "__LLVM_COV":
                        arch_bytes += int(segment.get("size", 0))
                    else:
                        arch_bytes += sum(
                            int(section.get("size", 0))
                            for section in matching_sections
                        )
                    section_names.update(
                        str(section.get("name") or "")
                        for section in matching_sections
                    )
                if arch_bytes:
                    record_bytes += arch_bytes
                    architectures.append(str(architecture.get("architecture") or "?"))
            if not record_bytes:
                continue
            record.metadata["coverageInstrumentationBytes"] = record_bytes
            affected.append(record)
            savings += record_bytes
            items.append(
                {
                    "path": record.relative_path,
                    "size": record.size,
                    "coverageBytes": record_bytes,
                    "architectures": architectures,
                    "sections": sorted(section_names),
                }
            )
        if not affected:
            return
        _mark(affected, "release-code-coverage")
        insights.append(
            _insight(
                "release-code-coverage",
                "Disable code coverage instrumentation in Release",
                f"LLVM coverage/profile segments occupy about {savings:,} bytes across {len(affected)} production binar{'ies' if len(affected) != 1 else 'y'}.",
                detail=(
                    "The __LLVM_COV / __llvm_prf* data is compiler-generated profiling "
                    "instrumentation, not ordinary symbols. A release archive normally does "
                    "not need it, and strip will not provide the same saving."
                ),
                action=(
                    "Check the archive scheme and Release configuration for code coverage, "
                    "CLANG_ENABLE_CODE_COVERAGE, -fprofile-instr-generate, and "
                    "-fcoverage-mapping. Disable them for distribution, rebuild, and compare."
                ),
                severity="high",
                confidence="high",
                savings=savings,
                paths=[record.relative_path for record in affected],
                items=sorted(
                    items, key=lambda item: int(item["coverageBytes"]), reverse=True
                ),
                category="binaries",
            )
        )

    def _bitcode_insight(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        affected: list[Record] = []
        items: list[dict[str, Any]] = []
        savings = 0
        for record in records:
            if not record.macho:
                continue
            record_bytes = 0
            architectures: list[str] = []
            for architecture in record.macho.get("architectures", []):
                arch_bytes = sum(
                    int(segment.get("size", 0))
                    for segment in architecture.get("segments", [])
                    if str(segment.get("name") or "") == "__LLVM"
                )
                if arch_bytes:
                    record_bytes += arch_bytes
                    architectures.append(str(architecture.get("architecture") or "?"))
            if not record_bytes:
                continue
            record.metadata["embeddedBitcodeBytes"] = record_bytes
            affected.append(record)
            savings += record_bytes
            items.append(
                {
                    "path": record.relative_path,
                    "size": record.size,
                    "bitcodeBytes": record_bytes,
                    "architectures": architectures,
                }
            )
        if not affected:
            return
        _mark(affected, "embedded-bitcode")
        insights.append(
            _insight(
                "embedded-bitcode",
                "Remove legacy embedded bitcode from shipped binaries",
                f"__LLVM segments occupy about {savings:,} bytes across {len(affected)} binar{'ies' if len(affected) != 1 else 'y'}.",
                detail=(
                    "Apple no longer accepts bitcode submissions, but older prebuilt vendor "
                    "frameworks can still carry full or marker payloads into local builds."
                ),
                action=(
                    "Update the dependency or rebuild it without embedded bitcode. Verify the "
                    "exported archive after changing ENABLE_BITCODE or vendor packaging."
                ),
                severity="high",
                confidence="high",
                savings=savings,
                paths=[record.relative_path for record in affected],
                items=sorted(
                    items, key=lambda item: int(item["bitcodeBytes"]), reverse=True
                ),
                category="binaries",
            )
        )

    def _symbol_insight(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        binaries = [
            record
            for record in records
            if record.macho
            and not record.name.lower().startswith("libswift")
            and int(record.metadata.get("stripSymbolEstimateBytes", 0)) >= 16 * 1024
        ]
        binaries.sort(key=lambda record: record.size, reverse=True)
        if not binaries:
            return
        _progress(self.progress, "Inspecting production symbol tables…")
        items: list[dict[str, Any]] = []
        saving_total = 0
        stripped_records: list[Record] = []
        native_sizes: dict[str, int] = {}
        if self.platform.symbol_strip_available:
            with tempfile.TemporaryDirectory(prefix="openbundle-strip-") as directory:
                output = Path(directory)
                for record in binaries[:50]:
                    stripped_size = self.platform.stripped_size(
                        record.absolute_path, output
                    )
                    if stripped_size is not None and stripped_size < record.size:
                        native_sizes[record.relative_path] = stripped_size

        for record in binaries[:50]:
            estimate = int(record.metadata.get("stripSymbolEstimateBytes", 0))
            stripped_size = native_sizes.get(record.relative_path)
            if stripped_size is not None:
                saving = record.size - stripped_size
                method = "Apple strip -rSTx simulation"
            else:
                saving = min(record.size, estimate)
                stripped_size = record.size - saving
                method = "portable Mach-O symbol-table estimate"
            if saving < 16 * 1024:
                continue

            architecture_items: list[dict[str, Any]] = []
            for architecture in record.macho.get("architectures", []):
                symbol_table = architecture.get("symbol_table") or {}
                strip = symbol_table.get("strip_rSTx") or {}
                architecture_saving = int(strip.get("estimated_bytes", 0) or 0)
                if architecture_saving <= 0:
                    continue
                classifications = symbol_table.get("classifications") or {}
                architecture_items.append(
                    {
                        "architecture": architecture.get("architecture", "Unknown"),
                        "estimatedBytes": architecture_saving,
                        "candidateCount": int(strip.get("candidate_count", 0) or 0),
                        "localCount": int(
                            (classifications.get("local") or {}).get("count", 0)
                        ),
                        "debugCount": int(
                            (classifications.get("debug") or {}).get("count", 0)
                        ),
                        "swiftCount": int(
                            (classifications.get("swift") or {}).get("count", 0)
                        ),
                        "swiftEligible": bool(strip.get("swift_eligible")),
                    }
                )

            record.metadata["strippedSizeEstimate"] = stripped_size
            items.append(
                {
                    "path": record.relative_path,
                    "size": record.size,
                    "strippedSize": stripped_size,
                    "savings": saving,
                    "method": method,
                    "architectures": architecture_items,
                }
            )
            saving_total += saving
            stripped_records.append(record)
        if stripped_records:
            _mark(stripped_records, "strip-symbols")
            exact_count = sum(
                item["method"] == "Apple strip -rSTx simulation" for item in items
            )
            measurement = (
                "A copied-binary strip simulation"
                if exact_count == len(items)
                else "Portable Mach-O parsing"
            )
            insights.append(
                _insight(
                    "strip-symbols",
                    f"Strip production symbols from {len(stripped_records)} binar{'ies' if len(stripped_records) != 1 else 'y'}",
                    f"{measurement} found about {saving_total:,} removable bytes.",
                    detail=(
                        "OpenBundle reads each nlist and string-table entry and models "
                        "strip -rSTx, including local, debug, and eligible Swift symbols. "
                        "Stripping must happen only after matching dSYMs are produced and "
                        "uploaded, or crash symbolication will suffer."
                    ),
                    action="For Release only, validate STRIP settings or add a final strip -rSTx phase ordered after dSYM generation.",
                    severity="high",
                    confidence="high" if exact_count == len(items) else "medium",
                    savings=saving_total,
                    paths=[record.relative_path for record in stripped_records],
                    items=items,
                    category="binaries",
                )
            )

    def _exported_symbols_insight(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        """Recommend a small export allowlist for app executables.

        This is deliberately separate from ``strip-symbols``.  The export trie
        is consumed by dyld, while LC_SYMTAB is the classic symbol/string table.
        A linker allowlist can shrink both and may enable further dead stripping,
        but this static estimate never claims the build-dependent code saving.
        """

        affected: list[Record] = []
        items: list[dict[str, Any]] = []
        saving_total = 0
        for record in records:
            if not record.macho or record.name.lower().startswith("libswift"):
                continue
            architecture_items: list[dict[str, Any]] = []
            record_saving = 0
            exported_count = 0
            for architecture in record.macho.get("architectures", []):
                if not architecture.get("is_executable"):
                    continue
                export_trie = architecture.get("export_trie") or {}
                if not export_trie.get("valid") or export_trie.get("malformed"):
                    continue
                count = int(export_trie.get("symbol_count", 0) or 0)
                allowlist_count = int(bool(export_trie.get("has_main"))) + int(
                    bool(export_trie.get("has_mh_execute_header"))
                )
                removable_count = max(0, count - allowlist_count)
                if removable_count < 32:
                    continue

                trie_bytes = int(export_trie.get("size", 0) or 0)
                symbol_table = architecture.get("symbol_table") or {}
                external = (
                    (symbol_table.get("classifications") or {}).get(
                        "external_defined"
                    )
                    or {}
                )
                external_bytes = int(external.get("entry_bytes", 0) or 0) + int(
                    external.get("string_bytes", 0) or 0
                )
                # Retain a proportional allowance for _main and optionally
                # __mh_execute_header.  Linker layout can change, so this is a
                # bounded estimate rather than a promised post-build delta.
                retained_external = (
                    math.ceil(external_bytes * allowlist_count / count)
                    if count and external_bytes
                    else 0
                )
                estimated = trie_bytes + max(0, external_bytes - retained_external)
                if estimated < 4 * 1024:
                    continue
                architecture_items.append(
                    {
                        "architecture": architecture.get("architecture", "Unknown"),
                        "exportCount": count,
                        "candidateCount": removable_count,
                        "exportTrieBytes": trie_bytes,
                        "reachableExportTrieBytes": int(
                            export_trie.get("reachable_byte_count", 0) or 0
                        ),
                        "trailingExportMetadataBytes": int(
                            export_trie.get("trailing_byte_count", 0) or 0
                        ),
                        "externalSymbolBytes": external_bytes,
                        "estimatedBytes": estimated,
                        "hasMain": bool(export_trie.get("has_main")),
                        "hasMHExecuteHeader": bool(
                            export_trie.get("has_mh_execute_header")
                        ),
                        "sample": list(export_trie.get("symbols_sample", []))[:12],
                    }
                )
                record_saving += estimated
                exported_count += count

            if not architecture_items:
                continue
            record.metadata["exportedSymbolMetadataEstimate"] = record_saving
            affected.append(record)
            saving_total += record_saving
            items.append(
                {
                    "path": record.relative_path,
                    "size": record.size,
                    "exportCount": exported_count,
                    "savings": record_saving,
                    "architectures": architecture_items,
                }
            )

        if not affected:
            return
        _mark(affected, "exported-symbols")
        insights.append(
            _insight(
                "exported-symbols",
                f"Limit exported symbols in {len(affected)} executable{'s' if len(affected) != 1 else ''}",
                f"Export tries and related external-symbol records use about {saving_total:,} reducible bytes.",
                detail=(
                    "App and extension executables rarely need to publish their Swift APIs. "
                    "This estimate covers the full dyld export region—including trailing "
                    "symbol metadata—and related external-symbol records. It deliberately "
                    "excludes any additional build-dependent dead-code saving."
                ),
                action=(
                    "Set EXPORTED_SYMBOLS_FILE to a reviewed allowlist containing _main. "
                    "Keep __mh_execute_header for Crashlytics when required, and retain "
                    "anything reached through dlsym or a plug-in mechanism."
                ),
                severity="high" if saving_total >= 1024 * 1024 else "medium",
                confidence="medium",
                savings=saving_total,
                paths=[record.relative_path for record in affected],
                items=sorted(items, key=lambda item: int(item["savings"]), reverse=True),
                category="binaries",
            )
        )

    def _architecture_insight(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        affected: list[Record] = []
        items: list[dict[str, Any]] = []
        savings = 0
        for record in records:
            if not record.macho or not record.macho.get("is_fat"):
                continue
            unwanted = [
                arch
                for arch in record.macho.get("architectures", [])
                if str(arch.get("architecture")) in {"i386", "x86_64"}
                or "Simulator" in str(arch.get("platform") or "")
            ]
            if not unwanted:
                continue
            record_savings = sum(int(arch.get("size", 0)) for arch in unwanted)
            affected.append(record)
            savings += record_savings
            items.append(
                {
                    "path": record.relative_path,
                    "architectures": [
                        str(arch.get("architecture")) for arch in unwanted
                    ],
                    "savings": record_savings,
                }
            )
        if affected:
            _mark(affected, "simulator-architectures")
            insights.append(
                _insight(
                    "simulator-architectures",
                    "Remove simulator architectures from the distribution bundle",
                    f"Simulator/i386/x86_64 slices account for about {savings:,} bytes.",
                    detail="A device IPA should normally contain device architectures only. Fat development .app bundles are expected, but they should not be shipped.",
                    action="Fix the archive configuration or vendor framework packaging so the exported IPA contains device slices only.",
                    severity="high",
                    confidence="high",
                    savings=savings,
                    paths=[record.relative_path for record in affected],
                    items=items,
                    category="binaries",
                )
            )

    def _framework_insights(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        debug_pattern = re.compile(
            r"(?i)(xctest|quick|nimble|flex|injection|reveal|snapshottesting|ohhttpstubs)"
        )
        debug = [
            record
            for record in records
            if record.macho
            and debug_pattern.search(record.relative_path)
            and (
                ".framework/" in record.relative_path.lower()
                or ".dylib" in record.relative_path.lower()
            )
        ]
        if debug:
            _mark(debug, "debug-frameworks")
            insights.append(
                _insight(
                    "debug-frameworks",
                    "Remove test or debug tooling from Release",
                    "Framework names associated with testing, injection, or inspection are present in the bundle.",
                    detail="Name matching is heuristic, but these products are rarely intended for an App Store archive.",
                    action="Remove their Release target linkage and embed phases.",
                    severity="high",
                    confidence="medium",
                    savings=None,
                    paths=[record.relative_path for record in debug],
                    category="frameworks",
                )
            )

        framework_sizes: dict[str, int] = {}
        for record in records:
            name = _framework_name(record.relative_path)
            if name:
                framework_sizes[name] = framework_sizes.get(name, 0) + record.size
        sdk_prefixes = {
            "AWS": lambda name: name.startswith("AWS"),
            "Amplify": lambda name: name.startswith("Amplify"),
            "Firebase": lambda name: name.startswith("Firebase"),
            "Google": lambda name: name.startswith("Google"),
            "Stripe": lambda name: name.startswith("Stripe"),
            "Twilio": lambda name: name.startswith("Twilio"),
        }
        for prefix, matcher in sdk_prefixes.items():
            modules = sorted(name for name in framework_sizes if matcher(name))
            if len(modules) < 3:
                continue
            total = sum(framework_sizes[name] for name in modules)
            insight_id = f"audit-sdk-{prefix.lower()}"
            matching_records = [
                record
                for record in records
                if (name := _framework_name(record.relative_path)) in modules
            ]
            _mark(matching_records, insight_id)
            insights.append(
                _insight(
                    insight_id,
                    f"Audit {len(modules)} {prefix} SDK modules",
                    f"These modules occupy {total:,} bytes across their framework bundles.",
                    detail="Presence does not prove a module is unused. Modular SDKs often make it easy to link a broader product set than the app calls.",
                    action="Compare linked package products with imports and runtime features; remove only modules not required by transitive dependencies.",
                    severity="medium",
                    confidence="review",
                    savings=None,
                    paths=modules,
                    items=[
                        {"name": name, "size": framework_sizes[name]}
                        for name in sorted(
                            modules, key=lambda item: framework_sizes[item], reverse=True
                        )
                    ],
                    category="dependencies",
                )
            )

    def _localization_insights(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        localized = [
            record
            for record in records
            if record.absolute_path.suffix.lower() == ".strings"
        ]
        binary_plists: list[Record] = []
        comment_items: list[dict[str, Any]] = []
        comment_records: list[Record] = []
        comment_savings = 0
        comment_pattern = re.compile(rb"/\*.*?\*/", re.DOTALL)
        for record in localized:
            try:
                raw = record.absolute_path.read_bytes()
            except OSError:
                continue
            if raw.startswith(b"bplist00"):
                binary_plists.append(record)
                continue
            comments = comment_pattern.findall(raw)
            if comments:
                size = sum(len(comment) for comment in comments)
                comment_savings += size
                comment_records.append(record)
                comment_items.append(
                    {
                        "path": record.relative_path,
                        "commentBytes": size,
                        "size": record.size,
                    }
                )
        if binary_plists:
            _mark(binary_plists, "localization-encoding")
            insights.append(
                _insight(
                    "localization-encoding",
                    f"Emit {len(binary_plists)} .strings file{'s' if len(binary_plists) != 1 else ''} as UTF-8 text",
                    "Binary plist encoding is often larger for localized string tables.",
                    detail="This is the unusual case where the human-readable representation can be smaller in the final app.",
                    action="Set STRINGS_FILE_OUTPUT_ENCODING to UTF-8 for Release and remeasure.",
                    severity="medium",
                    confidence="high",
                    savings=None,
                    paths=[record.relative_path for record in binary_plists],
                    category="localizations",
                )
            )
        if comment_records and comment_savings >= 4 * 1024:
            _mark(comment_records, "localization-comments")
            insights.append(
                _insight(
                    "localization-comments",
                    "Strip translator comments from production .strings",
                    f"Block comments occupy about {comment_savings:,} bytes before archive compression.",
                    detail="Translator context belongs in source files but is not needed by NSLocalizedString at runtime.",
                    action="Minify copied .strings files during Release packaging without changing the source localization files.",
                    severity="medium",
                    confidence="high",
                    savings=comment_savings,
                    paths=[record.relative_path for record in comment_records],
                    items=comment_items,
                    category="localizations",
                )
            )

    def _media_insights(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        videos = [
            record
            for record in records
            if record.category == "video"
        ]
        video_total = sum(item.size for item in videos)
        if videos and video_total >= 512 * 1024:
            _mark(videos, "bundled-video")
            insights.append(
                _insight(
                    "bundled-video",
                    f"Review {len(videos)} bundled video file{'s' if len(videos) != 1 else ''}",
                    f"Bundled video contributes {video_total:,} bytes and every user downloads it.",
                    detail="Short onboarding clips are frequently better compressed, streamed, or delivered on demand. Offline requirements may justify bundling.",
                    action="Verify the bitrate, duration, and offline requirement; consider HEVC and on-demand delivery.",
                    severity="medium",
                    confidence="review",
                    savings=None,
                    paths=[record.relative_path for record in videos],
                    items=[
                        {"path": record.relative_path, "size": record.size}
                        for record in sorted(videos, key=lambda item: item.size, reverse=True)
                    ],
                    category="media",
                )
            )
        audio = [
            record
            for record in records
            if record.category == "audio"
        ]
        audio_total = sum(item.size for item in audio)
        if audio and audio_total >= 512 * 1024:
            _mark(audio, "bundled-audio")
            insights.append(
                _insight(
                    "bundled-audio",
                    f"Review {len(audio)} large bundled audio file{'s' if len(audio) != 1 else ''}",
                    f"Bundled audio contributes {audio_total:,} bytes.",
                    detail="Lossless or high-bitrate source audio is easy to copy into an app accidentally.",
                    action="Match codec, channels, and bitrate to the in-app listening context; stream or download long content on demand.",
                    severity="low",
                    confidence="review",
                    savings=None,
                    paths=[record.relative_path for record in audio],
                    category="media",
                )
            )
        complex_vectors: list[Record] = []
        for record in records:
            if record.absolute_path.suffix.lower() != ".svg" or record.size < 100 * 1024:
                continue
            try:
                sample = record.absolute_path.read_text(
                    encoding="utf-8", errors="ignore"
                )
            except OSError:
                continue
            if sample.count("<path") >= 300 or "data:image/" in sample:
                record.metadata["svgPathCount"] = sample.count("<path")
                complex_vectors.append(record)
        if complex_vectors:
            _mark(complex_vectors, "complex-vectors")
            insights.append(
                _insight(
                    "complex-vectors",
                    f"Rasterize {len(complex_vectors)} illustration-like SVG{'s' if len(complex_vectors) != 1 else ''}",
                    "These SVGs are large, path-heavy, or embed raster data and may not benefit from vector storage.",
                    detail="Icons and simple shapes should remain vector. Detailed fixed-size illustrations often compress better as HEIC/WebP-like raster assets.",
                    action="Compare a correctly sized raster export against the SVG and keep the smaller visually equivalent asset.",
                    severity="low",
                    confidence="review",
                    savings=None,
                    paths=[record.relative_path for record in complex_vectors],
                    category="images",
                )
            )

    def _lottie_insights(
        self, records: list[Record], insights: list[dict[str, Any]]
    ) -> None:
        animations = [record for record in records if record.category == "animation"]
        similar = _lottie_similarity_groups(animations)
        if similar:
            affected = [record for group in similar for record in group]
            _mark(affected, "similar-lotties")
            insights.append(
                _insight(
                    "similar-lotties",
                    f"Consolidate {len(similar)} structurally similar Lottie group{'s' if len(similar) != 1 else ''}",
                    "Animations share canvas, timing, layer types, and normalized layer names.",
                    detail="This heuristic intentionally does not call the files duplicates. Similar state animations can sometimes share layers, colors, or one parameterized source.",
                    action="Open each group in the animation editor and consolidate only genuinely shared artwork or timelines.",
                    severity="low",
                    confidence="review",
                    savings=None,
                    paths=[record.relative_path for record in affected],
                    items=[
                        {
                            "paths": [record.relative_path for record in group],
                            "totalSize": sum(record.size for record in group),
                        }
                        for group in similar
                    ],
                    category="animations",
                )
            )
        if len(animations) >= 6 and sum(item.size for item in animations) >= 512 * 1024:
            _mark(animations, "lottie-library")
            insights.append(
                _insight(
                    "lottie-library",
                    f"Audit {len(animations)} bundled Lottie animations",
                    f"JSON animations contribute {sum(item.size for item in animations):,} bytes before filesystem overhead.",
                    detail="Multiple one-off animations can repeat masks, image assets, and nearly identical state transitions.",
                    action="Remove unused states, share external image assets, minify JSON, and consider one layered animation for related variants.",
                    severity="low",
                    confidence="review",
                    savings=None,
                    paths=[record.relative_path for record in animations],
                    category="animations",
                )
            )

    def _category_breakdown(self, records: list[Record]) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, int]] = {}
        for record in records:
            category = grouped.setdefault(
                record.category,
                {
                    "size": 0,
                    "compressedSize": 0,
                    "installSize": 0,
                    "downloadSize": 0,
                    "fileCount": 0,
                },
            )
            category["size"] += record.size
            category["compressedSize"] += record.compressed_size
            category["installSize"] += record.delivered_install_size
            category["downloadSize"] += record.delivered_download_size
            category["fileCount"] += 1
        return [
            {
                "id": category,
                "label": CATEGORY_LABELS.get(category, category.title()),
                **values,
            }
            for category, values in sorted(
                grouped.items(), key=lambda item: item[1]["size"], reverse=True
            )
        ]

    def _file_node(self, record: Record) -> dict[str, Any]:
        return {
            "name": record.name,
            "path": record.relative_path,
            "kind": "file",
            "category": record.category,
            "size": record.size,
            "compressedSize": record.compressed_size,
            "installSize": record.delivered_install_size,
            "downloadSize": record.delivered_download_size,
            "allocatedSize": record.allocated_size,
            "children": record.virtual_children,
            "metadata": record.metadata,
            "duplicateGroup": record.duplicate_group,
            "insights": record.insight_ids,
        }

    def _build_tree(
        self,
        root_name: str,
        records: list[Record],
        component_duplicates: dict[str, str],
    ) -> dict[str, Any]:
        root: dict[str, Any] = {
            "name": root_name,
            "path": "",
            "kind": "directory",
            "category": "other",
            "size": 0,
            "compressedSize": 0,
            "installSize": 0,
            "downloadSize": 0,
            "allocatedSize": 0,
            "children": [],
            "metadata": {},
            "duplicateGroup": None,
            "insights": [],
        }
        directories: dict[str, dict[str, Any]] = {"": root}
        for record in records:
            parts = Path(record.relative_path).parts
            parent_path = ""
            for part in parts[:-1]:
                current_path = f"{parent_path}/{part}".lstrip("/")
                if current_path not in directories:
                    directory = {
                        "name": part,
                        "path": current_path,
                        "kind": "directory",
                        "category": "other",
                        "size": 0,
                        "compressedSize": 0,
                        "installSize": 0,
                        "downloadSize": 0,
                        "allocatedSize": 0,
                        "children": [],
                        "metadata": {
                            "componentDuplicate": bool(
                                component_duplicates.get(current_path)
                            )
                        },
                        "duplicateGroup": component_duplicates.get(current_path),
                        "insights": (
                            ["duplicate-components"]
                            if component_duplicates.get(current_path)
                            else []
                        ),
                    }
                    directories[parent_path]["children"].append(directory)
                    directories[current_path] = directory
                parent_path = current_path
            directories[parent_path]["children"].append(self._file_node(record))

        def summarize(node: dict[str, Any]) -> None:
            children = node.get("children", [])
            if not children or node.get("kind") != "directory":
                return
            for child in children:
                summarize(child)
            node["size"] = sum(int(child.get("size", 0)) for child in children)
            node["compressedSize"] = sum(
                int(child.get("compressedSize", 0)) for child in children
            )
            node["installSize"] = sum(
                int(child.get("installSize", child.get("size", 0)))
                for child in children
            )
            node["downloadSize"] = sum(
                int(
                    child.get(
                        "downloadSize", child.get("compressedSize", 0)
                    )
                )
                for child in children
            )
            node["allocatedSize"] = sum(
                int(child.get("allocatedSize", 0)) for child in children
            )
            category_sizes: dict[str, int] = {}
            insight_ids: set[str] = set(node.get("insights", []))
            duplicate_groups: set[str] = set()
            anonymous_duplicates = 0
            for child in children:
                category = str(child.get("category", "other"))
                category_sizes[category] = category_sizes.get(category, 0) + int(
                    child.get("size", 0)
                )
                insight_ids.update(child.get("insights", []))
                child_metadata = child.get("metadata", {})
                child_groups = {
                    str(group)
                    for group in child_metadata.get("duplicateGroups", [])
                    if group
                }
                if child.get("duplicateGroup"):
                    child_groups.add(str(child["duplicateGroup"]))
                declared_count = int(child_metadata.get("duplicateCount", 0))
                anonymous_duplicates += max(0, declared_count - len(child_groups))
                duplicate_groups.update(child_groups)
            if category_sizes:
                node["category"] = max(category_sizes, key=category_sizes.get)
            node["insights"] = sorted(insight_ids)
            node["metadata"]["duplicateGroups"] = sorted(
                duplicate_groups,
                key=lambda value: (value[:1], len(value), value),
            )
            node["metadata"]["duplicateCount"] = (
                len(duplicate_groups) + anonymous_duplicates
            )
            node["metadata"]["fileCount"] = sum(
                1
                if child.get("kind") == "file"
                else int(child.get("metadata", {}).get("fileCount", 0))
                for child in children
            )
            children.sort(key=lambda child: int(child.get("size", 0)), reverse=True)

        summarize(root)
        return root

    def _inventory(
        self, tree: dict[str, Any], records: list[Record]
    ) -> list[dict[str, Any]]:
        components: list[dict[str, Any]] = []

        def visit(node: dict[str, Any], depth: int) -> None:
            name = str(node.get("name", ""))
            path = str(node.get("path", ""))
            is_component = (
                depth == 1
                or name.lower().endswith((".framework", ".appex", ".bundle", ".app"))
            )
            if is_component and path:
                components.append(
                    {
                        "name": name,
                        "path": path,
                        "kind": (
                            "framework"
                            if name.lower().endswith(".framework")
                            else "extension"
                            if name.lower().endswith(".appex")
                            else "bundle"
                            if name.lower().endswith(".bundle")
                            else "component"
                        ),
                        "category": node.get("category", "other"),
                        "size": int(node.get("size", 0)),
                        "compressedSize": int(node.get("compressedSize", 0)),
                        "installSize": int(
                            node.get("installSize", node.get("size", 0))
                        ),
                        "downloadSize": int(
                            node.get(
                                "downloadSize",
                                node.get("compressedSize", 0),
                            )
                        ),
                        "fileCount": int(
                            node.get("metadata", {}).get("fileCount", 0)
                        ),
                        "insightCount": len(node.get("insights", [])),
                        "duplicateGroup": node.get("duplicateGroup"),
                    }
                )
                if depth > 1:
                    return
            for child in node.get("children", []):
                if child.get("kind") == "directory":
                    visit(child, depth + 1)

        visit(tree, 0)
        components.sort(key=lambda item: item["size"], reverse=True)
        return components
