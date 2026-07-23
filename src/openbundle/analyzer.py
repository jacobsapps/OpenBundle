"""Local iOS bundle analysis and recommendation engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
import base64
import hashlib
import json
import math
import os
import plistlib
import re
import shutil
import subprocess
import tempfile
import zlib

from .artifact import PreparedArtifact, prepare_artifact
from .linkmap import parse_linkmap
from .macho import parse_macho


Progress = Callable[[str], None]

IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".heic", ".heif", ".gif", ".webp"}
VECTOR_SUFFIXES = {".svg", ".pdf"}
VIDEO_SUFFIXES = {".mp4", ".mov", ".m4v", ".webm"}
AUDIO_SUFFIXES = {".mp3", ".m4a", ".aac", ".wav", ".caf", ".flac", ".ogg"}
FONT_SUFFIXES = {".ttf", ".otf", ".ttc", ".woff", ".woff2"}
COREML_SUFFIXES = {".mlmodel", ".mlmodelc", ".mlpackage"}
INTERFACE_SUFFIXES = {".nib", ".storyboardc"}
LOCALIZATION_SUFFIXES = {".strings", ".stringsdict", ".xcstrings"}

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

    @property
    def name(self) -> str:
        return Path(self.relative_path).name


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


def _app_icon_data_url(
    app_root: Path, info_plist: dict[str, Any]
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
    if not usable:
        return None
    icon = max(usable, key=lambda path: path.stat().st_size)
    try:
        payload = icon.read_bytes()
        if Path("/usr/bin/sips").exists():
            with tempfile.TemporaryDirectory(prefix="openbundle-icon-") as directory:
                normalized = Path(directory) / "icon.png"
                result = subprocess.run(
                    [
                        "/usr/bin/sips",
                        "-s",
                        "format",
                        "png",
                        str(icon),
                        "--out",
                        str(normalized),
                    ],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                if result.returncode == 0 and normalized.is_file():
                    payload = normalized.read_bytes()
        encoded = base64.b64encode(payload).decode("ascii")
    except (OSError, subprocess.TimeoutExpired):
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


def _assetutil_children(path: Path, relative_path: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    assetutil = shutil.which("assetutil") or "/usr/bin/assetutil"
    if not Path(assetutil).exists():
        return [], []
    try:
        result = subprocess.run(
            [assetutil, "--info", str(path)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if result.returncode != 0:
            return [], []
        values = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return [], []
    if not isinstance(values, list):
        return [], []

    grouped: dict[str, dict[str, Any]] = {}
    renditions: list[dict[str, Any]] = []
    for index, value in enumerate(values):
        if not isinstance(value, dict) or "AssetType" not in value:
            continue
        size = value.get("SizeOnDisk", 0)
        if not isinstance(size, (int, float)) or size <= 0:
            continue
        name = str(
            value.get("Name")
            or value.get("RenditionName")
            or f"{value.get('AssetType', 'Asset')} {index + 1}"
        )
        entry = grouped.setdefault(
            name,
            {
                "name": name,
                "path": f"{relative_path}::{name}",
                "kind": "asset",
                "category": "asset_catalog",
                "size": 0,
                "compressedSize": 0,
                "allocatedSize": 0,
                "children": [],
                "metadata": {
                    "assetType": str(value.get("AssetType", "Asset")),
                    "renditionCount": 0,
                },
                "insights": [],
            },
        )
        rendition_size = int(size)
        entry["size"] += rendition_size
        entry["compressedSize"] += rendition_size
        entry["allocatedSize"] += rendition_size
        entry["metadata"]["renditionCount"] += 1
        digest = value.get("SHA1Digest")
        rendition = {
            "entry": entry,
            "name": name,
            "path": entry["path"],
            "size": rendition_size,
            "digest": str(digest) if digest else None,
            "assetType": str(value.get("AssetType", "Asset")),
        }
        renditions.append(rendition)
    return list(grouped.values()), renditions


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
                    "name": str(section.get("name") or "Unnamed section"),
                    "path": f"{prefix}::{segment.get('name')}::{section.get('name')}",
                    "kind": "section",
                    "category": "binary_section",
                    "size": int(section.get("size", 0)),
                    "compressedSize": int(section.get("size", 0)),
                    "allocatedSize": int(section.get("size", 0)),
                    "children": [],
                    "metadata": {
                        "segment": segment.get("name"),
                        "virtualSize": section.get("virtual_size", 0),
                    },
                    "insights": [],
                }
                for section in segment.get("sections", [])
                if int(section.get("size", 0)) > 0
            ]
            section_nodes = _normalize_virtual_sizes(
                section_nodes, segment_size, "Segment headers & padding"
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


def _sips_properties(path: Path) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [
                "/usr/bin/sips",
                "-g",
                "pixelWidth",
                "-g",
                "pixelHeight",
                "-g",
                "hasAlpha",
                str(path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if result.returncode:
        return {}
    properties: dict[str, Any] = {}
    for line in result.stdout.splitlines():
        if ":" not in line:
            continue
        key, raw_value = (part.strip() for part in line.split(":", 1))
        if key in {"pixelWidth", "pixelHeight"}:
            try:
                properties[key] = int(raw_value)
            except ValueError:
                pass
        elif key == "hasAlpha":
            properties[key] = raw_value.lower() == "yes"
    return properties


def _converted_image_size(
    path: Path, output_dir: Path, image_format: str, quality: int = 85
) -> int | None:
    output = output_dir / f"{hashlib.sha1(str(path).encode()).hexdigest()}.{image_format}"
    try:
        result = subprocess.run(
            [
                "/usr/bin/sips",
                "-s",
                "format",
                image_format,
                "-s",
                "formatOptions",
                str(quality),
                str(path),
                "--out",
                str(output),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if result.returncode == 0 and output.is_file():
            return output.stat().st_size
    except (OSError, subprocess.TimeoutExpired):
        return None
    return None


def _alternate_icon_size(path: Path, output_dir: Path) -> int | None:
    digest = hashlib.sha1(str(path).encode()).hexdigest()
    small = output_dir / f"{digest}-180.png"
    restored = output_dir / f"{digest}-1024.png"
    commands = [
        [
            "/usr/bin/sips",
            "-s",
            "format",
            "png",
            "-z",
            "180",
            "180",
            str(path),
            "--out",
            str(small),
        ],
        [
            "/usr/bin/sips",
            "-s",
            "format",
            "png",
            "-z",
            "1024",
            "1024",
            str(small),
            "--out",
            str(restored),
        ],
    ]
    try:
        for command in commands:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if result.returncode:
                return None
        return restored.stat().st_size if restored.is_file() else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _strip_size(path: Path, output_dir: Path) -> int | None:
    try:
        finder = subprocess.run(
            ["xcrun", "--find", "strip"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if finder.returncode:
            return None
        strip_tool = finder.stdout.strip()
        output = output_dir / f"{hashlib.sha1(str(path).encode()).hexdigest()}.stripped"
        result = subprocess.run(
            [strip_tool, "-rSTx", str(path), "-o", str(output)],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if result.returncode == 0 and output.is_file():
            return output.stat().st_size
    except (OSError, subprocess.TimeoutExpired):
        return None
    return None


def _is_duplicate_candidate(record: Record) -> bool:
    lower = record.relative_path.lower()
    if record.size < 1024 or record.category in {"signature", "metadata"}:
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
        items.append(
            {
                "group": group_id,
                "name": Path(paths[0]).name,
                "kind": kind,
                "size": size,
                "copies": len(paths),
                "paths": paths,
            }
        )
    return group_map, items


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
) -> dict[str, Any]:
    return {
        "id": insight_id,
        "title": title,
        "summary": summary,
        "detail": detail,
        "action": action,
        "severity": severity,
        "confidence": confidence,
        "savings": savings,
        "paths": paths or [],
        "items": items or [],
        "category": category,
    }


def _mark(records: Iterable[Record], insight_id: str) -> None:
    for record in records:
        if insight_id not in record.insight_ids:
            record.insight_ids.append(insight_id)


class BundleAnalyzer:
    """Analyze one iOS artifact and return report-ready JSON data."""

    def __init__(self, progress: Progress | None = None) -> None:
        self.progress = progress

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
                macho = parse_macho(path)
                digest, compressed = _stream_facts(
                    path, prepared.zip_sizes.get(path)
                )
            except OSError:
                continue
            category = _classify(relative, macho)
            metadata: dict[str, Any] = {"extension": path.suffix.lower()}
            lottie = _looks_like_lottie(path, size)
            if lottie:
                category = "animation"
                metadata.update(lottie)
            if macho:
                architectures = macho.get("architectures", [])
                first = architectures[0] if architectures else {}
                page_padding = 0
                for architecture in architectures:
                    for segment in architecture.get("segments", []):
                        segment_size = int(segment.get("size", 0))
                        if segment_size:
                            page_padding += _ceil(segment_size, 16 * 1024) - segment_size
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
                        "pagePaddingEstimate": page_padding,
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

    def analyze(self, input_path: str | Path) -> dict[str, Any]:
        _progress(self.progress, "Preparing artifact…")
        with prepare_artifact(input_path) as prepared:
            info_plist = _read_plist(prepared.app_root / "Info.plist")
            records = self._scan(prepared)
            _progress(self.progress, "Expanding asset catalogs and Mach-O binaries…")

            asset_renditions: list[dict[str, Any]] = []
            expanded_catalogs = 0
            for record in records:
                if record.category != "asset_catalog":
                    continue
                children, renditions = _assetutil_children(
                    record.absolute_path, record.relative_path
                )
                if children:
                    expanded_catalogs += 1
                    record.metadata["assetCount"] = len(children)
                    record.metadata["renditionCount"] = len(renditions)
                    record.virtual_children = _normalize_virtual_sizes(
                        children, record.size, "Catalog metadata & packing"
                    )
                    for child in record.virtual_children:
                        if not child.get("path"):
                            child["path"] = f"{record.relative_path}::catalog-overhead"
                    asset_renditions.extend(renditions)

            linkmaps_used = 0
            for record in records:
                if not record.macho:
                    continue
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
            tree = self._build_tree(
                prepared.app_root.name, records, component_duplicates
            )
            categories = self._category_breakdown(records)
            inventory = self._inventory(tree, records)
            largest_files = [
                {
                    "name": record.name,
                    "path": record.relative_path,
                    "size": record.size,
                    "compressedSize": record.compressed_size,
                    "category": record.category,
                    "insights": record.insight_ids,
                }
                for record in sorted(records, key=lambda item: item.size, reverse=True)[:150]
            ]

            total_size = sum(record.size for record in records)
            compressed_size = sum(record.compressed_size for record in records)
            allocated_size = sum(record.allocated_size for record in records)
            opportunity = min(
                total_size,
                sum(
                    int(insight["savings"])
                    for insight in insights
                    if isinstance(insight.get("savings"), int)
                    and int(insight["savings"]) > 0
                ),
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
                "iconDataURL": _app_icon_data_url(prepared.app_root, info_plist),
                "artifactName": prepared.input_path.name,
                "artifactKind": prepared.artifact_kind,
                "modifiedAt": datetime.fromtimestamp(
                    prepared.input_path.stat().st_mtime, timezone.utc
                ).isoformat(),
            }
            metrics = {
                "logicalSize": total_size,
                "compressedSize": compressed_size,
                "allocatedSize": allocated_size,
                "artifactSize": (
                    prepared.input_path.stat().st_size
                    if prepared.input_path.is_file()
                    else None
                ),
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
                "opportunityBytes": opportunity,
                "insightCount": len(insights),
                "duplicateGroupCount": (
                    len(
                        next(
                            (
                                insight.get("items", [])
                                for insight in insights
                                if insight.get("id") == "duplicates"
                            ),
                            [],
                        )
                    )
                    + len(component_duplicate_items)
                ),
            }

            return {
                "schemaVersion": 1,
                "generatedAt": datetime.now(timezone.utc).isoformat(),
                "generator": {"name": "OpenBundle", "version": "0.1.0"},
                "app": app,
                "metrics": metrics,
                "categories": categories,
                "tree": tree,
                "insights": insights,
                "inventory": inventory,
                "largestFiles": largest_files,
                "capabilities": {
                    "assetutilAvailable": bool(
                        shutil.which("assetutil") or Path("/usr/bin/assetutil").exists()
                    ),
                    "assetCatalogsExpanded": expanded_catalogs,
                    "linkmapsFound": len(prepared.linkmaps),
                    "linkmapsUsed": linkmaps_used,
                    "symbolStripSimulation": bool(shutil.which("xcrun")),
                    "imageConversionSimulation": Path("/usr/bin/sips").exists(),
                    "privacy": "All analysis ran on this Mac. No bundle bytes were uploaded.",
                },
                "limitations": [
                    "Download size is the IPA entry total when an IPA is supplied; otherwise it is a local deflate estimate. App Store thinning can differ.",
                    "Image savings are conversion estimates and need visual quality review.",
                    "Static dead-code reachability cannot be proven from a shipped binary alone. Use link maps plus runtime coverage for removal decisions.",
                    "Recommendations marked Review are heuristics, not proof that a dependency or resource is unused.",
                ],
                "research": [
                    {
                        "title": "Emerge X-Ray",
                        "url": "https://docs.emergetools.com/docs/treemap",
                    },
                    {
                        "title": "Emerge size insights",
                        "url": "https://docs.emergetools.com/docs/size-insights",
                    },
                    {
                        "title": "Remove duplicates",
                        "url": "https://docs.emergetools.com/docs/remove-duplicates",
                    },
                    {
                        "title": "Optimize images",
                        "url": "https://docs.emergetools.com/docs/optimize-images",
                    },
                    {
                        "title": "Apple basic app-size optimization",
                        "url": "https://developer.apple.com/documentation/xcode/doing-basic-optimization-to-reduce-your-app-s-size",
                    },
                    {
                        "title": "Apple build settings reference",
                        "url": "https://developer.apple.com/documentation/xcode/build-settings-reference",
                    },
                ],
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
        self._image_insights(records, minimum_os, insights)
        self._alternate_icon_insight(records, info_plist, insights)
        self._coverage_instrumentation_insight(records, insights)
        self._bitcode_insight(records, insights)
        self._symbol_insight(records, insights)
        self._architecture_insight(records, insights)
        self._framework_insights(records, insights)
        self._embedded_target_insight(records, insights)
        self._linkmap_insight(records, insights)
        self._swift_reflection_insight(records, insights)
        self._embedded_string_data_insight(records, insights)
        self._localization_insights(records, insights)
        self._media_insights(records, insights)
        self._lottie_insights(records, insights)
        severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        insights.sort(
            key=lambda item: (
                severity_order.get(str(item.get("severity")), 9),
                -int(item.get("savings") or 0),
                str(item.get("title")),
            )
        )
        return insights

    def _duplicate_insight(
        self,
        records: list[Record],
        asset_renditions: list[dict[str, Any]],
        insights: list[dict[str, Any]],
    ) -> None:
        record_by_path = {record.relative_path: record for record in records}
        groups: dict[tuple[str, int], list[Record]] = {}
        for record in records:
            if _is_duplicate_candidate(record):
                groups.setdefault((record.sha256, record.size), []).append(record)
        duplicate_groups = [
            group for group in groups.values() if len(group) > 1
        ]
        items: list[dict[str, Any]] = []
        savings = 0
        paths: list[str] = []
        group_index = 1
        for group in sorted(
            duplicate_groups,
            key=lambda values: values[0].size * (len(values) - 1),
            reverse=True,
        ):
            group_savings = group[0].size * (len(group) - 1)
            if group_savings < 1024:
                continue
            group_id = f"D{group_index}"
            group_index += 1
            for record in group:
                record.duplicate_group = group_id
            _mark(group, "duplicates")
            group_paths = [record.relative_path for record in group]
            items.append(
                {
                    "group": group_id,
                    "name": group[0].name,
                    "size": group[0].size,
                    "savings": group_savings,
                    "paths": group_paths,
                    "kind": "file",
                }
            )
            paths.extend(group_paths)
            savings += group_savings

        rendition_groups: dict[tuple[str, int], list[dict[str, Any]]] = {}
        for rendition in asset_renditions:
            if rendition.get("digest") and int(rendition.get("size", 0)) >= 1024:
                key = (str(rendition["digest"]), int(rendition["size"]))
                rendition_groups.setdefault(key, []).append(rendition)
        for group in sorted(
            (values for values in rendition_groups.values() if len(values) > 1),
            key=lambda values: int(values[0]["size"]) * (len(values) - 1),
            reverse=True,
        ):
            group_savings = int(group[0]["size"]) * (len(group) - 1)
            group_id = f"D{group_index}"
            group_index += 1
            group_paths = sorted({str(item["path"]) for item in group})
            for rendition in group:
                entry = rendition["entry"]
                entry["duplicateGroup"] = group_id
                if "duplicates" not in entry["insights"]:
                    entry["insights"].append("duplicates")
                catalog_path = str(rendition["path"]).split("::", 1)[0]
                catalog = record_by_path.get(catalog_path)
                if catalog:
                    _mark([catalog], "duplicates")
                    catalog.metadata["duplicateCount"] = int(
                        catalog.metadata.get("duplicateCount", 0)
                    ) + 1
            items.append(
                {
                    "group": group_id,
                    "name": str(group[0]["name"]),
                    "size": int(group[0]["size"]),
                    "savings": group_savings,
                    "paths": group_paths,
                    "kind": "asset rendition",
                }
            )
            paths.extend(group_paths)
            savings += group_savings

        if items:
            insights.append(
                _insight(
                    "duplicates",
                    f"Remove {len(items)} duplicate group{'s' if len(items) != 1 else ''}",
                    f"Keeping one copy from each group could save about {savings:,} bytes.",
                    detail=(
                        "Files are matched by SHA-256 content. Asset catalog renditions "
                        "use the digest and on-disk size reported by Apple’s assetutil."
                    ),
                    action=(
                        "Confirm bundle lookup behavior, keep one canonical resource, "
                        "and update callers that currently load from another framework bundle."
                    ),
                    severity="high",
                    confidence="high",
                    savings=savings,
                    paths=paths[:100],
                    items=items[:100],
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
                savings=overhead,
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
        loose_scaled: dict[str, list[Record]] = {}
        for record in records:
            if record.category != "image" or ".car::" in record.relative_path:
                continue
            match = re.match(
                r"(?i)(.*?)(?:@([123])x)?(?:~(?:iphone|ipad))?(\.[^.]+)$",
                record.relative_path,
            )
            if match and match.group(2):
                key = f"{match.group(1)}{match.group(3)}"
                loose_scaled.setdefault(key, []).append(record)
        scale_groups = [group for group in loose_scaled.values() if len(group) > 1]
        if scale_groups:
            candidates = [record for group in scale_groups for record in group]
            savings = sum(
                sum(item.size for item in group) - max(item.size for item in group)
                for group in scale_groups
            )
            _mark(candidates, "asset-catalog-scales")
            insights.append(
                _insight(
                    "asset-catalog-scales",
                    f"Move {len(scale_groups)} loose image set{'s' if len(scale_groups) != 1 else ''} into asset catalogs",
                    "Loose @2x/@3x variants are shipped together instead of benefiting from App Store thinning.",
                    detail=(
                        "The estimate assumes a device needs one scale from each set; actual "
                        "App Store delivery depends on the asset and target device."
                    ),
                    action="Create image sets in an .xcassets catalog and remove the loose copies from bundle resources.",
                    severity="medium",
                    confidence="medium",
                    savings=savings,
                    paths=[record.relative_path for record in candidates],
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
        if not candidates or not Path("/usr/bin/sips").exists():
            return
        _progress(self.progress, "Simulating image compression (largest images first)…")
        optimization_items: list[dict[str, Any]] = []
        total_savings = 0
        high_resolution: list[Record] = []
        with tempfile.TemporaryDirectory(prefix="openbundle-images-") as directory:
            output = Path(directory)
            for record in candidates[:80]:
                properties = _sips_properties(record.absolute_path)
                record.metadata.update(properties)
                width = int(properties.get("pixelWidth", 0))
                height = int(properties.get("pixelHeight", 0))
                if width >= 3000 or height >= 3000:
                    high_resolution.append(record)

                attempts: list[tuple[str, int]] = []
                if _safe_version_at_least(minimum_os, 12):
                    heic_size = _converted_image_size(
                        record.absolute_path, output, "heic", 85
                    )
                    if heic_size:
                        attempts.append(("HEIC quality 85", heic_size))
                if (
                    not bool(properties.get("hasAlpha"))
                    and record.absolute_path.suffix.lower() in {".png", ".jpg", ".jpeg"}
                ):
                    jpeg_size = _converted_image_size(
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
                record.metadata["optimizationMethod"] = method
                optimization_items.append(
                    {
                        "path": record.relative_path,
                        "size": record.size,
                        "optimizedSize": optimized_size,
                        "savings": saving,
                        "method": method,
                        "dimensions": (
                            f"{width}×{height}" if width and height else "Unknown"
                        ),
                    }
                )
                total_savings += saving
            optimized_records = [
                record
                for record in candidates
                if "optimizedSizeEstimate" in record.metadata
            ]
            if optimized_records:
                _mark(optimized_records, "optimize-images")
                insights.append(
                    _insight(
                        "optimize-images",
                        f"Optimize {len(optimized_records)} large image{'s' if len(optimized_records) != 1 else ''}",
                        f"Local quality-85 conversions estimate about {total_savings:,} bytes of savings.",
                        detail=(
                            "This mirrors Emerge’s 4 KB threshold and quality-85 starting "
                            "point. Conversion can change color, transparency, or fine detail."
                        ),
                        action="Review each converted image visually, then replace only assets that meet your quality bar.",
                        severity="high" if total_savings >= 1024 * 1024 else "medium",
                        confidence="medium",
                        savings=total_savings,
                        paths=[record.relative_path for record in optimized_records],
                        items=optimization_items,
                        category="images",
                    )
                )

        if high_resolution:
            _mark(high_resolution, "oversized-images")
            insights.append(
                _insight(
                    "oversized-images",
                    f"Review {len(high_resolution)} very high-resolution image{'s' if len(high_resolution) != 1 else ''}",
                    "At least one dimension is 3,000 px or larger, which is often excessive for an in-app header.",
                    detail="Pixel dimensions are measured locally with sips; required size depends on the maximum rendered point size and display scale.",
                    action="Resize photographic assets to the largest rendered size × the maximum supported scale before compression.",
                    severity="medium",
                    confidence="review",
                    savings=None,
                    paths=[record.relative_path for record in high_resolution],
                    category="images",
                )
            )

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
        if not icon_names or not Path("/usr/bin/sips").exists():
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
                properties = _sips_properties(record.absolute_path)
                record.metadata.update(properties)
                if (
                    int(properties.get("pixelWidth", 0)) != 1024
                    or int(properties.get("pixelHeight", 0)) != 1024
                ):
                    continue
                optimized_size = _alternate_icon_size(record.absolute_path, output)
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
            and not bool(record.metadata.get("encrypted"))
            and int(record.metadata.get("symbolTableBytes", 0)) >= 16 * 1024
        ]
        binaries.sort(key=lambda record: record.size, reverse=True)
        if not binaries or not shutil.which("xcrun"):
            return
        _progress(self.progress, "Simulating production symbol stripping…")
        items: list[dict[str, Any]] = []
        saving_total = 0
        stripped_records: list[Record] = []
        with tempfile.TemporaryDirectory(prefix="openbundle-strip-") as directory:
            output = Path(directory)
            for record in binaries[:50]:
                stripped_size = _strip_size(record.absolute_path, output)
                if stripped_size is None or stripped_size >= record.size:
                    continue
                saving = record.size - stripped_size
                if saving < 16 * 1024:
                    continue
                record.metadata["strippedSizeEstimate"] = stripped_size
                items.append(
                    {
                        "path": record.relative_path,
                        "size": record.size,
                        "strippedSize": stripped_size,
                        "savings": saving,
                    }
                )
                saving_total += saving
                stripped_records.append(record)
        if stripped_records:
            _mark(stripped_records, "strip-symbols")
            insights.append(
                _insight(
                    "strip-symbols",
                    f"Strip production symbols from {len(stripped_records)} binar{'ies' if len(stripped_records) != 1 else 'y'}",
                    f"A non-destructive local strip simulation saved about {saving_total:,} bytes.",
                    detail=(
                        "Swift and local/debug symbols can remain in production binaries. "
                        "Stripping must happen only after dSYMs are produced and uploaded to "
                        "your crash reporter, or crash symbolication will suffer."
                    ),
                    action="For Release only, validate STRIP settings or add a final strip -rSTx phase ordered after dSYM generation.",
                    severity="high",
                    confidence="high",
                    savings=saving_total,
                    paths=[record.relative_path for record in stripped_records],
                    items=items,
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
        dynamic: list[Record] = []
        for record in records:
            if (
                record.macho
                and _framework_name(record.relative_path)
                and any(
                    arch.get("file_type") == "dynamic-library"
                    for arch in record.macho.get("architectures", [])
                )
            ):
                dynamic.append(record)
        small = [record for record in dynamic if record.size < 1024 * 1024]
        if len(dynamic) >= 5 or len(small) >= 3:
            page_padding = sum(
                int(record.metadata.get("pagePaddingEstimate", 0)) for record in dynamic
            )
            _mark(dynamic, "dynamic-frameworks")
            insights.append(
                _insight(
                    "dynamic-frameworks",
                    f"Review {len(dynamic)} embedded dynamic frameworks",
                    f"{len(small)} are below 1 MB; each dynamic image adds load commands, signing, and page-alignment overhead.",
                    detail=(
                        "Static linking can include only referenced object code and reduce "
                        "per-framework overhead, but it can also duplicate code across app "
                        "extensions. The page-padding number is only a segment-alignment estimate."
                    ),
                    action="Prefer static products for small/internal modules where extension sharing and vendor constraints permit; benchmark the resulting archive.",
                    severity="medium",
                    confidence="review",
                    savings=page_padding or None,
                    paths=[record.relative_path for record in dynamic],
                    items=[
                        {
                            "name": _framework_name(record.relative_path),
                            "path": record.relative_path,
                            "size": record.size,
                            "pagePaddingEstimate": record.metadata.get(
                                "pagePaddingEstimate", 0
                            ),
                        }
                        for record in sorted(dynamic, key=lambda item: item.size)
                    ],
                    category="frameworks",
                )
            )

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
            saving = sum(record.size for record in debug)
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
                    savings=saving,
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
                record.category, {"size": 0, "compressedSize": 0, "fileCount": 0}
            )
            category["size"] += record.size
            category["compressedSize"] += record.compressed_size
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
            node["allocatedSize"] = sum(
                int(child.get("allocatedSize", 0)) for child in children
            )
            category_sizes: dict[str, int] = {}
            insight_ids: set[str] = set(node.get("insights", []))
            duplicates = 0
            for child in children:
                category = str(child.get("category", "other"))
                category_sizes[category] = category_sizes.get(category, 0) + int(
                    child.get("size", 0)
                )
                insight_ids.update(child.get("insights", []))
                if child.get("duplicateGroup"):
                    duplicates += 1
                duplicates += int(child.get("metadata", {}).get("duplicateCount", 0))
            if category_sizes:
                node["category"] = max(category_sizes, key=category_sizes.get)
            node["insights"] = sorted(insight_ids)
            node["metadata"]["duplicateCount"] = duplicates
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
