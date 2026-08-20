"""Host capabilities used by the shared bundle analyzer.

The analyzer itself is intentionally platform-neutral. Native macOS builds use
Apple's command-line tools when they are available, while browser/Pyodide builds
use the same analysis engine with those optional capabilities disabled.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol
import base64
import copy
import hashlib
import json
import re
import shutil
import subprocess


AssetCatalogResult = tuple[list[dict[str, Any]], list[dict[str, Any]]]


class AnalysisPlatform(Protocol):
    """The small host-specific surface required by :class:`BundleAnalyzer`."""

    environment: str
    privacy_message: str

    @property
    def asset_catalogs_available(self) -> bool: ...

    @property
    def image_conversion_available(self) -> bool: ...

    @property
    def symbol_strip_available(self) -> bool: ...

    @property
    def host_diagnostics(self) -> dict[str, Any]: ...

    def icon_png(self, path: Path) -> bytes | None: ...

    def asset_catalog(
        self, path: Path, relative_path: str
    ) -> AssetCatalogResult: ...

    def asset_catalog_diagnostics(self, relative_path: str) -> dict[str, Any]: ...

    def image_properties(self, path: Path) -> dict[str, Any]: ...

    def converted_image_size(
        self,
        path: Path,
        output_dir: Path,
        image_format: str,
        quality: int = 85,
    ) -> int | None: ...

    def alternate_icon_size(self, path: Path, output_dir: Path) -> int | None: ...

    def stripped_size(self, path: Path, output_dir: Path) -> int | None: ...


def _catalog_entries(
    values: object, relative_path: str
) -> AssetCatalogResult:
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
        raw_asset_type = str(value.get("AssetType") or "asset").strip().lower()
        asset_type = "image" if "image" in raw_asset_type else raw_asset_type
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
                    "assetType": asset_type,
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
        rendition_name = str(value.get("RenditionName") or name)
        try:
            scale = int(value.get("Scale", 0) or 0)
        except (TypeError, ValueError):
            scale = 0
        if not scale:
            scale_match = re.search(r"@([1-9][0-9]*)x(?:\.|$)", rendition_name)
            if scale_match:
                scale = int(scale_match.group(1))
        rendition = {
            "entry": entry,
            "name": name,
            "renditionName": rendition_name,
            "path": entry["path"],
            "size": rendition_size,
            "digest": str(digest) if digest else None,
            "assetType": asset_type,
            "scale": scale,
            "physical": True,
        }
        for source_key, target_key in (
            ("PixelWidth", "pixelWidth"),
            ("PixelHeight", "pixelHeight"),
        ):
            raw_dimension = value.get(source_key, 0)
            if isinstance(raw_dimension, (int, float)) and raw_dimension > 0:
                rendition[target_key] = int(raw_dimension)
        renditions.append(rendition)
    return list(grouped.values()), renditions


class NativeAnalysisPlatform:
    """Full macOS implementation backed by Apple's command-line tools."""

    environment = "macos"
    privacy_message = "All analysis ran on this Mac. No bundle bytes were uploaded."

    @property
    def asset_catalogs_available(self) -> bool:
        return bool(shutil.which("assetutil") or Path("/usr/bin/assetutil").exists())

    @property
    def image_conversion_available(self) -> bool:
        return Path("/usr/bin/sips").exists()

    @property
    def symbol_strip_available(self) -> bool:
        return bool(shutil.which("xcrun"))

    @property
    def host_diagnostics(self) -> dict[str, Any]:
        return {}

    def icon_png(self, path: Path) -> bytes | None:
        try:
            payload = path.read_bytes()
            if not self.image_conversion_available:
                return payload if path.suffix.lower() == ".png" else None
            import tempfile

            with tempfile.TemporaryDirectory(prefix="openbundle-icon-") as directory:
                normalized = Path(directory) / "icon.png"
                result = subprocess.run(
                    [
                        "/usr/bin/sips",
                        "-s",
                        "format",
                        "png",
                        str(path),
                        "--out",
                        str(normalized),
                    ],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                if result.returncode == 0 and normalized.is_file():
                    return normalized.read_bytes()
            return payload if path.suffix.lower() == ".png" else None
        except (OSError, subprocess.TimeoutExpired):
            return None

    def asset_catalog(self, path: Path, relative_path: str) -> AssetCatalogResult:
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
            return _catalog_entries(json.loads(result.stdout), relative_path)
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return [], []

    def asset_catalog_diagnostics(self, relative_path: str) -> dict[str, Any]:
        return {}

    def image_properties(self, path: Path) -> dict[str, Any]:
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

    def converted_image_size(
        self,
        path: Path,
        output_dir: Path,
        image_format: str,
        quality: int = 85,
    ) -> int | None:
        output = output_dir / (
            f"{hashlib.sha1(str(path).encode()).hexdigest()}.{image_format}"
        )
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

    def alternate_icon_size(self, path: Path, output_dir: Path) -> int | None:
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

    def stripped_size(self, path: Path, output_dir: Path) -> int | None:
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
            output = output_dir / (
                f"{hashlib.sha1(str(path).encode()).hexdigest()}.stripped"
            )
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


class BrowserAnalysisPlatform:
    """Browser-safe host used by Pyodide; no native processes are available.

    Browser APIs and WASM are asynchronous, while the Python analyzer is kept
    deliberately synchronous.  The web worker therefore prepares catalog and
    image measurements first and injects those immutable results here.  This
    keeps the recommendation engine identical in every host without pretending
    that Apple command-line tools exist in the browser.
    """

    environment = "browser"
    privacy_message = (
        "All analysis ran in this browser. No bundle bytes were uploaded."
    )

    def __init__(
        self,
        *,
        catalog_results: dict[str, dict[str, Any]] | None = None,
        image_results: dict[str, dict[str, Any]] | None = None,
        catalog_analysis_available: bool = False,
        image_analysis_available: bool = False,
        host_diagnostics: dict[str, Any] | None = None,
    ) -> None:
        self._catalog_results = catalog_results or {}
        self._image_results = image_results or {}
        self._catalog_analysis_available = catalog_analysis_available
        self._image_analysis_available = image_analysis_available
        self._host_diagnostics = copy.deepcopy(host_diagnostics or {})

    @property
    def asset_catalogs_available(self) -> bool:
        return self._catalog_analysis_available

    @property
    def image_conversion_available(self) -> bool:
        return self._image_analysis_available

    @property
    def symbol_strip_available(self) -> bool:
        return False

    @property
    def host_diagnostics(self) -> dict[str, Any]:
        return copy.deepcopy(self._host_diagnostics)

    def icon_png(self, path: Path) -> bytes | None:
        # Xcode often writes CgBI PNGs that browsers cannot decode directly.
        # Prefer the normalized 128 px preview produced while the worker was
        # already decoding Assets.car; otherwise show initials rather than a
        # broken image.
        for result in self._catalog_results.values():
            encoded = result.get("iconPNGBase64") if isinstance(result, dict) else None
            if not isinstance(encoded, str) or not encoded:
                continue
            try:
                payload = base64.b64decode(encoded, validate=True)
            except (ValueError, TypeError):
                continue
            if payload.startswith(b"\x89PNG\r\n\x1a\n"):
                return payload
        return None

    def asset_catalog(self, path: Path, relative_path: str) -> AssetCatalogResult:
        result = self._catalog_results.get(relative_path)
        if not result:
            return [], []

        # The analyzer annotates virtual children as insights are discovered,
        # so every run receives a private copy of the worker-produced data.
        children = copy.deepcopy(result.get("children", []))
        renditions = copy.deepcopy(result.get("renditions", []))
        entries = {
            str(entry.get("path")): entry
            for entry in children
            if isinstance(entry, dict) and entry.get("path")
        }
        linked: list[dict[str, Any]] = []
        for rendition in renditions:
            if not isinstance(rendition, dict):
                continue
            entry_path = str(rendition.pop("entryPath", ""))
            entry = entries.get(entry_path)
            if entry is None:
                continue
            rendition["entry"] = entry
            linked.append(rendition)
        return children, linked

    def asset_catalog_diagnostics(self, relative_path: str) -> dict[str, Any]:
        result = self._catalog_results.get(relative_path) or {}
        diagnostics = result.get("diagnostics", {})
        return copy.deepcopy(diagnostics) if isinstance(diagnostics, dict) else {}

    @staticmethod
    def _image_key(path: Path) -> str:
        """Return the stable path used by the worker across ZIP extractions."""

        parts = path.parts
        for index, part in enumerate(parts):
            if part.lower().endswith(".app"):
                return "/".join(parts[index + 1 :])
        return path.name

    def _image_result(self, path: Path) -> dict[str, Any]:
        result = self._image_results.get(self._image_key(path)) or {}
        return result if isinstance(result, dict) else {}

    def image_properties(self, path: Path) -> dict[str, Any]:
        result = self._image_result(path)
        properties = result.get("properties", {})
        return dict(properties) if isinstance(properties, dict) else {}

    def converted_image_size(
        self,
        path: Path,
        output_dir: Path,
        image_format: str,
        quality: int = 85,
    ) -> int | None:
        result = self._image_result(path)
        conversions = result.get("conversions", {})
        if not isinstance(conversions, dict):
            return None
        value = conversions.get(image_format)
        return int(value) if isinstance(value, (int, float)) and value > 0 else None

    def alternate_icon_size(self, path: Path, output_dir: Path) -> int | None:
        return None

    def stripped_size(self, path: Path, output_dir: Path) -> int | None:
        return None
