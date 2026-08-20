"""Resolve .ipa, .app, and .xcarchive inputs without uploading anything."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
import os
import stat
import tempfile
from typing import BinaryIO
import zipfile


# Extraction happens inside the browser's virtual filesystem. These limits leave
# room for the largest fixture currently used by OpenBundle (Tesla: ~996 MB,
# 8,261 entries, 402 MB largest entry) without allowing an archive to expand
# without bound.
MAX_ZIP_ENTRIES = 25_000
MAX_ZIP_ENTRY_BYTES = 512 * 1024 * 1024
MAX_ZIP_TOTAL_BYTES = 1152 * 1024 * 1024
MAX_ZIP_COMPRESSION_RATIO = 300
MAX_ZIP_MEMBER_NAME_LENGTH = 4096
MAX_ZIP_MEMBER_DEPTH = 128
_COPY_CHUNK_BYTES = 1024 * 1024


class ArtifactError(ValueError):
    """Raised when an input is not a supported Apple app artifact."""


@dataclass
class PreparedArtifact:
    input_path: Path
    app_root: Path
    artifact_kind: str
    archive_root: Path | None = None
    zip_sizes: dict[Path, int] = field(default_factory=dict)
    linkmaps: list[Path] = field(default_factory=list)
    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    artifact_name: str = ""
    artifact_size: int | None = None
    artifact_modified_at: float | None = None

    def __post_init__(self) -> None:
        # Cache source facts before browser hosts release a large compressed
        # upload. Analysis only needs the extracted app after preparation.
        if not self.artifact_name:
            self.artifact_name = self.input_path.name
        try:
            source_stat = self.input_path.stat()
        except OSError:
            return
        if self.artifact_modified_at is None:
            self.artifact_modified_at = source_stat.st_mtime
        if self.artifact_size is None and self.input_path.is_file():
            self.artifact_size = source_stat.st_size

    def cleanup(self) -> None:
        if self.temp_dir:
            self.temp_dir.cleanup()

    def __enter__(self) -> "PreparedArtifact":
        return self

    def __exit__(self, *_: object) -> None:
        self.cleanup()


def _candidate_apps(root: Path) -> list[Path]:
    candidates = [
        path
        for path in root.rglob("*.app")
        if path.is_dir() and (path / "Info.plist").is_file()
    ]
    # Nested Watch apps and plug-ins should not become the primary app.
    candidates.sort(key=lambda path: (len(path.relative_to(root).parts), str(path)))
    return candidates


def _linkmaps(archive_root: Path) -> list[Path]:
    candidates: list[Path] = []
    for folder_name in ("Linkmaps", "LinkMaps"):
        folder = archive_root / folder_name
        if folder.is_dir():
            candidates.extend(sorted(folder.rglob("*.txt")))
    return candidates


def _from_app(path: Path) -> PreparedArtifact:
    return PreparedArtifact(
        input_path=path,
        app_root=path,
        artifact_kind="app",
    )


def _from_archive(path: Path) -> PreparedArtifact:
    applications = path / "Products" / "Applications"
    candidates = _candidate_apps(applications) if applications.is_dir() else []
    if not candidates:
        raise ArtifactError(
            f"No .app was found under {path}/Products/Applications."
        )
    return PreparedArtifact(
        input_path=path,
        app_root=candidates[0],
        artifact_kind="xcarchive",
        archive_root=path,
        linkmaps=_linkmaps(path),
    )


def _member_parts(entry: zipfile.ZipInfo) -> tuple[str, ...] | None:
    # ZIP paths conventionally use '/'. Treat backslashes as separators too so
    # Windows-style traversal cannot become a surprising filename on POSIX.
    raw_name = entry.filename.replace("\\", "/")
    if len(raw_name) > MAX_ZIP_MEMBER_NAME_LENGTH:
        raise ArtifactError(
            f"Archive member name exceeds {MAX_ZIP_MEMBER_NAME_LENGTH} characters."
        )

    member = PurePosixPath(raw_name)
    if (
        member.is_absolute()
        or ".." in member.parts
        or not member.parts
        or member.parts[0] == "__MACOSX"
    ):
        return None
    if len(member.parts) > MAX_ZIP_MEMBER_DEPTH:
        raise ArtifactError(
            f"Archive member path exceeds {MAX_ZIP_MEMBER_DEPTH} components."
        )
    return member.parts


def _planned_zip_files(
    archive: zipfile.ZipFile,
) -> list[tuple[zipfile.ZipInfo, tuple[str, ...], int]]:
    entries = archive.infolist()
    if len(entries) > MAX_ZIP_ENTRIES:
        raise ArtifactError(
            f"Archive contains too many entries ({len(entries):,}; "
            f"maximum {MAX_ZIP_ENTRIES:,})."
        )

    total_size = 0
    planned: list[tuple[zipfile.ZipInfo, tuple[str, ...], int]] = []
    for entry in entries:
        parts = _member_parts(entry)
        if parts is None or entry.is_dir():
            continue

        unix_mode = (entry.external_attr >> 16) & 0xFFFF
        if unix_mode and stat.S_ISLNK(unix_mode):
            # Symlinks are metadata, not app payload bytes. Never materialize an
            # archive-provided link that later entries could traverse.
            continue
        if entry.flag_bits & 0x1:
            raise ArtifactError("Encrypted ZIP entries are not supported.")
        if entry.file_size > MAX_ZIP_ENTRY_BYTES:
            raise ArtifactError(
                f"Archive entry exceeds the {MAX_ZIP_ENTRY_BYTES // (1024 * 1024)} MB "
                "per-file limit."
            )
        if entry.file_size:
            ratio = entry.file_size / max(entry.compress_size, 1)
            if ratio > MAX_ZIP_COMPRESSION_RATIO:
                raise ArtifactError(
                    f"Archive entry exceeds the {MAX_ZIP_COMPRESSION_RATIO}:1 "
                    "compression-ratio limit."
                )

        total_size += entry.file_size
        if total_size > MAX_ZIP_TOTAL_BYTES:
            raise ArtifactError(
                f"Archive expands beyond the {MAX_ZIP_TOTAL_BYTES // (1024 * 1024)} MB "
                "unpacked limit."
            )
        planned.append((entry, parts, unix_mode))
    return planned


def _copy_zip_entry(
    source: BinaryIO,
    target: BinaryIO,
    *,
    expected_size: int,
    total_written: int,
) -> int:
    """Copy one member while independently enforcing the advertised limits."""

    copied = 0
    while True:
        chunk = source.read(_COPY_CHUNK_BYTES)
        if not chunk:
            break
        copied += len(chunk)
        if copied > expected_size:
            raise ArtifactError("Archive entry expanded beyond its declared size.")
        if copied > MAX_ZIP_ENTRY_BYTES:
            raise ArtifactError("Archive entry exceeded the per-file limit while reading.")
        if total_written + copied > MAX_ZIP_TOTAL_BYTES:
            raise ArtifactError("Archive exceeded the unpacked limit while reading.")
        target.write(chunk)

    if copied != expected_size:
        raise ArtifactError("Archive entry size does not match its ZIP metadata.")
    return copied


def _safe_extract_zip(path: Path) -> PreparedArtifact:
    if not zipfile.is_zipfile(path):
        raise ArtifactError(f"{path} is not a valid zip/IPA file.")

    temporary = tempfile.TemporaryDirectory(prefix="openbundle-")
    output_root = Path(temporary.name)
    compressed_sizes: dict[Path, int] = {}

    try:
        with zipfile.ZipFile(path) as archive:
            planned_files = _planned_zip_files(archive)
            total_written = 0
            for entry, parts, unix_mode in planned_files:
                destination = output_root.joinpath(*parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, destination.open("wb") as target:
                    total_written += _copy_zip_entry(
                        source,
                        target,
                        expected_size=entry.file_size,
                        total_written=total_written,
                    )
                if unix_mode:
                    try:
                        os.chmod(destination, unix_mode & 0o777)
                    except OSError:
                        pass
                compressed_sizes[destination] = int(entry.compress_size)

        archive_candidates = sorted(output_root.rglob("*.xcarchive"))
        for archive_root in archive_candidates:
            if archive_root.is_dir():
                prepared = _from_archive(archive_root)
                prepared.input_path = path
                prepared.artifact_kind = "zipped-xcarchive"
                prepared.temp_dir = temporary
                prepared.zip_sizes = compressed_sizes
                prepared.artifact_name = path.name
                source_stat = path.stat()
                prepared.artifact_size = source_stat.st_size
                prepared.artifact_modified_at = source_stat.st_mtime
                return prepared

        payload = output_root / "Payload"
        search_root = payload if payload.is_dir() else output_root
        candidates = _candidate_apps(search_root)
        if not candidates:
            raise ArtifactError("No .app bundle was found inside the IPA/zip.")
        return PreparedArtifact(
            input_path=path,
            app_root=candidates[0],
            artifact_kind="ipa" if path.suffix.lower() == ".ipa" else "zip",
            archive_root=None,
            zip_sizes=compressed_sizes,
            temp_dir=temporary,
        )
    except ArtifactError:
        temporary.cleanup()
        raise
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError) as error:
        temporary.cleanup()
        raise ArtifactError(f"Could not extract the archive: {error}") from error
    except Exception:
        temporary.cleanup()
        raise


def prepare_artifact(input_path: str | Path) -> PreparedArtifact:
    path = Path(input_path).expanduser().resolve()
    if not path.exists():
        raise ArtifactError(f"Input does not exist: {path}")
    if path.is_dir() and path.suffix.lower() == ".app":
        return _from_app(path)
    if path.is_dir() and path.suffix.lower() == ".xcarchive":
        return _from_archive(path)
    if path.is_file() and path.suffix.lower() in {".ipa", ".zip"}:
        return _safe_extract_zip(path)
    raise ArtifactError(
        "Expected an .ipa, .app, .xcarchive, or a zip containing one."
    )
