"""Resolve .ipa, .app, and .xcarchive inputs without uploading anything."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
import os
import shutil
import stat
import tempfile
import zipfile


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


def _safe_extract_zip(path: Path) -> PreparedArtifact:
    if not zipfile.is_zipfile(path):
        raise ArtifactError(f"{path} is not a valid zip/IPA file.")

    temporary = tempfile.TemporaryDirectory(prefix="openbundle-")
    output_root = Path(temporary.name)
    compressed_sizes: dict[Path, int] = {}

    try:
        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                member = PurePosixPath(entry.filename)
                if (
                    member.is_absolute()
                    or ".." in member.parts
                    or not member.parts
                    or member.parts[0] == "__MACOSX"
                ):
                    continue
                destination = output_root.joinpath(*member.parts)
                if entry.is_dir():
                    destination.mkdir(parents=True, exist_ok=True)
                    continue

                unix_mode = (entry.external_attr >> 16) & 0xFFFF
                if unix_mode and stat.S_ISLNK(unix_mode):
                    # A symlink is metadata, not app payload bytes. Avoid following
                    # potentially hostile links supplied by an arbitrary archive.
                    continue

                destination.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(entry) as source, destination.open("wb") as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
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
