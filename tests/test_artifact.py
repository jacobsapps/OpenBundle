from __future__ import annotations

from io import BytesIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from openbundle.artifact import ArtifactError, _copy_zip_entry, prepare_artifact
from tests.helpers import make_app


class ArtifactTests(unittest.TestCase):
    def test_accepts_app_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = make_app(Path(directory))
            with prepare_artifact(app) as prepared:
                self.assertEqual(prepared.app_root, app.resolve())
                self.assertEqual(prepared.artifact_kind, "app")

    def test_extracts_ipa_and_ignores_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = make_app(root / "source")
            ipa = root / "Test.ipa"
            with zipfile.ZipFile(ipa, "w", zipfile.ZIP_DEFLATED) as archive:
                for path in app.rglob("*"):
                    if path.is_file():
                        archive.write(
                            path,
                            Path("Payload") / app.name / path.relative_to(app),
                        )
                archive.writestr("../../outside.txt", "no")
            with prepare_artifact(ipa) as prepared:
                self.assertEqual(prepared.artifact_kind, "ipa")
                self.assertTrue((prepared.app_root / "Info.plist").is_file())
                self.assertFalse((Path(prepared.temp_dir.name).parent / "outside.txt").exists())

    def test_ignores_windows_style_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = make_app(root / "source")
            ipa = root / "Test.ipa"
            with zipfile.ZipFile(ipa, "w", zipfile.ZIP_DEFLATED) as archive:
                for path in app.rglob("*"):
                    if path.is_file():
                        archive.write(
                            path,
                            Path("Payload") / app.name / path.relative_to(app),
                        )
                archive.writestr(r"..\..\outside.txt", "no")
            with prepare_artifact(ipa) as prepared:
                self.assertTrue((prepared.app_root / "Info.plist").is_file())
                self.assertFalse((Path(prepared.temp_dir.name).parent / "outside.txt").exists())

    def test_rejects_too_many_zip_entries_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ipa = Path(directory) / "Many.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("one", "1")
                archive.writestr("two", "2")
            with patch("openbundle.artifact.MAX_ZIP_ENTRIES", 1):
                with patch.object(
                    zipfile.ZipFile,
                    "open",
                    side_effect=AssertionError("payload member was opened"),
                ):
                    with self.assertRaisesRegex(ArtifactError, "too many entries"):
                        prepare_artifact(ipa)

    def test_rejects_entry_over_the_uncompressed_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ipa = Path(directory) / "Large.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Test.app/large", b"12345")
            with patch("openbundle.artifact.MAX_ZIP_ENTRY_BYTES", 4):
                with self.assertRaisesRegex(ArtifactError, "per-file limit"):
                    prepare_artifact(ipa)

    def test_rejects_archive_over_the_total_uncompressed_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ipa = Path(directory) / "Large.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Test.app/one", b"123")
                archive.writestr("Payload/Test.app/two", b"456")
            with patch("openbundle.artifact.MAX_ZIP_TOTAL_BYTES", 5):
                with self.assertRaisesRegex(ArtifactError, "unpacked limit"):
                    prepare_artifact(ipa)

    def test_rejects_excessive_compression_ratio(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ipa = Path(directory) / "Bomb.ipa"
            with zipfile.ZipFile(ipa, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("Payload/Test.app/zeros", b"\0" * (1024 * 1024))
            with self.assertRaisesRegex(ArtifactError, "compression-ratio limit"):
                prepare_artifact(ipa)

    def test_stream_copy_rejects_data_beyond_declared_size(self) -> None:
        target = BytesIO()
        with self.assertRaisesRegex(ArtifactError, "declared size"):
            _copy_zip_entry(
                BytesIO(b"12345"),
                target,
                expected_size=4,
                total_written=0,
            )
        self.assertEqual(target.getvalue(), b"")

    def test_rejects_unknown_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.txt"
            path.write_text("not an app")
            with self.assertRaises(ArtifactError):
                prepare_artifact(path)

    def test_caches_archive_facts_before_a_browser_releases_the_upload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = make_app(root / "source")
            ipa = root / "Cached.ipa"
            with zipfile.ZipFile(ipa, "w", zipfile.ZIP_DEFLATED) as archive:
                for path in app.rglob("*"):
                    if path.is_file():
                        archive.write(
                            path,
                            Path("Payload") / app.name / path.relative_to(app),
                        )
            expected_size = ipa.stat().st_size
            prepared = prepare_artifact(ipa)
            try:
                ipa.unlink()
                self.assertEqual(prepared.artifact_name, "Cached.ipa")
                self.assertEqual(prepared.artifact_size, expected_size)
                self.assertIsNotNone(prepared.artifact_modified_at)
                self.assertTrue((prepared.app_root / "Info.plist").is_file())
            finally:
                prepared.cleanup()


if __name__ == "__main__":
    unittest.main()
