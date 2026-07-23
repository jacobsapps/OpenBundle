from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
import zipfile

from openbundle.artifact import ArtifactError, prepare_artifact
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

    def test_rejects_unknown_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.txt"
            path.write_text("not an app")
            with self.assertRaises(ArtifactError):
                prepare_artifact(path)


if __name__ == "__main__":
    unittest.main()
