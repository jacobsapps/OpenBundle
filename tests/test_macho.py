from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from openbundle.macho import is_macho, parse_macho
from tests.helpers import write_macho


class MachOTests(unittest.TestCase):
    def test_parses_thin_arm64_sections_and_symbol_table(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "Example"
            write_macho(binary)
            self.assertTrue(is_macho(binary))
            info = parse_macho(binary)
            self.assertIsNotNone(info)
            assert info is not None
            self.assertFalse(info["is_fat"])
            architecture = info["architectures"][0]
            self.assertEqual(architecture["architecture"], "arm64")
            self.assertEqual(architecture["file_type"], "executable")
            self.assertEqual(architecture["symbol_table_bytes"], 260)
            self.assertEqual(architecture["segments"][0]["name"], "__TEXT")
            self.assertEqual(
                architecture["segments"][0]["sections"][0]["name"], "__text"
            )
            self.assertEqual(
                architecture["segments"][0]["sections"][0]["size"], 64
            )

    def test_rejects_non_macho(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "text"
            path.write_text("hello")
            self.assertFalse(is_macho(path))
            self.assertIsNone(parse_macho(path))


if __name__ == "__main__":
    unittest.main()
