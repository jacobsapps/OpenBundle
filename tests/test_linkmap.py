from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from openbundle.linkmap import parse_linkmap


class LinkmapTests(unittest.TestCase):
    def test_aggregates_symbols_by_object_file(self) -> None:
        content = """# Object files:
[  0] linker synthesized
[  1] /work/Feature/File.o
[  2] /work/libVendor.a(Vendor.o)
# Sections:
# Address Size Segment Section
# Symbols:
0x1000 0x00000020 [  1] _$s4Test
0x1020 0x00000010 [  1] _$s5Other
0x1030 0x00000040 [  2] _vendor
# Dead Stripped Symbols:
0x0000 0x00000100 [  2] _unused
"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Test-LinkMap-normal-arm64.txt"
            path.write_text(content)
            units = parse_linkmap(path)
            self.assertEqual(units[0]["name"], "libVendor.a/Vendor.o")
            self.assertEqual(units[0]["size"], 64)
            self.assertEqual(units[1]["size"], 48)


if __name__ == "__main__":
    unittest.main()
