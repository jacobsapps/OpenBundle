from __future__ import annotations

from pathlib import Path
import json
import tempfile
import unittest

from openbundle.analyzer import BundleAnalyzer, Record
from openbundle.report import render_report
from tests.helpers import make_app


class AnalyzerTests(unittest.TestCase):
    def test_analyzes_duplicates_small_files_and_unnecessary_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = make_app(root, small_file_count=260)
            report = BundleAnalyzer().analyze(app)
            insight_ids = {item["id"] for item in report["insights"]}
            self.assertIn("duplicates", insight_ids)
            self.assertIn("unnecessary-files", insight_ids)
            self.assertIn("small-files", insight_ids)
            self.assertEqual(report["app"]["bundleID"], "com.example.test")
            self.assertEqual(
                report["tree"]["size"], report["metrics"]["logicalSize"]
            )
            self.assertGreater(report["metrics"]["fileCount"], 260)

            duplicate = next(
                item for item in report["insights"] if item["id"] == "duplicates"
            )
            self.assertEqual(duplicate["savings"], len(b"same resource bytes" * 200))

    def test_marks_exactly_repeated_components_as_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = make_app(root)
            for name in ("First.bundle", "Second.bundle"):
                bundle = app / "Resources" / name
                bundle.mkdir()
                (bundle / "payload.dat").write_bytes(b"component payload" * 400)

            report = BundleAnalyzer().analyze(app)
            component_insight = next(
                item
                for item in report["insights"]
                if item["id"] == "duplicate-components"
            )
            self.assertEqual(component_insight["items"][0]["copies"], 2)

            component_nodes = {
                child["name"]: child
                for resources in report["tree"]["children"]
                if resources["name"] == "Resources"
                for child in resources["children"]
            }
            self.assertTrue(component_nodes["First.bundle"]["duplicateGroup"])
            self.assertEqual(
                component_nodes["First.bundle"]["duplicateGroup"],
                component_nodes["Second.bundle"]["duplicateGroup"],
            )

    def test_coverage_estimate_counts_only_profile_sections_in_data_segment(self) -> None:
        record = Record(
            relative_path="Test",
            absolute_path=Path("/does/not/matter"),
            size=2000,
            compressed_size=1000,
            allocated_size=4096,
            category="binary",
            sha256="0" * 64,
            macho={
                "architectures": [
                    {
                        "architecture": "arm64",
                        "segments": [
                            {
                                "name": "__DATA",
                                "size": 1000,
                                "sections": [
                                    {"name": "__data", "size": 900},
                                    {"name": "__llvm_prf_cnts", "size": 100},
                                ],
                            },
                            {
                                "name": "__LLVM_COV",
                                "size": 300,
                                "sections": [
                                    {"name": "__llvm_covfun", "size": 280},
                                ],
                            },
                        ],
                    }
                ]
            },
        )
        insights: list[dict] = []
        BundleAnalyzer()._coverage_instrumentation_insight([record], insights)
        self.assertEqual(insights[0]["savings"], 400)
        self.assertEqual(record.metadata["coverageInstrumentationBytes"], 400)

    def test_reports_reflection_names_and_payload_like_binary_strings(self) -> None:
        record = Record(
            relative_path="Test",
            absolute_path=Path("/does/not/matter"),
            size=3 * 1024 * 1024,
            compressed_size=2 * 1024 * 1024,
            allocated_size=3 * 1024 * 1024,
            category="binary",
            sha256="0" * 64,
            macho={
                "architectures": [
                    {
                        "architecture": "arm64",
                        "segments": [
                            {
                                "name": "__TEXT",
                                "sections": [
                                    {"name": "__cstring", "size": 1_200_000},
                                    {"name": "__swift5_reflstr", "size": 180_000},
                                    {"name": "__swift5_fieldmd", "size": 90_000},
                                ],
                            }
                        ],
                    }
                ]
            },
        )
        insights: list[dict] = []
        analyzer = BundleAnalyzer()
        analyzer._swift_reflection_insight([record], insights)
        analyzer._embedded_string_data_insight([record], insights)
        self.assertEqual(
            {item["id"] for item in insights},
            {"swift-reflection", "embedded-string-data"},
        )

    def test_reports_large_nested_target_by_bundle_share(self) -> None:
        main = Record(
            relative_path="Test",
            absolute_path=Path("/does/not/matter"),
            size=1000,
            compressed_size=800,
            allocated_size=4096,
            category="binary",
            sha256="0" * 64,
        )
        nested = Record(
            relative_path="Watch/Companion.app/Companion",
            absolute_path=Path("/does/not/matter"),
            size=500,
            compressed_size=400,
            allocated_size=4096,
            category="binary",
            sha256="1" * 64,
        )
        insights: list[dict] = []
        BundleAnalyzer()._embedded_target_insight([main, nested], insights)
        self.assertEqual(insights[0]["id"], "large-embedded-targets")
        self.assertEqual(insights[0]["items"][0]["bundleShare"], 33.3)

    def test_renders_standalone_html_with_escaped_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.html"
            data = {
                "app": {"name": "</script><script>alert(1)</script>"},
                "tree": {},
            }
            render_report(data, output)
            html = output.read_text()
            self.assertNotIn("</script><script>alert(1)</script>", html)
            payload = html.split(
                '<script id="report-data" type="application/json">', 1
            )[1].split("</script>", 1)[0]
            decoded = json.loads(payload)
            self.assertEqual(
                decoded["app"]["name"], "</script><script>alert(1)</script>"
            )


if __name__ == "__main__":
    unittest.main()
