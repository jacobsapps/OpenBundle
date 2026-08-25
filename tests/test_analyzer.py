from __future__ import annotations

from pathlib import Path
import json
import plistlib
import tempfile
import unittest

from openbundle.analyzer import (
    BundleAnalyzer,
    Record,
    _architecture_inventory,
    _apply_macho_delivery_estimate,
    _binary_inventory,
    _collect_capability_declarations,
    _component_duplicate_groups,
    _cross_target_duplicate_inventory,
    _rank_recommendations,
    _representative_asset_rendition,
)
from openbundle.platform import BrowserAnalysisPlatform, _catalog_entries
from openbundle.report import render_report, render_report_html
from tests.helpers import make_app


class AnalyzerTests(unittest.TestCase):
    def test_binary_views_split_symbol_records_and_string_table(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = make_app(Path(directory))
            report = BundleAnalyzer().analyze(app)

        binary_node = next(
            child for child in report["tree"]["children"] if child["name"] == "Test"
        )
        linkedit_node = next(
            child
            for child in binary_node["children"]
            if child["name"] == "__LINKEDIT"
        )
        by_name = {child["name"]: child for child in linkedit_node["children"]}
        self.assertEqual(by_name["Symbol records"]["size"], 32)
        self.assertEqual(by_name["Symbol string table"]["size"], 14)
        self.assertEqual(
            sum(child["size"] for child in linkedit_node["children"]),
            linkedit_node["size"],
        )
        self.assertEqual(
            by_name["Symbol string table"]["metadata"]["loadCommand"],
            "LC_SYMTAB",
        )

        binary = next(
            item for item in report["binaries"]["items"] if item["name"] == "Test"
        )
        linkedit = next(
            segment
            for segment in binary["architectures"][0]["segments"]
            if segment["name"] == "__LINKEDIT"
        )
        self.assertEqual(
            [section["name"] for section in linkedit["sections"]],
            ["Symbol records", "Symbol string table"],
        )
        self.assertEqual(linkedit["unattributedSize"], 0)

        html = render_report_html(report)
        self.assertIn("Symbol names are stored separately.", html)
        self.assertIn("Symbol string table", html)

    def test_latest_iphone_delivery_selects_arm64e_from_fat_binary(self) -> None:
        record = Record(
            relative_path="Frameworks/Example.framework/Example",
            absolute_path=Path("/temporary/Example"),
            size=1_100,
            compressed_size=550,
            allocated_size=4_096,
            category="binary",
            sha256="1" * 64,
            macho={
                "is_fat": True,
                "architectures": [
                    {"architecture": "x86_64", "size": 500},
                    {"architecture": "arm64", "size": 400},
                    {"architecture": "arm64e", "size": 300},
                ],
            },
        )

        self.assertTrue(_apply_macho_delivery_estimate(record))
        self.assertEqual(record.delivered_install_size, 300)
        self.assertEqual(record.delivered_download_size, 150)
        self.assertEqual(
            record.metadata["deliveryEstimate"]["architecture"], "arm64e"
        )

    def test_only_material_measured_recommendations_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = make_app(root, small_file_count=260)
            report = BundleAnalyzer().analyze(app)
            insight_ids = {item["id"] for item in report["insights"]}
            self.assertNotIn("duplicates", insight_ids)
            self.assertNotIn("unnecessary-files", insight_ids)
            self.assertNotIn("small-files", insight_ids)
            self.assertEqual(report["app"]["bundleID"], "com.example.test")
            self.assertEqual(
                report["tree"]["size"], report["metrics"]["logicalSize"]
            )
            self.assertGreater(report["metrics"]["fileCount"], 260)

            self.assertTrue(
                all(item["savings"] >= 100_000 for item in report["insights"])
            )

    def test_marks_exactly_repeated_components_as_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = make_app(root)
            for name in ("First.bundle", "Second.bundle"):
                bundle = app / "Resources" / name
                bundle.mkdir()
                (bundle / "payload.dat").write_bytes(b"component payload" * 400)

            report = BundleAnalyzer().analyze(app)
            self.assertNotIn(
                "duplicate-components",
                {item["id"] for item in report["insights"]},
            )

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
            component = report["architecture"]["duplicateComponents"][0]
            self.assertEqual(component["duplicateType"], "component")
            self.assertEqual(component["scope"], "same-runtime")
            self.assertEqual(component["actionability"], "review")

    def test_recommendation_cutoff_and_order_are_exact(self) -> None:
        candidates = [
            {"id": "none", "title": "None", "savings": None},
            {"id": "bool", "title": "Bool", "savings": True},
            {"id": "string", "title": "String", "savings": "900000"},
            {"id": "nan", "title": "NaN", "savings": float("nan")},
            {"id": "infinity", "title": "Infinity", "savings": float("inf")},
            {"id": "small", "title": "Small", "savings": 99_999},
            {"id": "tie-z", "title": "Zulu", "savings": 100_000},
            {"id": "large", "title": "Large", "savings": 300_000},
            {"id": "tie-a", "title": "Alpha", "savings": 100_000},
        ]

        ranked = _rank_recommendations(candidates)

        self.assertEqual(
            [item["id"] for item in ranked],
            ["large", "tie-a", "tie-z"],
        )

    def test_component_duplicate_scope_recognizes_extension_roots(self) -> None:
        records = [
            Record(
                relative_path=f"PlugIns/{name}.appex/payload.dat",
                absolute_path=Path("/temporary/Test.app")
                / f"PlugIns/{name}.appex/payload.dat",
                size=8_000,
                compressed_size=6_000,
                allocated_size=8_192,
                category="other",
                sha256="a" * 64,
            )
            for name in ("First", "Second")
        ]

        _, items = _component_duplicate_groups(records)

        extension_group = next(item for item in items if item["kind"] == "appex")
        self.assertEqual(extension_group["duplicateType"], "component")
        self.assertEqual(extension_group["scope"], "cross-target")
        self.assertEqual(extension_group["actionability"], "review")

    def test_loose_image_thinning_keeps_grouped_scale_evidence(self) -> None:
        def image(path: str, size: int, digest: str) -> Record:
            return Record(
                relative_path=path,
                absolute_path=Path("/temporary/Test.app") / path,
                size=size,
                compressed_size=size,
                allocated_size=size,
                category="image",
                sha256=digest,
            )

        records = [
            image("Artwork@2x.png", 120_000, "1" * 64),
            image("Artwork@3x.png", 260_000, "2" * 64),
            image("Icon@2x~iphone.png", 80_000, "3" * 64),
            image("Icon@3x~iphone.png", 150_000, "4" * 64),
            image("Icon@2x~ipad.png", 90_000, "5" * 64),
            image("Badge@2x~iphone.png", 50_000, "6" * 64),
            image("Badge@2x~ipad.png", 60_000, "7" * 64),
        ]
        insights: list[dict] = []

        BundleAnalyzer()._asset_catalog_insights(records, insights)

        insight = next(item for item in insights if item["id"] == "asset-catalog-scales")
        self.assertEqual(insight["savings"], 200_000)
        self.assertEqual(len(insight["items"]), 2)
        artwork = insight["items"][0]
        self.assertEqual(artwork["name"], "Artwork.png")
        self.assertEqual(artwork["size"], 380_000)
        self.assertEqual(artwork["retainedSize"], 260_000)
        self.assertEqual(artwork["savings"], 120_000)
        self.assertEqual(
            [variant["scale"] for variant in artwork["variants"]],
            [2, 3],
        )
        self.assertNotIn("asset-catalog-scales", records[4].insight_ids)
        self.assertNotIn("asset-catalog-scales", records[5].insight_ids)
        self.assertNotIn("asset-catalog-scales", records[6].insight_ids)

    def test_duplicate_recommendation_keeps_every_group_for_expansion(self) -> None:
        records = []
        for index in range(101):
            digest = f"{index:064x}"
            for copy in range(2):
                records.append(
                    Record(
                        relative_path=f"Target{copy}/duplicate-{index}.dat",
                        absolute_path=Path("/temporary/Test.app")
                        / f"Target{copy}/duplicate-{index}.dat",
                        size=2_048,
                        compressed_size=2_048,
                        allocated_size=4_096,
                        category="other",
                        sha256=digest,
                    )
                )
        insights: list[dict] = []

        BundleAnalyzer()._duplicate_insight(records, [], insights)

        self.assertEqual(len(insights), 1)
        self.assertEqual(len(insights[0]["items"]), 101)
        self.assertEqual(insights[0]["savings"], 101 * 2_048)
        self.assertEqual(insights[0]["pathCount"], 202)
        self.assertEqual(len(insights[0]["paths"]), 202)
        self.assertEqual(insights[0]["pathsOmitted"], 0)

    def test_duplicate_savings_do_not_cross_runtime_bundles(self) -> None:
        paths = (
            "assets/shared.js",
            "PlugIns/Share.appex/share-copy.js",
            "PlugIns/Widget.appex/widget-copy.js",
        )
        records = [
            Record(
                relative_path=path,
                absolute_path=Path("/temporary/Test.app") / path,
                size=250_000,
                compressed_size=200_000,
                allocated_size=253_952,
                category="other",
                sha256="a" * 64,
            )
            for path in paths
        ]
        insights: list[dict] = []

        BundleAnalyzer()._duplicate_insight(records, [], insights)

        self.assertEqual(insights, [])
        self.assertTrue(all(record.duplicate_group is None for record in records))

        inventory = _cross_target_duplicate_inventory(records)
        self.assertEqual(inventory["count"], 1)
        self.assertEqual(inventory["totalRepeatedSize"], 500_000)
        self.assertEqual(inventory["items"][0]["targetCount"], 3)
        self.assertEqual(inventory["items"][0]["pathCount"], 3)
        self.assertEqual(inventory["items"][0]["duplicateType"], "file")
        self.assertEqual(inventory["items"][0]["scope"], "cross-target")
        self.assertEqual(inventory["items"][0]["actionability"], "review")
        self.assertEqual(inventory["items"][0]["group"], "X1")
        self.assertTrue(all(record.duplicate_group is None for record in records))
        self.assertEqual(
            inventory["items"][0]["name"],
            "shared.js +2 more",
        )

    def test_cross_target_catalog_overlap_is_review_evidence_and_marks_tree(
        self,
    ) -> None:
        catalog_paths = (
            "Assets.car",
            "Phone.bundle/Assets.car",
            "PlugIns/Widget.appex/Assets.car",
        )
        records = [
            Record(
                relative_path=path,
                absolute_path=Path("/temporary/Test.app") / path,
                size=500_000 + index,
                compressed_size=400_000,
                allocated_size=503_808,
                category="asset_catalog",
                sha256=str(index + 1) * 64,
            )
            for index, path in enumerate(catalog_paths)
        ]
        renditions: list[dict] = []
        entries_by_catalog: dict[str, list[dict]] = {
            path: [] for path in catalog_paths
        }
        for asset_index, size in enumerate((120_000, 80_000)):
            for catalog_path in catalog_paths:
                entry_path = f"{catalog_path}::SharedAsset{asset_index}"
                entry = {
                    "name": f"SharedAsset{asset_index}",
                    "path": entry_path,
                    "kind": "asset",
                    "category": "asset_catalog",
                    "size": size,
                    "compressedSize": size,
                    "allocatedSize": size,
                    "children": [],
                    "metadata": {"assetType": "image", "renditionCount": 1},
                    "insights": [],
                }
                entries_by_catalog[catalog_path].append(entry)
                renditions.append(
                    {
                        "entry": entry,
                        "name": entry["name"],
                        "path": entry_path,
                        "displayPath": f"{entry_path}/3x.png",
                        "size": size,
                        "digest": f"{asset_index + 1:064x}",
                    }
                )
        for record in records:
            record.virtual_children = entries_by_catalog[record.relative_path]

        insights: list[dict] = []
        analyzer = BundleAnalyzer()
        analyzer._duplicate_insight(records, renditions, insights)

        # The app and resource bundle share one runtime, so their copies remain
        # actionable recommendation savings. The extension copy does not.
        self.assertEqual(insights[0]["savings"], 200_000)
        same_runtime_group = records[0].metadata["duplicateGroup"]
        self.assertEqual(
            records[1].metadata["duplicateGroup"], same_runtime_group
        )
        self.assertNotIn("duplicateGroup", records[2].metadata)

        inventory = _cross_target_duplicate_inventory(
            records,
            asset_renditions=renditions,
        )

        self.assertEqual(inventory["count"], 1)
        self.assertEqual(inventory["totalRepeatedSize"], 200_000)
        catalog = inventory["items"][0]
        self.assertEqual(catalog["duplicateType"], "catalog")
        self.assertEqual(catalog["scope"], "cross-target")
        self.assertEqual(catalog["actionability"], "review")
        self.assertEqual(catalog["targetCount"], 2)
        self.assertEqual(catalog["catalogCount"], 3)
        self.assertEqual(catalog["repeatedAssetCount"], 2)
        self.assertEqual(catalog["repeatedRenditionCount"], 2)
        self.assertEqual(catalog["repeatedAssetNameCount"], 2)
        self.assertEqual(catalog["repeatedSize"], 200_000)

        # Cross-target evidence augments, rather than overwrites, the safer
        # same-runtime recommendation grouping.
        self.assertEqual(records[0].metadata["duplicateGroup"], same_runtime_group)
        self.assertIn(
            catalog["group"],
            records[0].metadata["crossTargetDuplicateGroups"],
        )
        widget = records[2]
        self.assertEqual(widget.metadata["duplicateGroup"], catalog["group"])
        self.assertEqual(widget.metadata["scope"], "cross-target")
        self.assertEqual(widget.metadata["crossTargetRepeatedAssetCount"], 2)
        self.assertTrue(
            all(
                entry["duplicateGroup"].startswith("XA")
                and entry["scope"] == "cross-target"
                for entry in entries_by_catalog[catalog_paths[2]]
            )
        )

        tree = analyzer._build_tree("Test.app", records, {})
        widget_catalog = next(
            child
            for plugins in tree["children"]
            if plugins["name"] == "PlugIns"
            for extension in plugins["children"]
            if extension["name"] == "Widget.appex"
            for child in extension["children"]
            if child["name"] == "Assets.car"
        )
        self.assertEqual(
            widget_catalog["metadata"]["duplicateCatalogGroup"],
            catalog["group"],
        )
        self.assertTrue(
            all(child["duplicateGroup"] for child in widget_catalog["children"])
        )

    def test_duplicate_path_totals_include_item_paths_beyond_display_cap(self) -> None:
        records = [
            Record(
                relative_path=f"copies/copy-{index}.dat",
                absolute_path=Path("/temporary/Test.app")
                / f"copies/copy-{index}.dat",
                size=2_048,
                compressed_size=1_024,
                allocated_size=4_096,
                category="other",
                sha256="a" * 64,
            )
            for index in range(60)
        ]
        insights: list[dict] = []

        BundleAnalyzer()._duplicate_insight(records, [], insights)

        self.assertEqual(insights[0]["pathCount"], 60)
        self.assertEqual(len(insights[0]["paths"]), 60)
        self.assertEqual(insights[0]["items"][0]["pathCount"], 60)
        self.assertEqual(len(insights[0]["items"][0]["paths"]), 50)
        self.assertEqual(insights[0]["items"][0]["pathsOmitted"], 10)

    def test_equal_sized_duplicate_group_ids_do_not_depend_on_input_order(self) -> None:
        def records() -> list[Record]:
            return [
                Record(
                    relative_path=path,
                    absolute_path=Path("/temporary/Test.app") / path,
                    size=2_048,
                    compressed_size=1_024,
                    allocated_size=4_096,
                    category="other",
                    sha256=digest,
                )
                for digest, paths in (
                    ("a" * 64, ("A/one.dat", "A/two.dat")),
                    ("b" * 64, ("B/one.dat", "B/two.dat")),
                )
                for path in paths
            ]

        forward = records()
        reversed_records = list(reversed(records()))
        BundleAnalyzer()._duplicate_insight(forward, [], [])
        BundleAnalyzer()._duplicate_insight(reversed_records, [], [])

        self.assertEqual(
            {record.relative_path: record.duplicate_group for record in forward},
            {
                record.relative_path: record.duplicate_group
                for record in reversed_records
            },
        )

    def test_localization_and_interface_slots_are_not_removable_duplicates(self) -> None:
        records = [
            Record(
                relative_path=path,
                absolute_path=Path("/temporary/Test.app") / path,
                size=120_000,
                compressed_size=80_000,
                allocated_size=122_880,
                category=category,
                sha256=digest,
            )
            for path, category, digest in (
                ("en.lproj/Localizable.strings", "localization", "b" * 64),
                ("fr.lproj/Localizable.strings", "localization", "b" * 64),
                ("First.storyboardc/view.nib", "interface", "c" * 64),
                ("Second.storyboardc/view.nib", "interface", "c" * 64),
            )
        ]
        insights: list[dict] = []

        BundleAnalyzer()._duplicate_insight(records, [], insights)

        self.assertEqual(insights, [])

    def test_cross_target_files_covered_by_a_component_are_not_repeated_twice(self) -> None:
        component_paths = (
            "Frameworks/Shared.framework",
            "PlugIns/Widget.appex/Frameworks/Shared.framework",
        )
        records = [
            Record(
                relative_path=f"{path}/payload.dat",
                absolute_path=Path("/temporary/Test.app") / path / "payload.dat",
                size=250_000,
                compressed_size=200_000,
                allocated_size=253_952,
                category="other",
                sha256="a" * 64,
            )
            for path in component_paths
        ]
        component = {
            "group": "C1",
            "name": "Shared.framework",
            "kind": "framework",
            "size": 250_000,
            "copies": 2,
            "paths": list(component_paths),
        }

        inventory = _cross_target_duplicate_inventory(records, [component])

        self.assertEqual(inventory["count"], 0)
        self.assertEqual(inventory["totalRepeatedSize"], 0)

    def test_duplicate_evidence_keeps_a_representative_filename(self) -> None:
        records = [
            Record(
                relative_path=path,
                absolute_path=Path("/temporary/Test.app") / path,
                size=120_000,
                compressed_size=80_000,
                allocated_size=122_880,
                category="image",
                sha256="d" * 64,
            )
            for path in ("EmptyAudio.png", "EmptyImages.png")
        ]
        insights: list[dict] = []

        BundleAnalyzer()._duplicate_insight(records, [], insights)

        self.assertEqual(
            insights[0]["items"][0]["name"],
            "EmptyAudio.png +1 more",
        )
        self.assertEqual(insights[0]["items"][0]["duplicateType"], "file")
        self.assertEqual(insights[0]["items"][0]["scope"], "same-runtime")
        self.assertEqual(insights[0]["items"][0]["actionability"], "candidate")
        self.assertEqual(insights[0]["pathCount"], 2)
        self.assertEqual(insights[0]["pathsOmitted"], 0)

    def test_catalog_rendition_groups_are_clustered_by_catalog_path_set(
        self,
    ) -> None:
        catalog_paths = (
            "FeatureA.bundle/Assets.car",
            "FeatureB.bundle/Assets.car",
        )
        records = [
            Record(
                relative_path=path,
                absolute_path=Path("/temporary/Test.app") / path,
                size=500_000 + index,
                compressed_size=400_000,
                allocated_size=503_808,
                category="asset_catalog",
                sha256=str(index + 1) * 64,
            )
            for index, path in enumerate(catalog_paths)
        ]
        entries: list[dict] = []
        renditions: list[dict] = []
        sizes = (120_000, 80_000, 50_000)
        for asset_index, size in enumerate(sizes):
            for catalog_path in catalog_paths:
                entry_path = f"{catalog_path}::Asset{asset_index}"
                entry = {
                    "name": f"Asset{asset_index}",
                    "path": entry_path,
                    "kind": "asset",
                    "category": "asset_catalog",
                    "size": size,
                    "metadata": {"assetType": "image", "renditionCount": 1},
                    "insights": [],
                }
                entries.append(entry)
                renditions.append(
                    {
                        "entry": entry,
                        "name": f"Asset{asset_index}",
                        "path": entry_path,
                        "displayPath": f"{entry_path}/Asset{asset_index}@3x.png",
                        "size": size,
                        "digest": f"{asset_index + 1:064x}",
                        "assetType": "image",
                        "scale": 3,
                        "physical": True,
                    }
                )
        insights: list[dict] = []

        BundleAnalyzer()._duplicate_insight(records, renditions, insights)

        self.assertEqual(len(insights), 1)
        insight = insights[0]
        self.assertEqual(insight["itemCount"], 1)
        self.assertEqual(insight["pathCount"], 2)
        catalog_group = insight["items"][0]
        self.assertEqual(catalog_group["duplicateType"], "catalog")
        self.assertEqual(catalog_group["catalogPaths"], list(catalog_paths))
        self.assertEqual(catalog_group["repeatedAssetCount"], 3)
        self.assertEqual(catalog_group["assetGroupCount"], 3)
        self.assertEqual(len(catalog_group["assetGroups"]), 3)
        self.assertEqual(catalog_group["savings"], sum(sizes))
        self.assertEqual(
            catalog_group["savings"],
            sum(group["savings"] for group in catalog_group["assetGroups"]),
        )
        # The nested groups are evidence for the one aggregate row; the
        # recommendation must not count their bytes again.
        self.assertEqual(insight["savings"], catalog_group["savings"])
        self.assertTrue(all(record.duplicate_group is None for record in records))
        for record in records:
            self.assertEqual(record.metadata["duplicateType"], "catalog")
            self.assertEqual(record.metadata["duplicateCount"], 1)
            self.assertEqual(record.metadata["repeatedAssetCount"], 3)
            self.assertEqual(
                record.metadata["duplicateGroup"], catalog_group["group"]
            )
            self.assertEqual(
                record.metadata["duplicateCatalogGroup"], catalog_group["group"]
            )
            self.assertFalse(record.metadata["exactMatch"])
        self.assertTrue(all(entry["duplicateType"] == "asset" for entry in entries))
        self.assertTrue(
            all(entry["metadata"]["duplicateCount"] == 1 for entry in entries)
        )
        self.assertTrue(
            all(rendition["duplicateType"] == "asset" for rendition in renditions)
        )

    def test_exact_catalog_file_match_suppresses_rendition_evidence(self) -> None:
        catalog_paths = (
            "FeatureA.bundle/Assets.car",
            "FeatureB.bundle/Assets.car",
        )
        records = [
            Record(
                relative_path=path,
                absolute_path=Path("/temporary/Test.app") / path,
                size=500_000,
                compressed_size=400_000,
                allocated_size=503_808,
                category="asset_catalog",
                sha256="a" * 64,
            )
            for path in catalog_paths
        ]
        entries: list[dict] = []
        renditions: list[dict] = []
        for catalog_path in catalog_paths:
            entry_path = f"{catalog_path}::Header"
            entry = {
                "name": "Header",
                "path": entry_path,
                "kind": "asset",
                "metadata": {"assetType": "image", "renditionCount": 1},
                "insights": [],
            }
            entries.append(entry)
            renditions.append(
                {
                    "entry": entry,
                    "name": "Header",
                    "path": entry_path,
                    "displayPath": f"{entry_path}/Header@3x.png",
                    "size": 200_000,
                    "digest": "b" * 64,
                    "assetType": "image",
                    "scale": 3,
                    "physical": True,
                }
            )
        insights: list[dict] = []

        BundleAnalyzer()._duplicate_insight(records, renditions, insights)

        self.assertEqual(insights[0]["itemCount"], 1)
        item = insights[0]["items"][0]
        self.assertEqual(item["kind"], "file")
        self.assertEqual(item["duplicateType"], "catalog")
        self.assertTrue(item["exactMatch"])
        self.assertEqual(item["savings"], 500_000)
        self.assertNotIn("assetGroups", item)
        self.assertEqual(records[0].duplicate_group, records[1].duplicate_group)
        for record in records:
            self.assertEqual(record.metadata["duplicateType"], "catalog")
            self.assertTrue(record.metadata["exactMatch"])
            self.assertEqual(record.metadata["duplicateCount"], 1)
        self.assertTrue(all("duplicateGroup" not in entry for entry in entries))
        self.assertTrue(
            all("duplicateGroup" not in rendition for rendition in renditions)
        )

    def test_catalog_clusters_do_not_merge_different_catalog_path_sets(self) -> None:
        catalog_paths = (
            "FeatureA.bundle/Assets.car",
            "FeatureB.bundle/Assets.car",
            "FeatureC.bundle/Assets.car",
        )
        records = [
            Record(
                relative_path=path,
                absolute_path=Path("/temporary/Test.app") / path,
                size=400_000 + index,
                compressed_size=300_000,
                allocated_size=401_408,
                category="asset_catalog",
                sha256=str(index + 1) * 64,
            )
            for index, path in enumerate(catalog_paths)
        ]
        renditions: list[dict] = []
        for set_index, pair in enumerate(
            (catalog_paths[:2], (catalog_paths[0], catalog_paths[2]))
        ):
            for asset_index in range(2):
                size = 40_000 + set_index * 10_000 + asset_index
                for catalog_path in pair:
                    entry_path = f"{catalog_path}::Set{set_index}Asset{asset_index}"
                    entry = {
                        "name": f"Set{set_index}Asset{asset_index}",
                        "path": entry_path,
                        "kind": "asset",
                        "metadata": {"assetType": "image"},
                        "insights": [],
                    }
                    renditions.append(
                        {
                            "entry": entry,
                            "name": entry["name"],
                            "path": entry_path,
                            "displayPath": f"{entry_path}/3x.png",
                            "size": size,
                            "digest": f"{set_index * 2 + asset_index + 1:064x}",
                        }
                    )
        insights: list[dict] = []

        BundleAnalyzer()._duplicate_insight(records, renditions, insights)

        catalog_items = [
            item
            for item in insights[0]["items"]
            if item["duplicateType"] == "catalog"
        ]
        self.assertEqual(len(catalog_items), 2)
        self.assertEqual(
            {tuple(item["catalogPaths"]) for item in catalog_items},
            {catalog_paths[:2], (catalog_paths[0], catalog_paths[2])},
        )
        by_path = {record.relative_path: record for record in records}
        self.assertEqual(by_path[catalog_paths[0]].metadata["duplicateCount"], 2)
        self.assertEqual(by_path[catalog_paths[0]].metadata["repeatedAssetCount"], 4)
        self.assertEqual(by_path[catalog_paths[1]].metadata["duplicateCount"], 1)
        self.assertEqual(by_path[catalog_paths[2]].metadata["duplicateCount"], 1)

    def test_static_linking_candidates_are_architecture_evidence_not_savings(self) -> None:
        def binary(
            path: str,
            size: int,
            *,
            file_type: str,
            dependencies: tuple[str, ...] = (),
            rpaths: tuple[str, ...] = (),
            page_padding: int = 0,
        ) -> Record:
            return Record(
                relative_path=path,
                absolute_path=Path("/does/not/matter") / path,
                size=size,
                compressed_size=size,
                allocated_size=size,
                category="binary",
                sha256="0" * 64,
                metadata={
                    "dependencies": list(dependencies),
                    "pagePaddingEstimate": page_padding,
                },
                macho={
                    "architectures": [
                        {
                            "file_type": file_type,
                            "dependencies": list(dependencies),
                            "rpaths": list(rpaths),
                        }
                    ]
                },
            )

        app = binary(
            "Example",
            4_000_000,
            file_type="executable",
            dependencies=(
                "@rpath/Large.framework/Large",
                "@loader_path/Frameworks/Large.framework/Large",
                "@executable_path/Frameworks/Feature.framework/Feature",
                "@rpath/Shared.framework/Shared",
            ),
            rpaths=("@loader_path/Frameworks",),
        )
        large = binary(
            "Frameworks/Large.framework/Large",
            8_300_000,
            file_type="dynamic-library",
            page_padding=70_000,
        )
        large_resource = Record(
            relative_path="Frameworks/Large.framework/Info.plist",
            absolute_path=Path("/does/not/matter/Info.plist"),
            size=700_000,
            compressed_size=500_000,
            allocated_size=700_416,
            category="metadata",
            sha256="2" * 64,
        )
        feature = binary(
            "Frameworks/Feature.framework/Feature",
            2_000_000,
            file_type="dynamic-library",
            dependencies=("@rpath/Shared.framework/Shared",),
            rpaths=("/usr/lib/swift",),
            page_padding=30_000,
        )
        shared = binary(
            "Frameworks/Shared.framework/Shared",
            800_000,
            file_type="dynamic-library",
            page_padding=40_000,
        )
        runtime_loaded = binary(
            "Frameworks/Runtime.framework/Runtime",
            5_000_000,
            file_type="dynamic-library",
            page_padding=20_000,
        )
        insights: list[dict] = []

        BundleAnalyzer()._framework_insights(
            [app, large, large_resource, feature, shared, runtime_loaded], insights
        )

        self.assertNotIn(
            "dynamic-frameworks", {item["id"] for item in insights}
        )
        inventory = _architecture_inventory(
            [app, large, large_resource, feature, shared, runtime_loaded],
            {
                "CFBundleDisplayName": "Example",
                "CFBundleIdentifier": "com.example",
                "CFBundleExecutable": "Example",
            },
            "Example.app",
            [],
        )
        by_path = {item["path"]: item for item in inventory["frameworks"]}
        large_root = "Frameworks/Large.framework"
        shared_root = "Frameworks/Shared.framework"
        runtime_root = "Frameworks/Runtime.framework"
        self.assertEqual(by_path[large_root]["binarySize"], 8_300_000)
        self.assertEqual(by_path[large_root]["size"], 9_000_000)
        self.assertEqual(by_path[large_root]["consumerCount"], 1)
        self.assertEqual(by_path[large_root]["consumers"], ["Example"])
        self.assertTrue(by_path[large_root]["staticCandidate"])
        self.assertEqual(by_path[shared_root]["consumerCount"], 2)
        self.assertEqual(
            by_path[shared_root]["consumers"],
            ["Example", "Frameworks/Feature.framework/Feature"],
        )
        self.assertFalse(by_path[shared_root]["staticCandidate"])
        self.assertEqual(by_path[runtime_root]["consumerCount"], 0)
        self.assertFalse(by_path[runtime_root]["staticCandidate"])
        reviews = inventory["linkingReviews"]
        self.assertEqual(
            [item["path"] for item in reviews],
            [large_root, "Frameworks/Feature.framework"],
        )
        self.assertEqual(reviews[0]["reviewScopeBytes"], 8_300_000)
        self.assertEqual(reviews[0]["frameworkSize"], 9_000_000)
        self.assertEqual(reviews[0]["resourceSize"], 700_000)
        self.assertEqual(reviews[0]["consumer"], "Example")
        self.assertEqual(reviews[0]["consumerName"], "Example")
        self.assertEqual(inventory["linkingReviewThresholdBytes"], 2_000_000)
        self.assertNotIn(
            runtime_root,
            {item["path"] for item in reviews},
        )
        self.assertEqual(_rank_recommendations(insights), [])

    def test_linking_reviews_are_large_direct_dynamic_candidates_only(self) -> None:
        def binary(
            path: str,
            size: int,
            file_types: tuple[str, ...],
            *,
            dependencies: tuple[str, ...] = (),
            rpaths: tuple[str, ...] = (),
        ) -> Record:
            return Record(
                relative_path=path,
                absolute_path=Path("/does/not/matter") / path,
                size=size,
                compressed_size=size // 2,
                allocated_size=size,
                category="binary",
                sha256=path,
                metadata={"dependencies": list(dependencies)},
                macho={
                    "architectures": [
                        {
                            "file_type": file_type,
                            "dependencies": list(dependencies),
                            "rpaths": list(rpaths),
                        }
                        for file_type in file_types
                    ]
                },
            )

        names_and_sizes = (
            ("Duplicate", 10_000_000),
            ("Mixed", 9_000_000),
            ("First", 8_000_000),
            ("Second", 7_000_000),
            ("Third", 6_000_000),
            ("Fourth", 5_000_000),
            ("Tiny", 1_900_000),
        )
        dependencies = tuple(
            f"@rpath/{name}.framework/{name}" for name, _ in names_and_sizes
        )
        records = [
            binary(
                "Example",
                4_000_000,
                ("executable",),
                dependencies=dependencies,
                rpaths=("@loader_path/Frameworks",),
            )
        ]
        for name, size in names_and_sizes:
            file_types = (
                ("dynamic-library", "executable")
                if name == "Mixed"
                else ("dynamic-library",)
            )
            records.append(
                binary(
                    f"Frameworks/{name}.framework/{name}",
                    size,
                    file_types,
                )
            )

        inventory = _architecture_inventory(
            records,
            {
                "CFBundleDisplayName": "Example",
                "CFBundleIdentifier": "com.example",
                "CFBundleExecutable": "Example",
            },
            "Example.app",
            [
                {
                    "group": "C1",
                    "name": "Duplicate.framework",
                    "kind": "framework",
                    "size": 10_000_000,
                    "copies": 2,
                    "paths": ["Frameworks/Duplicate.framework"],
                }
            ],
        )

        self.assertEqual(
            [item["name"] for item in inventory["linkingReviews"]],
            ["First", "Second", "Third"],
        )
        self.assertTrue(
            all(
                item["consumer"] == "Example"
                for item in inventory["linkingReviews"]
            )
        )
        self.assertEqual(len(inventory["linkingReviews"]), 3)

    def test_architecture_inventory_keeps_targets_and_framework_consumers(self) -> None:
        def record(
            path: str,
            size: int,
            *,
            absolute_path: Path,
            file_type: str | None = None,
            dependencies: tuple[str, ...] = (),
            rpaths: tuple[str, ...] = (),
        ) -> Record:
            macho = (
                {
                    "architectures": [
                        {
                            "file_type": file_type,
                            "dependencies": list(dependencies),
                            "rpaths": list(rpaths),
                        }
                    ]
                }
                if file_type
                else None
            )
            return Record(
                relative_path=path,
                absolute_path=absolute_path,
                size=size,
                compressed_size=size // 2,
                allocated_size=size,
                category="binary" if macho else "metadata",
                sha256="a" * 64,
                metadata={"dependencies": list(dependencies)},
                macho=macho,
            )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            widget_plist = root / "Widget-Info.plist"
            widget_plist.write_bytes(
                plistlib.dumps(
                    {
                        "CFBundleDisplayName": "Example Widget",
                        "CFBundleIdentifier": "com.example.widget",
                        "CFBundleExecutable": "Widget",
                        "NSExtension": {
                            "NSExtensionPointIdentifier": "com.apple.widgetkit-extension"
                        },
                    }
                )
            )
            records = [
                record(
                    "Example",
                    4_000_000,
                    absolute_path=root / "Example",
                    file_type="executable",
                    dependencies=("@rpath/Large.framework/Large",),
                    rpaths=("@loader_path/Frameworks",),
                ),
                record(
                    "Frameworks/Large.framework/Large",
                    8_300_000,
                    absolute_path=root / "Large",
                    file_type="dynamic-library",
                ),
                record(
                    "Frameworks/Large.framework/Info.plist",
                    700_000,
                    absolute_path=root / "Large-Info.plist",
                ),
                record(
                    "PlugIns/Widget.appex/Info.plist",
                    2_000,
                    absolute_path=widget_plist,
                ),
                record(
                    "PlugIns/Widget.appex/Widget",
                    500_000,
                    absolute_path=root / "Widget",
                    file_type="executable",
                ),
            ]

            inventory = _architecture_inventory(
                records,
                {
                    "CFBundleDisplayName": "Example",
                    "CFBundleIdentifier": "com.example",
                    "CFBundleExecutable": "Example",
                },
                "Example.app",
                [
                    {
                        "group": "C1",
                        "name": "Shared.bundle",
                        "kind": "bundle",
                        "size": 200_000,
                        "copies": 2,
                        "paths": ["One.bundle", "Two.bundle"],
                    }
                ],
            )

        self.assertEqual(
            [(item["name"], item["kind"]) for item in inventory["targets"]],
            [("Example", "App"), ("Example Widget", "Widget")],
        )
        self.assertEqual(
            sum(item["size"] for item in inventory["targets"]),
            sum(item.size for item in records),
        )
        self.assertEqual(inventory["targets"][1]["size"], 502_000)
        framework = inventory["frameworks"][0]
        self.assertEqual(framework["name"], "Large")
        self.assertEqual(framework["size"], 9_000_000)
        self.assertEqual(framework["binarySize"], 8_300_000)
        self.assertEqual(framework["consumers"], ["Example"])
        self.assertTrue(framework["staticCandidate"])
        self.assertEqual(
            inventory["duplicateComponents"][0]["repeatedSize"], 200_000
        )

    def test_dynamic_framework_consumers_resolve_matching_bundle_scope(
        self,
    ) -> None:
        def binary(
            path: str,
            *,
            file_type: str,
            dependencies: tuple[str, ...] = (),
            rpaths: tuple[str, ...] = (),
            page_padding: int = 0,
        ) -> Record:
            return Record(
                relative_path=path,
                absolute_path=Path("/does/not/matter") / path,
                size=2_000_000,
                compressed_size=1_500_000,
                allocated_size=2_002_944,
                category="binary",
                sha256="1" * 64,
                metadata={
                    "dependencies": list(dependencies),
                    "pagePaddingEstimate": page_padding,
                },
                macho={
                    "architectures": [
                        {
                            "file_type": file_type,
                            "dependencies": list(dependencies),
                            "rpaths": list(rpaths),
                        }
                    ]
                },
            )

        dependency = "@rpath/Shared.framework/Shared"
        main = binary(
            "Example",
            file_type="executable",
            dependencies=(dependency,),
            rpaths=("@loader_path/Frameworks",),
        )
        system_user = binary(
            "SystemUser",
            file_type="executable",
            dependencies=(
                "/System/Library/Frameworks/Shared.framework/Shared",
                "@rpath/shared.framework/shared",
            ),
            rpaths=("@loader_path/Frameworks",),
        )
        extension = binary(
            "PlugIns/Widget.appex/Widget",
            file_type="executable",
            dependencies=(dependency,),
            rpaths=("@loader_path/Frameworks",),
        )
        main_framework = binary(
            "Frameworks/Shared.framework/Shared",
            file_type="dynamic-library",
            page_padding=60_000,
        )
        extension_framework = binary(
            "PlugIns/Widget.appex/Frameworks/Shared.framework/Shared",
            file_type="dynamic-library",
            page_padding=60_000,
        )
        wrong_scope_consumer = binary(
            "AnotherExecutable",
            file_type="executable",
            dependencies=("@rpath/ExtensionOnly.framework/ExtensionOnly",),
            rpaths=("@loader_path/Frameworks",),
        )
        extension_only = binary(
            "PlugIns/Widget.appex/Frameworks/ExtensionOnly.framework/ExtensionOnly",
            file_type="dynamic-library",
            page_padding=10_000,
        )
        insights: list[dict] = []

        BundleAnalyzer()._framework_insights(
            [
                main,
                system_user,
                extension,
                main_framework,
                extension_framework,
                wrong_scope_consumer,
                extension_only,
            ],
            insights,
        )

        inventory = _architecture_inventory(
            [
                main,
                system_user,
                extension,
                main_framework,
                extension_framework,
                wrong_scope_consumer,
                extension_only,
            ],
            {"CFBundleExecutable": "Example"},
            "Example.app",
            [],
        )
        items = {item["path"]: item for item in inventory["frameworks"]}
        self.assertEqual(
            items["Frameworks/Shared.framework"]["consumers"], ["Example"]
        )
        self.assertEqual(
            items["PlugIns/Widget.appex/Frameworks/Shared.framework"]["consumers"],
            ["PlugIns/Widget.appex/Widget"],
        )
        self.assertTrue(items["Frameworks/Shared.framework"]["staticCandidate"])
        self.assertTrue(items["PlugIns/Widget.appex/Frameworks/Shared.framework"]["staticCandidate"])
        extension_only_root = "PlugIns/Widget.appex/Frameworks/ExtensionOnly.framework"
        self.assertEqual(items[extension_only_root]["consumerCount"], 0)
        self.assertFalse(items[extension_only_root]["staticCandidate"])

    def test_failed_macho_parse_disqualifies_exact_consumer_claim(self) -> None:
        framework = Record(
            relative_path="Frameworks/Feature.framework/Feature",
            absolute_path=Path("/does/not/matter/Feature"),
            size=2_000_000,
            compressed_size=1_500_000,
            allocated_size=2_002_944,
            category="binary",
            sha256="3" * 64,
            metadata={"dependencies": [], "pagePaddingEstimate": 100_000},
            macho={
                "architectures": [
                    {
                        "file_type": "dynamic-library",
                        "dependencies": [],
                        "rpaths": [],
                    }
                ]
            },
        )
        consumer = Record(
            relative_path="Example",
            absolute_path=Path("/does/not/matter/Example"),
            size=3_000_000,
            compressed_size=2_000_000,
            allocated_size=3_002_368,
            category="binary",
            sha256="4" * 64,
            metadata={"dependencies": ["@rpath/Feature.framework/Feature"]},
            macho={
                "architectures": [
                    {
                        "file_type": "executable",
                        "dependencies": ["@rpath/Feature.framework/Feature"],
                        "rpaths": ["@loader_path/Frameworks"],
                    }
                ]
            },
        )
        broken = Record(
            relative_path="BrokenMachO",
            absolute_path=Path("/does/not/matter/BrokenMachO"),
            size=4,
            compressed_size=4,
            allocated_size=4096,
            category="binary",
            sha256="5" * 64,
            metadata={"machoCandidate": True, "machoParseFailed": True},
        )
        insights: list[dict] = []

        BundleAnalyzer()._framework_insights(
            [consumer, framework, broken], insights
        )

        inventory = _architecture_inventory(
            [consumer, framework, broken],
            {"CFBundleExecutable": "Example"},
            "Example.app",
            [],
        )
        item = inventory["frameworks"][0]
        self.assertEqual(item["consumerCount"], 1)
        self.assertFalse(item["staticCandidate"])

    def test_ambiguous_run_paths_never_become_static_candidates(self) -> None:
        def binary(
            path: str,
            *,
            file_type: str,
            dependencies: tuple[str, ...] = (),
            rpaths: tuple[str, ...] = (),
        ) -> Record:
            return Record(
                relative_path=path,
                absolute_path=Path("/does/not/matter") / path,
                size=2_000_000,
                compressed_size=1_500_000,
                allocated_size=2_002_944,
                category="binary",
                sha256="6" * 64,
                metadata={"dependencies": list(dependencies)},
                macho={
                    "architectures": [
                        {
                            "file_type": file_type,
                            "dependencies": list(dependencies),
                            "rpaths": list(rpaths),
                        }
                    ]
                },
            )

        consumer = binary(
            "Example",
            file_type="executable",
            dependencies=("@rpath/Shared.framework/Shared",),
            rpaths=(
                "@loader_path/Frameworks",
                "@loader_path/Alternates",
            ),
        )
        primary = binary(
            "Frameworks/Shared.framework/Shared",
            file_type="dynamic-library",
        )
        alternate = binary(
            "Alternates/Shared.framework/Shared",
            file_type="dynamic-library",
        )

        inventory = _architecture_inventory(
            [consumer, primary, alternate],
            {"CFBundleExecutable": "Example"},
            "Example.app",
            [],
        )

        self.assertEqual(
            [item["consumerCount"] for item in inventory["frameworks"]],
            [0, 0],
        )
        self.assertTrue(
            all(
                item["consumerResolution"] == "Incomplete"
                and not item["staticCandidate"]
                for item in inventory["frameworks"]
            )
        )

    def test_helper_executable_cannot_supply_the_app_runpath(self) -> None:
        def binary(
            path: str,
            *,
            file_type: str,
            dependencies: tuple[str, ...] = (),
            rpaths: tuple[str, ...] = (),
        ) -> Record:
            return Record(
                relative_path=path,
                absolute_path=Path("/does/not/matter") / path,
                size=2_000_000,
                compressed_size=1_500_000,
                allocated_size=2_002_944,
                category="binary",
                sha256="7" * 64,
                metadata={"dependencies": list(dependencies)},
                macho={
                    "architectures": [
                        {
                            "architecture": "arm64",
                            "file_type": file_type,
                            "dependencies": list(dependencies),
                            "rpaths": list(rpaths),
                        }
                    ]
                },
            )

        real_app = binary("RealApp", file_type="executable")
        helper = binary(
            "HelperTool",
            file_type="executable",
            rpaths=("@loader_path/Frameworks",),
        )
        loader = binary(
            "Frameworks/Loader.framework/Loader",
            file_type="dynamic-library",
            dependencies=("@rpath/Target.framework/Target",),
        )
        target = binary(
            "Frameworks/Target.framework/Target",
            file_type="dynamic-library",
        )

        inventory = _architecture_inventory(
            [real_app, helper, loader, target],
            {"CFBundleExecutable": "RealApp"},
            "RealApp.app",
            [],
        )
        item = next(
            framework
            for framework in inventory["frameworks"]
            if framework["name"] == "Target"
        )
        self.assertEqual(item["consumerCount"], 0)
        self.assertEqual(item["consumerResolution"], "Incomplete")
        self.assertFalse(item["staticCandidate"])

    def test_representative_rendition_prefers_exact_3x_over_4x(self) -> None:
        representative = _representative_asset_rendition(
            [
                {"name": "Poster 2x", "size": 200, "scale": 2},
                {"name": "Poster 4x", "size": 800, "scale": 4},
                {"name": "Poster 3x", "size": 400, "scale": 3},
            ]
        )

        self.assertEqual(representative["name"], "Poster 3x")

    def test_native_catalog_asset_types_are_normalized(self) -> None:
        children, renditions = _catalog_entries(
            [
                {
                    "AssetType": "Image",
                    "Name": "Poster",
                    "RenditionName": "Poster@3x.png",
                    "SizeOnDisk": 123_000,
                    "Scale": 3,
                    "PixelWidth": 900,
                    "PixelHeight": 600,
                }
            ],
            "Assets.car",
        )

        self.assertEqual(children[0]["metadata"]["assetType"], "image")
        self.assertEqual(renditions[0]["assetType"], "image")
        self.assertEqual(renditions[0]["scale"], 3)

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

    def test_browser_platform_uses_shared_analyzer_without_native_tools(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = make_app(Path(directory))
            report = BundleAnalyzer(platform=BrowserAnalysisPlatform()).analyze(app)

            self.assertEqual(report["capabilities"]["environment"], "browser")
            self.assertFalse(report["capabilities"]["assetutilAvailable"])
            self.assertFalse(report["capabilities"]["imageConversionSimulation"])
            self.assertFalse(report["capabilities"]["symbolStripSimulation"])
            self.assertIn("browser", report["capabilities"]["privacy"])
            self.assertEqual(report["architecture"]["targets"][0]["kind"], "App")
            self.assertEqual(report["binaries"]["count"], 1)
            self.assertEqual(report["binaries"]["items"][0]["target"], "Test App")
            html = render_report_html(report).lower()
            self.assertIn("<!doctype html>", html)
            self.assertIn('data-view="architecture"', html)
            self.assertIn('data-view="binaries"', html)
            self.assertIn('id="recommendations-count"', html)
            self.assertIn("bundle treemap", html)
            self.assertNotIn('id="map-key"', html)
            self.assertNotIn("map-recommendation-mark", html)
            self.assertIn('id="duplicate-map-key"', html)
            self.assertIn("duplication", html)
            self.assertIn("finding", html)
            self.assertIn("duplicate-type-badge", html)
            self.assertNotIn("duplicate-group-badge", html)
            self.assertNotIn("exact-duplicate", html)
            self.assertNotIn("repeated-assets", html)
            self.assertNotIn("contains-duplicates", html)
            self.assertIn("review every runtime", html)
            self.assertIn("repeated footprint", html)
            self.assertIn("worth testing", html)
            self.assertIn("data-linking-review", html)
            self.assertNotIn("review static / mergeable", html)

    def test_delivery_metrics_use_latest_iphone_catalog_estimate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = make_app(Path(directory))
            catalog = app / "Assets.car"
            catalog.write_bytes(bytes(range(250)) * 4)
            platform = BrowserAnalysisPlatform(
                catalog_results={
                    "Assets.car": {
                        "children": [],
                        "renditions": [],
                        "diagnostics": {
                            "entries": 4,
                            "deliveryEstimate": {
                                "complete": True,
                                "estimatedSize": 400,
                                "entryCount": 4,
                                "selectedEntryCount": 1,
                            },
                        },
                    }
                },
                catalog_analysis_available=True,
            )

            report = BundleAnalyzer(platform=platform).analyze(app)

            self.assertEqual(
                report["metrics"]["installSize"],
                report["metrics"]["logicalSize"] - 600,
            )
            self.assertLess(
                report["metrics"]["downloadSize"],
                report["metrics"]["compressedSize"],
            )
            self.assertEqual(
                report["metrics"]["delivery"]["assetCatalogEstimateCount"],
                1,
            )
            self.assertEqual(
                report["tree"]["installSize"],
                report["metrics"]["installSize"],
            )
            catalog_node = next(
                node
                for node in report["tree"]["children"]
                if node["name"] == "Assets.car"
            )
            self.assertEqual(catalog_node["size"], 1_000)
            self.assertEqual(catalog_node["installSize"], 400)

    def test_browser_reports_strip_and_exports_from_portable_macho_data(self) -> None:
        record = Record(
            relative_path="Example",
            absolute_path=Path("/does/not/matter"),
            size=2_000_000,
            compressed_size=1_000_000,
            allocated_size=2_002_944,
            category="binary",
            sha256="0" * 64,
            metadata={"stripSymbolEstimateBytes": 180_000},
            macho={
                "architectures": [
                    {
                        "architecture": "arm64",
                        "is_executable": True,
                        "symbol_table": {
                            "classifications": {
                                "local": {"count": 300},
                                "debug": {"count": 20},
                                "swift": {"count": 120},
                                "external_defined": {
                                    "count": 200,
                                    "entry_bytes": 3_200,
                                    "string_bytes": 15_000,
                                },
                            },
                            "strip_rSTx": {
                                "estimated_bytes": 180_000,
                                "candidate_count": 440,
                                "swift_eligible": True,
                            },
                        },
                        "export_trie": {
                            "valid": True,
                            "malformed": False,
                            "size": 8_000,
                            "symbol_count": 200,
                            "has_main": True,
                            "has_mh_execute_header": True,
                            "symbols_sample": ["_main", "_$s7Example3fooyyF"],
                        },
                    }
                ]
            },
        )
        insights: list[dict] = []
        analyzer = BundleAnalyzer(platform=BrowserAnalysisPlatform())
        analyzer._symbol_insight([record], insights)
        analyzer._exported_symbols_insight([record], insights)

        by_id = {item["id"]: item for item in insights}
        self.assertEqual(by_id["strip-symbols"]["savings"], 180_000)
        self.assertEqual(
            by_id["strip-symbols"]["items"][0]["method"],
            "portable Mach-O symbol-table estimate",
        )
        self.assertGreater(by_id["exported-symbols"]["savings"], 8_000)
        self.assertIn("strip-symbols", record.insight_ids)
        self.assertIn("exported-symbols", record.insight_ids)

    def test_binary_inventory_exposes_owners_and_measured_composition(self) -> None:
        record = Record(
            relative_path="Frameworks/Feature.framework/Feature",
            absolute_path=Path("/does/not/matter"),
            size=1_000_000,
            compressed_size=600_000,
            allocated_size=1_003_520,
            category="binary",
            sha256="0" * 64,
            metadata={
                "fileType": "dynamic-library",
                "strippedSizeEstimate": 820_000,
                "exportedSymbolMetadataEstimate": 24_000,
            },
            macho={
                "architectures": [
                    {
                        "architecture": "arm64",
                        "size": 1_000_000,
                        "file_type": "dynamic-library",
                        "platform": "iOS",
                        "minimum_os": "15.0",
                        "sdk": "18.0",
                        "encrypted": True,
                        "segments": [
                            {
                                "name": "__TEXT",
                                "size": 700_000,
                                "virtual_size": 720_000,
                                "file_offset": 0,
                                "sections": [
                                    {
                                        "name": "__text",
                                        "size": 620_000,
                                        "virtual_size": 620_000,
                                    }
                                ],
                            }
                        ],
                        "symbol_table": {
                            "strip_rSTx": {"estimated_bytes": 175_000}
                        },
                    }
                ]
            },
        )
        inventory = _binary_inventory(
            [record],
            [
                {
                    "name": "Example",
                    "path": "",
                    "kind": "App",
                }
            ],
        )

        self.assertEqual(inventory["count"], 1)
        binary = inventory["items"][0]
        self.assertTrue(binary["parsed"])
        self.assertEqual(binary["owner"], "Feature")
        self.assertEqual(binary["target"], "Example")
        self.assertEqual(binary["stripSymbolsBytes"], 180_000)
        self.assertEqual(binary["exportedSymbolMetadataBytes"], 24_000)
        self.assertTrue(binary["encrypted"])
        self.assertEqual(binary["architectures"][0]["minimumOS"], "15.0")
        segment = binary["architectures"][0]["segments"][0]
        self.assertEqual(segment["sections"][0]["name"], "__text")
        self.assertEqual(segment["unattributedSize"], 80_000)

    def test_binary_inventory_keeps_unreadable_macho_candidates(self) -> None:
        record = Record(
            relative_path="Broken",
            absolute_path=Path("/does/not/matter"),
            size=512,
            compressed_size=400,
            allocated_size=4096,
            category="binary",
            sha256="0" * 64,
            metadata={"machoCandidate": True, "machoParseFailed": True},
        )

        inventory = _binary_inventory(
            [record],
            [{"name": "Example", "path": "", "kind": "App"}],
        )

        self.assertEqual(inventory["count"], 1)
        self.assertFalse(inventory["items"][0]["parsed"])
        self.assertEqual(inventory["items"][0]["architectures"], [])

    def test_browser_catalog_measurements_feed_duplicates_and_images(self) -> None:
        catalog_result = {
            "children": [
                {
                    "name": "Header",
                    "path": "Assets.car::Header",
                    "kind": "asset",
                    "category": "asset_catalog",
                    "size": 200_000,
                    "compressedSize": 200_000,
                    "allocatedSize": 200_000,
                    "children": [],
                    "metadata": {"assetType": "image", "renditionCount": 2},
                    "insights": [],
                }
            ],
            "renditions": [
                {
                    "entryPath": "Assets.car::Header",
                    "name": "Header",
                    "path": "Assets.car::Header",
                    "displayPath": "Assets.car::Header/one",
                    "size": 100_000,
                    "digest": "a" * 64,
                    "assetType": "image",
                    "pixelWidth": 1200,
                    "pixelHeight": 800,
                    "scale": 3,
                    "physical": True,
                    "optimizedSize": 60_000,
                    "optimizationMethod": "JPEG quality 85",
                    "thumbnailDataURL": "data:image/webp;base64,UklGRg==",
                },
                {
                    "entryPath": "Assets.car::Header",
                    "name": "Header",
                    "path": "Assets.car::Header",
                    "displayPath": "Assets.car::Header/two",
                    "size": 100_000,
                    "digest": "a" * 64,
                    "assetType": "image",
                    "pixelWidth": 1200,
                    "pixelHeight": 800,
                    "scale": 2,
                    "physical": True,
                    "optimizedSize": 70_000,
                    "optimizationMethod": "JPEG quality 85",
                },
            ],
            "diagnostics": {
                "entries": 2,
                "supportedOutputs": 2,
                "unsupportedOutputs": 0,
                "duplicateDigestCount": 2,
            },
        }
        platform = BrowserAnalysisPlatform(
            catalog_results={"Assets.car": catalog_result},
            catalog_analysis_available=True,
            image_analysis_available=True,
        )
        children, renditions = platform.asset_catalog(
            Path("/temporary/Test.app/Assets.car"), "Assets.car"
        )
        catalog = Record(
            relative_path="Assets.car",
            absolute_path=Path("/temporary/Test.app/Assets.car"),
            size=210_000,
            compressed_size=200_000,
            allocated_size=212_992,
            category="asset_catalog",
            sha256="1" * 64,
            virtual_children=children,
        )
        insights: list[dict] = []
        analyzer = BundleAnalyzer(platform=platform)
        analyzer._duplicate_insight([catalog], renditions, insights)
        analyzer._image_insights([catalog], renditions, "18.0", insights)
        analyzer._attach_asset_rendition_metadata(renditions)

        by_id = {item["id"]: item for item in insights}
        self.assertEqual(by_id["duplicates"]["savings"], 100_000)
        self.assertEqual(by_id["optimize-images"]["savings"], 40_000)
        self.assertIn("duplicates", children[0]["insights"])
        self.assertIn("optimize-images", children[0]["insights"])
        metadata = children[0]["metadata"]
        self.assertEqual(metadata["optimizationSavingsEstimate"], 40_000)
        self.assertEqual(metadata["optimizedSizeEstimate"], 60_000)
        self.assertEqual(metadata["optimizedRenditionCount"], 1)
        self.assertEqual(metadata["headlineRendition"]["size"], 100_000)
        self.assertEqual(metadata["headlineRendition"]["scale"], 3)
        self.assertEqual(metadata["headlineRendition"]["savings"], 40_000)
        self.assertEqual(len(metadata["renditions"]), 2)
        self.assertEqual(metadata["renditions"][0]["savings"], 40_000)
        self.assertEqual(metadata["renditions"][0]["duplicateGroup"], "D1")
        self.assertEqual(metadata["renditions"][0]["duplicateType"], "asset")
        self.assertEqual(metadata["renditions"][0]["scope"], "same-runtime")
        self.assertEqual(metadata["renditions"][0]["actionability"], "candidate")
        self.assertEqual(
            metadata["thumbnailDataURL"], "data:image/webp;base64,UklGRg=="
        )

    def test_asset_rendition_metadata_is_bounded_and_image_only(self) -> None:
        image_entry = {
            "path": "Assets.car::Poster",
            "kind": "asset",
            "metadata": {"assetType": "image"},
        }
        color_entry = {
            "path": "Assets.car::Accent",
            "kind": "asset",
            "metadata": {"assetType": "color"},
        }
        reference_entry = {
            "path": "Assets.car::Reference",
            "kind": "asset",
            "metadata": {"assetType": "image"},
        }
        renditions = [
            {
                "entry": image_entry,
                "assetType": "image",
                "name": f"Poster {index}",
                "displayPath": f"Assets.car::Poster/{index}",
                "size": 1_000 + index,
                "scale": index % 3 + 1,
                "physical": True,
                "thumbnailDataURL": "data:image/svg+xml,<svg></svg>",
            }
            for index in range(30)
        ]
        renditions.append(
            {
                "entry": color_entry,
                "assetType": "color",
                "name": "Accent",
                "size": 128,
            }
        )
        renditions.extend(
            {
                "entry": reference_entry,
                "assetType": "image",
                "name": f"Reference {scale}x",
                "size": 100 * scale,
                "scale": scale,
                "physical": False,
            }
            for scale in (1, 2)
        )

        BundleAnalyzer._attach_asset_rendition_metadata(renditions)

        metadata = image_entry["metadata"]
        self.assertEqual(len(metadata["renditions"]), 24)
        self.assertEqual(metadata["renditionsOmitted"], 6)
        self.assertEqual(metadata["headlineRendition"]["scale"], 3)
        self.assertEqual(metadata["headlineRendition"]["size"], 1_029)
        self.assertEqual(reference_entry["metadata"]["headlineRendition"]["size"], 200)
        self.assertNotIn("thumbnailDataURL", metadata)
        self.assertTrue(all("path" not in item for item in metadata["renditions"]))
        self.assertNotIn("renditions", color_entry["metadata"])

    def test_required_app_icon_slots_are_not_reported_as_removable_duplicates(self) -> None:
        records = [
            Record(
                relative_path=path,
                absolute_path=Path("/temporary/Test.app") / path,
                size=15_000,
                compressed_size=12_000,
                allocated_size=16_384,
                category="image",
                sha256="f" * 64,
            )
            for path in ("AppIcon40x40@3x.png", "AppIcon60x60@2x.png")
        ]
        entry = {
            "path": "Assets.car::AppIcon",
            "insights": [],
            "metadata": {},
        }
        renditions = [
            {
                "entry": entry,
                "name": "AppIcon",
                "path": "Assets.car::AppIcon",
                "displayPath": f"Assets.car::AppIcon/slot-{index}",
                "size": 500_000,
                "digest": "e" * 64,
            }
            for index in range(2)
        ]
        insights: list[dict] = []
        BundleAnalyzer(platform=BrowserAnalysisPlatform())._duplicate_insight(
            records, renditions, insights
        )
        self.assertEqual(insights, [])
        self.assertTrue(all(record.duplicate_group is None for record in records))

    def test_binary_coverage_records_truncated_macho_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = make_app(Path(directory))
            (app / "BrokenMachO").write_bytes(b"\xcf\xfa\xed\xfe")
            report = BundleAnalyzer(
                platform=BrowserAnalysisPlatform()
            ).analyze(app)
            coverage = report["capabilities"]["binaryAnalysisCoverage"]
            self.assertGreaterEqual(coverage["candidateCount"], 2)
            self.assertEqual(coverage["candidateCount"] - coverage["parsedCount"], 1)

    def test_reports_declared_capabilities_and_privacy_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = make_app(Path(directory))
            info_path = app / "Info.plist"
            with info_path.open("rb") as handle:
                info = plistlib.load(handle)
            info.update(
                {
                    "NSCameraUsageDescription": "Scan documents",
                    "UIBackgroundModes": ["audio", "remote-notification"],
                    "CFBundleURLTypes": [{"CFBundleURLSchemes": ["openbundle"]}],
                    "UIRequiredDeviceCapabilities": ["arm64", "gps"],
                }
            )
            with info_path.open("wb") as handle:
                plistlib.dump(info, handle)

            privacy = {
                "NSPrivacyTracking": True,
                "NSPrivacyTrackingDomains": ["metrics.example.com"],
                "NSPrivacyAccessedAPITypes": [
                    {
                        "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPICategoryFileTimestamp",
                        "NSPrivacyAccessedAPITypeReasons": ["C617.1"],
                    }
                ],
                "NSPrivacyCollectedDataTypes": [
                    {
                        "NSPrivacyCollectedDataType": "NSPrivacyCollectedDataTypeEmailAddress",
                        "NSPrivacyCollectedDataTypePurposes": ["NSPrivacyCollectedDataTypePurposeAppFunctionality"],
                        "NSPrivacyCollectedDataTypeLinked": True,
                        "NSPrivacyCollectedDataTypeTracking": False,
                    }
                ],
            }
            with (app / "PrivacyInfo.xcprivacy").open("wb") as handle:
                plistlib.dump(privacy, handle)

            profile = {
                "Entitlements": {
                    "com.apple.developer.associated-domains": ["applinks:example.com"],
                    "com.apple.security.application-groups": ["group.com.example.test"],
                }
            }
            (app / "embedded.mobileprovision").write_bytes(
                b"CMS-prefix" + plistlib.dumps(profile) + b"CMS-suffix"
            )

            extension = app / "PlugIns" / "Share.appex"
            extension.mkdir(parents=True)
            with (extension / "Info.plist").open("wb") as handle:
                plistlib.dump(
                    {
                        "CFBundleDisplayName": "Share",
                        "CFBundleIdentifier": "com.example.test.share",
                        "NSExtension": {
                            "NSExtensionPointIdentifier": "com.apple.share-services"
                        },
                    },
                    handle,
                )

            report = BundleAnalyzer().analyze(app)
            declarations = report["capabilities"]["declarations"]
            main = declarations["targets"][0]
            self.assertEqual(main["permissions"][0]["label"], "Camera")
            self.assertEqual(main["urlSchemes"], ["openbundle"])
            self.assertEqual(main["requiredDeviceCapabilities"], ["gps"])
            self.assertEqual(
                {item["label"] for item in main["entitlements"]},
                {"App Groups", "Associated domains"},
            )
            self.assertEqual(declarations["targets"][1]["kind"], "Extension")
            manifest = declarations["privacyManifests"][0]
            self.assertTrue(manifest["tracking"])
            self.assertEqual(manifest["trackingDomains"], ["metrics.example.com"])
            self.assertEqual(manifest["accessedAPIs"][0]["reasons"], ["C617.1"])
            self.assertTrue(manifest["collectedData"][0]["linked"])

    def test_target_executable_entitlements_feed_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = make_app(Path(directory))
            with (app / "Info.plist").open("rb") as handle:
                info = plistlib.load(handle)
            binary = Record(
                relative_path="Test",
                absolute_path=app / "Test",
                size=1,
                compressed_size=1,
                allocated_size=4096,
                category="binary",
                sha256="0" * 64,
                macho={
                    "entitlements": [
                        {
                            "com.apple.developer.associated-domains": [
                                "applinks:example.com"
                            ],
                            "com.apple.developer.networking.multicast": True,
                        }
                    ]
                },
            )

            declarations = _collect_capability_declarations(
                app, app.name, info, [binary]
            )

            self.assertEqual(
                {item["label"] for item in declarations["targets"][0]["entitlements"]},
                {"Associated domains", "Multicast networking"},
            )

    def test_locales_separate_app_and_component_content_and_compare_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = make_app(Path(directory))
            english = app / "en.lproj"
            french = app / "fr.lproj"
            base = app / "Base.lproj"
            english.mkdir()
            french.mkdir()
            base.mkdir()
            (english / "Localizable.strings").write_text(
                '"hello" = "Hello";\n"same" = "Same";\n"onlyEnglish" = "Missing";\n',
                encoding="utf-8",
            )
            (french / "Localizable.strings").write_text(
                '/* Translator note */\n"hello" = "Bonjour";\n"same" = "Same";\n',
                encoding="utf-8",
            )
            (base / "Interface.strings").write_text(
                '"button" = "Button";\n', encoding="utf-8"
            )
            component = app / "Frameworks" / "Feature.framework" / "de.lproj"
            component.mkdir()
            (component / "Feature.strings").write_text(
                '"vendor" = "Abhaengigkeit";\n', encoding="utf-8"
            )

            report = BundleAnalyzer().analyze(app)
            locales = report["locales"]
            self.assertEqual(locales["localeCount"], 4)
            rows = {
                (row["bundle"], row["locale"]): row for row in locales["rows"]
            }
            french_row = rows[("Test.app", "fr")]
            self.assertEqual(french_row["source"], "app")
            self.assertEqual(french_row["referenceLocale"], "en")
            self.assertEqual(french_row["missingKeyCount"], 1)
            self.assertEqual(french_row["identicalValueCount"], 1)
            base_row = rows[("Test.app", "Base")]
            self.assertIsNone(base_row["referenceLocale"])
            self.assertIsNone(base_row["missingKeyCount"])
            component_row = rows[("Feature.framework", "de")]
            self.assertEqual(component_row["source"], "component")
            self.assertEqual(component_row["target"], "Test.app")
            self.assertIsNone(component_row["referenceLocale"])


if __name__ == "__main__":
    unittest.main()
