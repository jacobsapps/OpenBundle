import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  parseImportedReport,
  validateAndNormalizeReport,
} from "../web/analysis-library.mjs";
import { compareReports } from "../web/analysis-compare.mjs";

function node(name, path, size, children = [], kind = "directory") {
  return {
    name,
    path,
    kind,
    category: kind === "file" ? "other" : "binary",
    size,
    compressedSize: Math.floor(size * 0.7),
    allocatedSize: size,
    children,
    metadata: {},
    insights: [],
  };
}

function report({ download = 800, unpacked = 1000, children = [], insights = [] } = {}) {
  return {
    schemaVersion: 2,
    generatedAt: "2026-08-20T00:00:00Z",
    app: {
      name: "Example",
      bundleID: "com.example.app",
      version: "1.0",
      build: "1",
      artifactName: "Example.ipa",
    },
    metrics: {
      artifactSize: download,
      compressedSize: download - 10,
      logicalSize: unpacked,
    },
    categories: [],
    insights,
    capabilities: {
      binaryAnalysisCoverage: { parsedCount: 2, candidateCount: 2 },
      assetCatalogCoverage: { parsedCatalogCount: 1, catalogCount: 1 },
      imageConversionAvailable: true,
    },
    tree: node("Example.app", "", unpacked, children),
  };
}

test("imports raw OpenBundle JSON and normalizes a legacy schema marker", () => {
  const value = report();
  delete value.schemaVersion;
  const imported = parseImportedReport(JSON.stringify(value), "example.json");
  assert.equal(imported.source, "json-import");
  assert.equal(imported.filename, "example.json");
  assert.equal(imported.report.schemaVersion, 1);
  assert.equal(imported.report.metrics.logicalSize, 1000);
  assert.equal(imported.report.metrics.installSize, 1000);
  assert.equal(imported.report.metrics.downloadSize, 800);
  assert.equal(imported.report.tree.installSize, 1000);
});

test("comparison prefers delivery download and install metrics", () => {
  const before = report({ download: 800, unpacked: 1_000 });
  const after = report({ download: 900, unpacked: 1_200 });
  before.metrics.downloadSize = 500;
  before.metrics.installSize = 700;
  after.metrics.downloadSize = 550;
  after.metrics.installSize = 770;

  const comparison = compareReports(before, after);
  assert.deepEqual(comparison.metrics.download, {
    before: 500,
    after: 550,
    delta: 50,
    percent: 10,
  });
  assert.deepEqual(comparison.metrics.install, {
    before: 700,
    after: 770,
    delta: 70,
    percent: 10,
  });
});

test("extracts report JSON from HTML without executing imported scripts", () => {
  globalThis.__openbundleImportExecuted = false;
  const payload = JSON.stringify(report()).replaceAll("<", "\\u003c");
  const html = `<!doctype html><script>globalThis.__openbundleImportExecuted=true</script>
    <script type="application/json" id="report-data">${payload}</script>`;
  const imported = parseImportedReport(html, "report.html");
  assert.equal(imported.source, "html-import");
  assert.equal(imported.report.app.name, "Example");
  assert.equal(globalThis.__openbundleImportExecuted, false);
  delete globalThis.__openbundleImportExecuted;
});

test("rejects corrupt JSON, arbitrary HTML, and malformed report shapes", () => {
  assert.throws(
    () => parseImportedReport("{broken", "broken.json"),
    /not valid OpenBundle JSON/,
  );
  assert.throws(
    () => parseImportedReport("<h1>Not a report</h1>", "page.html"),
    /does not contain valid OpenBundle report data/,
  );
  assert.throws(
    () => validateAndNormalizeReport({ app: {}, metrics: {}, tree: {} }),
    /bundle tree is malformed|invalid unpacked bundle size/,
  );
  const unsupported = report();
  unsupported.schemaVersion = 99;
  assert.throws(
    () => validateAndNormalizeReport(unsupported),
    /schema is not supported/,
  );
});

test("removes imported image URLs outside OpenBundle's bounded data formats", () => {
  const value = report();
  value.app.iconDataURL = "https://tracker.invalid/icon.png";
  value.tree.metadata.thumbnailDataURL = "data:image/svg+xml,<svg></svg>";
  validateAndNormalizeReport(value);
  assert.equal(value.app.iconDataURL, undefined);
  assert.equal(value.tree.metadata.thumbnailDataURL, undefined);
});

test("produces deterministic metric, component, framework, target, and recommendation diffs", () => {
  const before = report({
    download: 800,
    unpacked: 1000,
    children: [
      node("Frameworks", "Frameworks", 300, [
        node("Foo.framework", "Frameworks/Foo.framework", 300),
      ]),
      node("Old.dat", "Old.dat", 200, [], "file"),
      node("PlugIns", "PlugIns", 100, [
        node("Widget.appex", "PlugIns/Widget.appex", 100),
      ]),
    ],
    insights: [{ id: "duplicates", title: "Duplicates", savings: 120_000 }],
  });
  const after = report({
    download: 900,
    unpacked: 1200,
    children: [
      node("Frameworks", "Frameworks", 550, [
        node("Foo.framework", "Frameworks/Foo.framework", 350),
        node("Bar.framework", "Frameworks/Bar.framework", 200),
      ]),
      node("New.dat", "New.dat", 250, [], "file"),
      node("PlugIns", "PlugIns", 140, [
        node("Widget.appex", "PlugIns/Widget.appex", 140),
      ]),
    ],
    insights: [
      { id: "duplicates", title: "Duplicates", savings: 80_000 },
      { id: "strip-symbols", title: "Strip symbols", savings: 150_000 },
    ],
  });

  const comparison = compareReports(before, after);
  assert.deepEqual(comparison.metrics.download, {
    before: 800,
    after: 900,
    delta: 100,
    percent: 12.5,
  });
  assert.equal(comparison.components.added[0].path, "New.dat");
  assert.equal(comparison.components.removed[0].path, "Old.dat");
  assert.equal(
    comparison.components.changed[0].path,
    "Frameworks/Foo.framework",
  );
  assert.equal(comparison.frameworks.beforeCount, 1);
  assert.equal(comparison.frameworks.afterCount, 2);
  assert.equal(comparison.frameworks.changes.added[0].name, "Bar.framework");
  assert.equal(comparison.targets.changes.changed[0].delta, 40);
  assert.deepEqual(
    comparison.recommendations.map((item) => item.id),
    ["strip-symbols", "duplicates"],
  );
  assert.deepEqual(comparison.recommendations[1], {
    id: "duplicates",
    title: "Duplicates",
    state: "removed",
    before: 120_000,
    after: 0,
    delta: -120_000,
  });
});

test("comparison ignores recommendations without material measured savings", () => {
  const before = report({
    insights: [
      { id: "missing", title: "Missing", savings: null },
      { id: "tiny", title: "Tiny", savings: 99_999 },
      { id: "boundary", title: "Boundary", savings: 100_000 },
    ],
  });
  const after = report({
    insights: [
      { id: "missing", title: "Missing", savings: 0 },
      { id: "tiny", title: "Tiny", savings: 50_000 },
      { id: "boundary", title: "Boundary", savings: 110_000 },
    ],
  });
  assert.deepEqual(compareReports(before, after).recommendations, [
    {
      id: "boundary",
      title: "Boundary",
      state: "changed",
      before: 100_000,
      after: 110_000,
      delta: 10_000,
    },
  ]);
});

test("uses stable architecture identities and compares declared product capabilities", () => {
  const before = report();
  const after = report();
  before.architecture = {
    targets: [
      {
        name: "Share",
        path: "PlugIns/OldShare.appex",
        kind: "Share extension",
        bundleID: "com.example.share",
        size: 400,
      },
    ],
    frameworks: [
      {
        name: "Feature",
        path: "PlugIns/OldShare.appex/Frameworks/Feature.framework",
        owner: "PlugIns/OldShare.appex",
        size: 200,
        consumerCount: 1,
        staticCandidate: true,
        consumerResolution: "Resolved",
        linking: "Dynamic",
      },
    ],
  };
  after.architecture = {
    targets: [
      {
        name: "Sharing",
        path: "PlugIns/NewShare.appex",
        kind: "Share extension",
        bundleID: "com.example.share",
        size: 450,
      },
    ],
    frameworks: [
      {
        name: "Feature",
        path: "PlugIns/NewShare.appex/Frameworks/Feature.framework",
        owner: "PlugIns/NewShare.appex",
        size: 200,
        consumerCount: 2,
        staticCandidate: false,
        consumerResolution: "Resolved",
        linking: "Dynamic",
      },
    ],
  };
  before.capabilities = {
    binaryAnalysisCoverage: { parsedCount: 1, candidateCount: 5 },
    declarations: {
      targets: [
        {
          name: "Share",
          bundleID: "com.example.share",
          permissions: [{ label: "Camera" }],
        },
      ],
      privacyManifests: [
        { bundle: "Alpha.framework", bundlePath: "Frameworks/Alpha.framework", path: "Frameworks/Alpha.framework/PrivacyInfo.xcprivacy", tracking: false },
        { bundle: "Beta.framework", bundlePath: "Frameworks/Beta.framework", path: "Frameworks/Beta.framework/PrivacyInfo.xcprivacy", tracking: false },
      ],
    },
  };
  after.capabilities = {
    binaryAnalysisCoverage: { parsedCount: 5, candidateCount: 5 },
    declarations: {
      targets: [
        {
          name: "Sharing",
          bundleID: "com.example.share",
          permissions: [{ label: "Camera" }, { label: "Microphone" }],
        },
      ],
      privacyManifests: [
        { bundle: "Alpha.framework", bundlePath: "Frameworks/Alpha.framework", path: "Frameworks/Alpha.framework/PrivacyInfo.xcprivacy", tracking: true },
        { bundle: "Beta.framework", bundlePath: "Frameworks/Beta.framework", path: "Frameworks/Beta.framework/PrivacyInfo.xcprivacy", tracking: false },
      ],
    },
  };

  const comparison = compareReports(before, after);
  assert.equal(comparison.targets.changes.addedCount, 0);
  assert.equal(comparison.targets.changes.removedCount, 0);
  assert.equal(comparison.targets.changes.changed[0].delta, 50);
  assert.equal(comparison.frameworks.changes.addedCount, 0);
  assert.equal(comparison.frameworks.changes.removedCount, 0);
  assert.equal(comparison.frameworks.changes.changed[0].delta, 0);
  assert.equal(comparison.frameworks.changes.changed[0].beforeConsumerCount, 1);
  assert.equal(comparison.frameworks.changes.changed[0].afterConsumerCount, 2);
  assert.deepEqual(
    comparison.capabilities.map((item) => item.name),
    ["Sharing — Permissions", "Alpha.framework — Tracking"],
  );
  assert.equal(
    comparison.capabilities.some((item) => item.name === "Binary parsing"),
    false,
  );
});

test("compares representative image renditions and stable locale rows", () => {
  const beforeAsset = node(
    "Poster",
    "Assets.car::Poster",
    600,
    [],
    "asset",
  );
  beforeAsset.metadata = {
    assetType: "image",
    headlineRendition: { size: 100, scale: 3 },
  };
  const afterAsset = structuredClone(beforeAsset);
  afterAsset.size = 900;
  afterAsset.metadata.headlineRendition.size = 120;
  const before = report({ children: [beforeAsset] });
  const after = report({ children: [afterAsset] });
  before.locales = {
    rows: [
      {
        bundlePath: ".",
        bundle: "Example.app",
        locale: "en",
        size: 10,
        keyCount: 4,
        missingKeyCount: 0,
      },
    ],
  };
  after.locales = {
    rows: [
      {
        bundlePath: ".",
        bundle: "Example.app",
        locale: "en",
        size: 12,
        keyCount: 5,
        missingKeyCount: 1,
      },
      {
        bundlePath: ".",
        bundle: "Example.app",
        locale: "fr",
        size: 11,
        keyCount: 5,
        missingKeyCount: 0,
      },
    ],
  };

  const comparison = compareReports(before, after);
  assert.equal(comparison.images.changed[0].delta, 20);
  assert.equal(comparison.images.changed[0].before, 100);
  assert.equal(comparison.images.changed[0].after, 120);
  assert.equal(comparison.locales.changes.added[0].name, "fr");
  assert.equal(comparison.locales.changes.changed[0].name, "en");
  assert.equal(comparison.locales.changes.changed[0].beforeKeyCount, 4);
  assert.equal(comparison.locales.changes.changed[0].afterMissingKeyCount, 1);
});

test("does not turn newer analysis coverage into product changes", () => {
  const frameworkTree = node("Frameworks", "Frameworks", 200, [
    node("Feature.framework", "Frameworks/Feature.framework", 200),
  ]);
  const before = report({ children: [frameworkTree] });
  const after = report({ children: [structuredClone(frameworkTree)] });
  after.architecture = {
    targets: [
      {
        name: "Example",
        path: "",
        kind: "App",
        bundleID: "com.example.app",
        size: 1000,
      },
    ],
    frameworks: [
      {
        name: "Feature",
        path: "Frameworks/Feature.framework",
        owner: "",
        size: 200,
      },
    ],
  };
  after.capabilities.declarations = {
    targets: [
      {
        name: "Example",
        bundleID: "com.example.app",
        permissions: [{ label: "Camera" }],
      },
    ],
    privacyManifests: [],
  };

  const comparison = compareReports(before, after);
  assert.equal(comparison.frameworks.changes.addedCount, 0);
  assert.equal(comparison.frameworks.changes.removedCount, 0);
  assert.equal(comparison.frameworks.changes.changedCount, 0);
  assert.equal(comparison.capabilitiesAvailable, false);
  assert.deepEqual(comparison.capabilities, []);
});

test("keeps same-named targets distinct by bundle path", () => {
  const before = report();
  const after = report();
  before.architecture = {
    targets: [
      { name: "Widget", path: "PlugIns/A.appex", kind: "Widget", size: 100 },
      { name: "Widget", path: "PlugIns/B.appex", kind: "Widget", size: 200 },
    ],
    frameworks: [],
  };
  after.architecture = {
    targets: [
      { name: "Widget", path: "PlugIns/A.appex", kind: "Widget", size: 150 },
      { name: "Widget", path: "PlugIns/B.appex", kind: "Widget", size: 250 },
    ],
    frameworks: [],
  };

  const changes = compareReports(before, after).targets.changes.changed;
  assert.equal(changes.length, 2);
  assert.deepEqual(
    changes.map((item) => item.path).sort(),
    ["PlugIns/A.appex", "PlugIns/B.appex"],
  );
  assert.equal(changes.reduce((total, item) => total + item.delta, 0), 100);
});

test("normalizes malformed nested renderer collections", () => {
  const value = report();
  value.insights = [
    {
      id: "duplicates",
      savings: 120_000,
      paths: "root.dat",
      items: [{
        paths: "copy.dat",
        catalogPaths: "Assets.car",
        variants: "2x",
        assetGroups: [{ paths: "asset.png", catalogPaths: "Assets.car" }],
      }],
    },
  ];
  value.capabilities.declarations = {
    targets: [{ permissions: "Camera", entitlements: [{ values: "value" }] }],
    privacyManifests: [
      {
        trackingDomains: "tracker.example",
        accessedAPIs: [{ reasons: "reason" }],
        collectedData: [{ purposes: "purpose" }],
      },
    ],
  };
  value.architecture = {
    targets: [],
    frameworks: [{ consumers: "App" }],
    linkingReviews: "Framework",
    duplicateComponents: [{ paths: "A.framework" }],
    crossTargetDuplicates: { items: [{ paths: "shared.js" }] },
  };
  value.binaries = {
    items: [{ architectures: [{ dependencies: "A", segments: [{ sections: "B" }] }] }],
  };
  value.locales = { rows: "en" };

  const normalized = validateAndNormalizeReport(value);
  assert.deepEqual(normalized.insights[0].paths, []);
  assert.deepEqual(normalized.insights[0].items[0].paths, []);
  assert.deepEqual(normalized.insights[0].items[0].catalogPaths, []);
  assert.deepEqual(normalized.insights[0].items[0].variants, []);
  assert.deepEqual(normalized.insights[0].items[0].assetGroups[0].paths, []);
  assert.deepEqual(normalized.insights[0].items[0].assetGroups[0].catalogPaths, []);
  assert.deepEqual(normalized.capabilities.declarations.targets[0].permissions, []);
  assert.deepEqual(normalized.capabilities.declarations.targets[0].entitlements[0].values, []);
  assert.deepEqual(normalized.capabilities.declarations.privacyManifests[0].accessedAPIs[0].reasons, []);
  assert.deepEqual(normalized.architecture.frameworks[0].consumers, []);
  assert.deepEqual(normalized.architecture.linkingReviews, []);
  assert.deepEqual(normalized.architecture.crossTargetDuplicates.items[0].paths, []);
  assert.deepEqual(normalized.binaries.items[0].architectures[0].segments[0].sections, []);
  assert.deepEqual(normalized.locales.rows, []);
});

test("persistence and comparison modules contain no cookie, local-storage, or network calls", async () => {
  const sources = await Promise.all([
    readFile(new URL("../web/analysis-library.mjs", import.meta.url), "utf8"),
    readFile(new URL("../web/analysis-compare.mjs", import.meta.url), "utf8"),
  ]);
  for (const source of sources) {
    assert.doesNotMatch(source, /document\.cookie|localStorage|sessionStorage/);
    assert.doesNotMatch(source, /\bfetch\s*\(|XMLHttpRequest|new\s+WebSocket/);
    assert.doesNotMatch(source, /DOMParser/);
  }
});
