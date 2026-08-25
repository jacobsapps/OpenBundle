function size(value) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : 0;
}

function downloadSize(report) {
  return size(
    report.metrics?.downloadSize ??
      report.metrics?.artifactSize ??
      report.metrics?.compressedSize,
  );
}

function installSize(report) {
  return size(report.metrics?.installSize ?? report.metrics?.logicalSize);
}

function metric(before, after) {
  const delta = after - before;
  return {
    before,
    after,
    delta,
    percent: before > 0 ? (delta / before) * 100 : null,
  };
}

function isBundle(node) {
  return /\.(?:framework|appex|app|bundle|xpc)$/i.test(String(node?.name || ""));
}

function componentKind(node) {
  const name = String(node?.name || "").toLowerCase();
  if (name.endsWith(".framework")) return "Framework";
  if (name.endsWith(".appex")) return "Extension";
  if (name.endsWith(".app")) return "App";
  if (name.endsWith(".xpc")) return "XPC service";
  if (name.endsWith(".bundle")) return "Resource bundle";
  if (node?.kind === "directory") return "Directory";
  return "File";
}

function entry(node) {
  return {
    key: String(node.path || node.name || ""),
    name: String(node.name || node.path || "Unnamed"),
    path: String(node.path || ""),
    kind: componentKind(node),
    size: size(node.installSize ?? node.size),
    compressedSize: size(node.downloadSize ?? node.compressedSize),
  };
}

function normalizedIdentity(value) {
  return String(value || "")
    .normalize("NFKC")
    .trim()
    .toLocaleLowerCase("en-US");
}

const CONTAINER_NAMES = new Set([
  "frameworks",
  "plugins",
  "watch",
  "appclips",
  "xpcservices",
]);

export function collectComponents(report) {
  const components = [];
  const visit = (node, depth) => {
    if (!node || typeof node !== "object") return;
    if (depth > 0 && isBundle(node)) {
      components.push(entry(node));
      return;
    }
    const children = Array.isArray(node.children) ? node.children : [];
    if (depth === 1 && !CONTAINER_NAMES.has(String(node.name || "").toLowerCase())) {
      components.push(entry(node));
      return;
    }
    for (const child of children) visit(child, depth + 1);
  };
  for (const child of report.tree?.children || []) visit(child, 1);
  return components;
}

export function collectImages(report) {
  const images = [];
  const stack = [report.tree];
  while (stack.length) {
    const node = stack.pop();
    if (!node || typeof node !== "object") continue;
    const metadata = node.metadata || {};
    const headline = metadata.headlineRendition;
    if (
      metadata.assetType === "image" &&
      headline &&
      size(headline.size) > 0
    ) {
      images.push({
        key: String(node.path || node.name || ""),
        name: String(node.name || node.path || "Image"),
        path: String(node.path || ""),
        kind: "Catalog asset",
        // One representative rendition only. Never sum 1x/2x/3x here.
        size: size(headline.size),
        compressedSize: 0,
        scale: size(headline.scale),
      });
    } else if (node.kind === "file" && node.category === "image") {
      images.push(entry(node));
    }
    for (const child of node.children || []) stack.push(child);
  }
  return images;
}

export function collectBundles(report, suffixes) {
  const endings = suffixes.map((suffix) => suffix.toLowerCase());
  const found = [];
  const stack = [report.tree];
  while (stack.length) {
    const node = stack.pop();
    if (!node || typeof node !== "object") continue;
    const name = String(node.name || "").toLowerCase();
    // The root app is already represented by the headline bundle metrics.
    // Bundle lists describe embedded frameworks and targets only.
    if (
      node !== report.tree &&
      endings.some((suffix) => name.endsWith(suffix))
    ) {
      found.push(entry(node));
    }
    for (const child of node.children || []) stack.push(child);
  }
  return found;
}

function diffEntries(beforeEntries, afterEntries, limit = 12) {
  const before = new Map(beforeEntries.map((item) => [item.key, item]));
  const after = new Map(afterEntries.map((item) => [item.key, item]));
  const added = [];
  const removed = [];
  const changed = [];
  for (const [key, current] of after) {
    const previous = before.get(key);
    if (!previous) {
      added.push({ ...current, before: 0, after: current.size, delta: current.size });
    } else if (
      previous.size !== current.size ||
      previous.consumerCount !== current.consumerCount ||
      previous.staticCandidate !== current.staticCandidate ||
      previous.consumerResolution !== current.consumerResolution ||
      previous.linking !== current.linking ||
      previous.keyCount !== current.keyCount ||
      previous.missingKeyCount !== current.missingKeyCount ||
      previous.identicalValueCount !== current.identicalValueCount
    ) {
      changed.push({
        ...current,
        before: previous.size,
        after: current.size,
        delta: current.size - previous.size,
        beforeConsumerCount: previous.consumerCount,
        afterConsumerCount: current.consumerCount,
        beforeStaticCandidate: previous.staticCandidate,
        afterStaticCandidate: current.staticCandidate,
        beforeKeyCount: previous.keyCount,
        afterKeyCount: current.keyCount,
        beforeMissingKeyCount: previous.missingKeyCount,
        afterMissingKeyCount: current.missingKeyCount,
      });
    }
  }
  for (const [key, previous] of before) {
    if (!after.has(key)) {
      removed.push({
        ...previous,
        before: previous.size,
        after: 0,
        delta: -previous.size,
      });
    }
  }
  added.sort((left, right) => right.after - left.after || left.path.localeCompare(right.path));
  removed.sort((left, right) => right.before - left.before || left.path.localeCompare(right.path));
  changed.sort(
    (left, right) =>
      Math.abs(right.delta) - Math.abs(left.delta) || left.path.localeCompare(right.path),
  );
  return {
    added: added.slice(0, limit),
    removed: removed.slice(0, limit),
    changed: changed.slice(0, limit),
    addedCount: added.length,
    removedCount: removed.length,
    changedCount: changed.length,
  };
}

function legacyLocaleEntries(report) {
  const grouped = new Map();
  const stack = [report.tree];
  while (stack.length) {
    const node = stack.pop();
    if (!node || typeof node !== "object") continue;
    if (node.kind === "file" && node.category === "localization") {
      const parts = String(node.path || "").split("/");
      const localeIndex = parts.findIndex((part) => part.toLowerCase().endsWith(".lproj"));
      if (localeIndex >= 0) {
        const locale = parts[localeIndex].slice(0, -".lproj".length);
        const bundleIndex = parts
          .slice(0, localeIndex)
          .map((part, index) => ({ part, index }))
          .filter(({ part }) => /\.(?:framework|bundle|appex|app|xpc)$/i.test(part))
          .at(-1)?.index;
        const bundlePath = Number.isInteger(bundleIndex)
          ? parts.slice(0, bundleIndex + 1).join("/")
          : ".";
        const key = `${normalizedIdentity(bundlePath)}:${normalizedIdentity(locale)}`;
        const current = grouped.get(key) || {
          key,
          name: locale,
          locale,
          path: bundlePath,
          bundlePath,
          kind: "Locale",
          size: 0,
          compressedSize: 0,
          keyCount: null,
          missingKeyCount: null,
          identicalValueCount: null,
        };
        current.size += size(node.size);
        current.compressedSize += size(node.compressedSize);
        grouped.set(key, current);
      }
    }
    for (const child of node.children || []) stack.push(child);
  }
  return [...grouped.values()];
}

function localeEntries(report) {
  if (!Array.isArray(report.locales?.rows)) return legacyLocaleEntries(report);
  return report.locales.rows.map((row) => {
    const bundlePath = String(row.bundlePath || ".");
    const locale = String(row.locale || "Unknown");
    return {
      key: `${normalizedIdentity(bundlePath)}:${normalizedIdentity(locale)}`,
      name: locale,
      locale,
      path: bundlePath,
      bundlePath,
      bundle: String(row.bundle || bundlePath),
      kind: "Locale",
      size: size(row.size),
      compressedSize: 0,
      keyCount: row.keyCount == null ? null : size(row.keyCount),
      missingKeyCount:
        row.missingKeyCount == null ? null : size(row.missingKeyCount),
      identicalValueCount:
        row.identicalValueCount == null ? null : size(row.identicalValueCount),
    };
  });
}

function targetIdentity(target) {
  const bundleID = normalizedIdentity(target.bundleID);
  if (bundleID) return `bundle:${bundleID}`;
  const path = normalizedIdentity(target.path);
  if (path) return `path:${path}`;
  return `target:${normalizedIdentity(target.kind)}:${normalizedIdentity(target.name)}`;
}

function architectureTargets(report) {
  if (!Array.isArray(report.architecture?.targets)) {
    return collectBundles(report, [".appex", ".app", ".xpc"]);
  }
  return report.architecture.targets.map((target) => ({
    key: targetIdentity(target),
    name: String(target.name || target.bundleID || "Target"),
    path: String(target.path || ""),
    kind: String(target.kind || "Target"),
    bundleID: String(target.bundleID || ""),
    size: size(target.size),
    compressedSize: size(target.compressedSize),
    fileCount: size(target.fileCount),
  }));
}

function architectureFrameworks(report) {
  if (!Array.isArray(report.architecture?.frameworks)) {
    return collectBundles(report, [".framework"]);
  }
  const targetKeys = new Map(
    (report.architecture.targets || []).map((target) => [
      String(target.path || ""),
      targetIdentity(target),
    ]),
  );
  return report.architecture.frameworks.map((framework) => {
    const owner = String(framework.owner || "");
    const relativePath = owner && String(framework.path || "").startsWith(`${owner}/`)
      ? String(framework.path).slice(owner.length + 1)
      : String(framework.path || framework.name || "");
    const ownerKey =
      targetKeys.get(owner) || `owner:${normalizedIdentity(owner || "main")}`;
    return {
      key: `${ownerKey}:${normalizedIdentity(relativePath || framework.name)}`,
      name: String(framework.name || relativePath || "Framework"),
      path: String(framework.path || ""),
      owner,
      kind: "Framework",
      size: size(framework.size),
      compressedSize: size(framework.compressedSize),
      consumerCount: size(framework.consumerCount),
      consumers: Array.isArray(framework.consumers) ? framework.consumers : [],
      consumerResolution: String(framework.consumerResolution || ""),
      staticCandidate: framework.staticCandidate === true,
      linking: String(framework.linking || "Unknown"),
    };
  });
}

function bundleDiff(before, after) {
  return {
    beforeCount: before.length,
    afterCount: after.length,
    size: metric(
      before.reduce((total, item) => total + item.size, 0),
      after.reduce((total, item) => total + item.size, 0),
    ),
    changes: diffEntries(before, after, 10),
  };
}

function recommendationDiff(beforeReport, afterReport) {
  const minimumSaving = 100_000;
  const usable = (report) =>
    new Map(
      (report.insights || [])
        .filter(
          (item) =>
            item &&
            typeof item.id === "string" &&
            Number.isFinite(Number(item.savings)) &&
            Number(item.savings) >= minimumSaving,
        )
        .map((item) => [item.id, item]),
    );
  const before = usable(beforeReport);
  const after = usable(afterReport);
  const changes = [];
  for (const [id, current] of after) {
    const previous = before.get(id);
    const currentSaving = size(current.savings);
    if (!previous) {
      changes.push({
        id,
        title: String(current.title || id),
        state: "added",
        before: 0,
        after: currentSaving,
        delta: currentSaving,
      });
      continue;
    }
    const previousSaving = size(previous.savings);
    if (previousSaving !== currentSaving || previous.title !== current.title) {
      changes.push({
        id,
        title: String(current.title || id),
        state: "changed",
        before: previousSaving,
        after: currentSaving,
        delta: currentSaving - previousSaving,
      });
    }
  }
  for (const [id, previous] of before) {
    if (!after.has(id)) {
      const previousSaving = size(previous.savings);
      changes.push({
        id,
        title: String(previous.title || id),
        state: "removed",
        before: previousSaving,
        after: 0,
        delta: -previousSaving,
      });
    }
  }
  return changes.sort(
    (left, right) =>
      Math.abs(right.delta) - Math.abs(left.delta) || left.title.localeCompare(right.title),
  );
}

function stringSet(values, project = (value) => value) {
  return [...new Set((Array.isArray(values) ? values : []).map(project).filter(Boolean))]
    .sort((left, right) => left.localeCompare(right))
    .join(", ");
}

function capabilityFacts(report) {
  const declarations = report.capabilities?.declarations || {};
  const facts = {};
  for (const target of declarations.targets || []) {
    const targetName = String(target.name || target.bundleID || target.kind || "Target");
    const identity = target.bundleID
      ? `bundle:${normalizedIdentity(target.bundleID)}`
      : target.path
        ? `path:${normalizedIdentity(target.path)}`
        : targetIdentity(target);
    const add = (label, value) => {
      if (value) {
        facts[`${identity}\u0000${label}`] = {
          label: `${targetName} — ${label}`,
          value,
        };
      }
    };
    add("Extension point", String(target.extensionPoint || ""));
    add("Permissions", stringSet(target.permissions, (item) => String(item.label || item.key || "")));
    add("Background modes", stringSet(target.backgroundModes, String));
    add("Background tasks", stringSet(target.backgroundTasks, String));
    add("URL schemes", stringSet(target.urlSchemes, String));
    add("Queried schemes", stringSet(target.queriedSchemes, String));
    add("Bonjour services", stringSet(target.bonjourServices, String));
    add("Transport domains", stringSet(target.transportDomains, String));
    add("Device capabilities", stringSet(target.requiredDeviceCapabilities, String));
    add(
      "Entitlements",
      stringSet(target.entitlements, (item) => {
        const values = stringSet(item.values, String);
        return `${item.label || item.key || "Entitlement"}${values ? ` (${values})` : ""}`;
      }),
    );
  }
  for (const manifest of declarations.privacyManifests || []) {
    const name = String(manifest.bundle || manifest.path || "Privacy manifest");
    const identity = normalizedIdentity(
      `${manifest.bundlePath || manifest.bundle || ""}:${manifest.path || ""}`,
    );
    const add = (label, value) => {
      facts[`privacy:${identity}\u0000${label}`] = {
        label: `${name} — ${label}`,
        value,
      };
    };
    add("Tracking", manifest.tracking ? "Declared" : "Not declared");
    const domains = stringSet(manifest.trackingDomains, String);
    if (domains) add("Tracking domains", domains);
    const accessed = stringSet(manifest.accessedAPIs, (item) => {
      const reasons = stringSet(item.reasons, String);
      return `${item.label || item.category || "API"}${reasons ? ` (${reasons})` : ""}`;
    });
    if (accessed) add("Accessed APIs", accessed);
    const collected = stringSet(manifest.collectedData, (item) => {
      const flags = [item.linked ? "linked" : "", item.tracking ? "tracking" : ""]
        .filter(Boolean)
        .join(", ");
      return `${item.label || item.category || "Collected data"}${flags ? ` (${flags})` : ""}`;
    });
    if (collected) add("Collected data", collected);
  }
  return facts;
}

function capabilityDiff(beforeReport, afterReport) {
  if (
    !beforeReport.capabilities?.declarations ||
    !afterReport.capabilities?.declarations
  ) {
    return [];
  }
  const before = capabilityFacts(beforeReport);
  const after = capabilityFacts(afterReport);
  return [...new Set([...Object.keys(before), ...Object.keys(after)])]
    .filter((key) => before[key]?.value !== after[key]?.value)
    .sort((left, right) => left.localeCompare(right))
    .map((key) => ({
      name: after[key]?.label || before[key]?.label || key.split("\u0000").at(-1),
      before: before[key]?.value || "Not declared",
      after: after[key]?.value || "Not declared",
    }));
}

export function compareReports(beforeReport, afterReport) {
  const architectureAvailable =
    Array.isArray(beforeReport.architecture?.frameworks) &&
    Array.isArray(beforeReport.architecture?.targets) &&
    Array.isArray(afterReport.architecture?.frameworks) &&
    Array.isArray(afterReport.architecture?.targets);
  const beforeFrameworks = architectureAvailable
    ? architectureFrameworks(beforeReport)
    : collectBundles(beforeReport, [".framework"]);
  const afterFrameworks = architectureAvailable
    ? architectureFrameworks(afterReport)
    : collectBundles(afterReport, [".framework"]);
  const beforeTargets = architectureAvailable
    ? architectureTargets(beforeReport)
    : collectBundles(beforeReport, [".appex", ".app", ".xpc"]);
  const afterTargets = architectureAvailable
    ? architectureTargets(afterReport)
    : collectBundles(afterReport, [".appex", ".app", ".xpc"]);
  return {
    deliveryMetricsAvailable: Boolean(
      beforeReport.metrics?.delivery?.kind ===
        "latest-iphone-thinning-estimate" &&
        afterReport.metrics?.delivery?.kind ===
          "latest-iphone-thinning-estimate",
    ),
    metrics: {
      download: metric(downloadSize(beforeReport), downloadSize(afterReport)),
      install: metric(installSize(beforeReport), installSize(afterReport)),
    },
    components: diffEntries(
      collectComponents(beforeReport),
      collectComponents(afterReport),
    ),
    images: diffEntries(collectImages(beforeReport), collectImages(afterReport)),
    frameworks: bundleDiff(
      beforeFrameworks,
      afterFrameworks,
    ),
    targets: bundleDiff(
      beforeTargets,
      afterTargets,
    ),
    locales: bundleDiff(
      localeEntries(beforeReport),
      localeEntries(afterReport),
    ),
    recommendations: recommendationDiff(beforeReport, afterReport),
    capabilities: capabilityDiff(beforeReport, afterReport),
    capabilitiesAvailable: Boolean(
      beforeReport.capabilities?.declarations &&
        afterReport.capabilities?.declarations,
    ),
  };
}
