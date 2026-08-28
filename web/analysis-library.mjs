const DATABASE_NAME = "openbundle-analysis-library";
const DATABASE_VERSION = 1;
const METADATA_STORE = "analyses";
const PAYLOAD_STORE = "payloads";

export const LIBRARY_SCHEMA_VERSION = 1;
export const MAX_IMPORT_BYTES = 64 * 1024 * 1024;

let databasePromise;

function finiteSize(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : fallback;
}

function requestResult(request) {
  return new Promise((resolve, reject) => {
    request.addEventListener("success", () => resolve(request.result), {
      once: true,
    });
    request.addEventListener(
      "error",
      () => reject(request.error || new Error("IndexedDB request failed.")),
      { once: true },
    );
  });
}

function transactionComplete(transaction) {
  return new Promise((resolve, reject) => {
    transaction.addEventListener("complete", resolve, { once: true });
    transaction.addEventListener(
      "abort",
      () => reject(transaction.error || new Error("IndexedDB transaction was aborted.")),
      { once: true },
    );
    transaction.addEventListener(
      "error",
      () => reject(transaction.error || new Error("IndexedDB transaction failed.")),
      { once: true },
    );
  });
}

function openDatabase() {
  if (databasePromise) return databasePromise;
  databasePromise = new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") {
      reject(new Error("This browser does not provide IndexedDB."));
      return;
    }
    const request = indexedDB.open(DATABASE_NAME, DATABASE_VERSION);
    request.addEventListener("upgradeneeded", () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(METADATA_STORE)) {
        const metadata = database.createObjectStore(METADATA_STORE, {
          keyPath: "id",
        });
        metadata.createIndex("savedAt", "savedAt");
      }
      if (!database.objectStoreNames.contains(PAYLOAD_STORE)) {
        database.createObjectStore(PAYLOAD_STORE, { keyPath: "id" });
      }
    });
    request.addEventListener(
      "success",
      () => {
        const database = request.result;
        database.addEventListener("versionchange", () => database.close());
        resolve(database);
      },
      { once: true },
    );
    request.addEventListener(
      "error",
      () => {
        databasePromise = undefined;
        reject(request.error || new Error("Could not open the analysis library."));
      },
      { once: true },
    );
    request.addEventListener(
      "blocked",
      () => {
        databasePromise = undefined;
        reject(new Error("Close other OpenBundle tabs and try again."));
      },
      { once: true },
    );
  });
  return databasePromise;
}

function assertBoundedJSON(value) {
  const stack = [{ value, depth: 0 }];
  let visited = 0;
  while (stack.length) {
    const current = stack.pop();
    visited += 1;
    if (visited > 750_000) {
      throw new Error("The report contains too many values to import safely.");
    }
    if (current.depth > 80) {
      throw new Error("The report is nested too deeply to import safely.");
    }
    if (typeof current.value === "string") {
      if (current.value.length > 4 * 1024 * 1024) {
        throw new Error("The report contains an unexpectedly large text value.");
      }
      continue;
    }
    if (typeof current.value === "number" && !Number.isFinite(current.value)) {
      throw new Error("The report contains a non-finite number.");
    }
    if (!current.value || typeof current.value !== "object") continue;
    const children = Array.isArray(current.value)
      ? current.value
      : Object.values(current.value);
    if (children.length > 250_000) {
      throw new Error("The report contains an unexpectedly large collection.");
    }
    for (const child of children) {
      stack.push({ value: child, depth: current.depth + 1 });
    }
  }
}

function boundedString(value, fallback, maximum = 4096) {
  if (typeof value !== "string") return fallback;
  return value.slice(0, maximum);
}

const SAFE_IMAGE_DATA_URL = /^data:image\/(?:png|jpeg|webp);base64,[a-z0-9+/]+={0,2}$/i;

function normalizeTree(root) {
  const stack = [root];
  let count = 0;
  while (stack.length) {
    const node = stack.pop();
    count += 1;
    if (count > 250_000) {
      throw new Error("The report bundle tree contains too many nodes.");
    }
    if (!node || typeof node !== "object" || Array.isArray(node)) {
      throw new Error("The report bundle tree contains an invalid node.");
    }
    node.name = boundedString(node.name, "Unnamed", 1024);
    node.path = boundedString(node.path, "");
    for (const key of ["size", "compressedSize", "allocatedSize"]) {
      node[key] = finiteSize(node[key]);
    }
    node.installSize = finiteSize(node.installSize, node.size);
    node.downloadSize = finiteSize(node.downloadSize, node.compressedSize);
    node.children = Array.isArray(node.children) ? node.children : [];
    node.metadata =
      node.metadata && typeof node.metadata === "object" && !Array.isArray(node.metadata)
        ? node.metadata
        : {};
    node.insights = Array.isArray(node.insights) ? node.insights : [];
    for (const child of node.children) stack.push(child);
  }
}

function removeUnsafeImageURLs(value) {
  const stack = [value];
  while (stack.length) {
    const current = stack.pop();
    if (!current || typeof current !== "object") continue;
    for (const [key, child] of Object.entries(current)) {
      if (key === "iconDataURL" || key === "thumbnailDataURL") {
        if (typeof child !== "string" || !SAFE_IMAGE_DATA_URL.test(child)) {
          delete current[key];
        }
      } else if (child && typeof child === "object") {
        stack.push(child);
      }
    }
  }
}

function plainObject(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : {};
}

function objectArray(value) {
  return Array.isArray(value)
    ? value.filter(
        (item) => item && typeof item === "object" && !Array.isArray(item),
      )
    : [];
}

function arrayField(object, key) {
  object[key] = Array.isArray(object[key]) ? object[key] : [];
}

function normalizeReportCollections(input) {
  input.insights = objectArray(input.insights);
  for (const insight of input.insights) {
    arrayField(insight, "paths");
    insight.items = objectArray(insight.items);
    for (const item of insight.items) {
      arrayField(item, "paths");
      arrayField(item, "catalogPaths");
      item.variants = objectArray(item.variants);
      item.assetGroups = objectArray(item.assetGroups);
      for (const group of item.assetGroups) {
        arrayField(group, "paths");
        arrayField(group, "catalogPaths");
      }
    }
  }

  input.architecture = plainObject(input.architecture);
  input.architecture.targets = objectArray(input.architecture.targets);
  input.architecture.frameworks = objectArray(input.architecture.frameworks);
  input.architecture.linkingReviews = objectArray(
    input.architecture.linkingReviews,
  );
  input.architecture.duplicateComponents = objectArray(
    input.architecture.duplicateComponents,
  );
  input.architecture.crossTargetDuplicates = plainObject(
    input.architecture.crossTargetDuplicates,
  );
  input.architecture.crossTargetDuplicates.items = objectArray(
    input.architecture.crossTargetDuplicates.items,
  );
  for (const framework of input.architecture.frameworks) {
    arrayField(framework, "consumers");
  }
  for (const duplicate of input.architecture.duplicateComponents) {
    arrayField(duplicate, "paths");
  }
  for (const duplicate of input.architecture.crossTargetDuplicates.items) {
    arrayField(duplicate, "paths");
    arrayField(duplicate, "catalogPaths");
    duplicate.assetGroups = objectArray(duplicate.assetGroups);
    for (const group of duplicate.assetGroups) {
      arrayField(group, "paths");
      arrayField(group, "catalogPaths");
    }
  }

  input.binaries = plainObject(input.binaries);
  input.binaries.items = objectArray(input.binaries.items);
  for (const binary of input.binaries.items) {
    for (const key of [
      "architectureNames",
      "platforms",
      "minimumOSVersions",
      "sdkVersions",
    ]) {
      arrayField(binary, key);
    }
    binary.architectures = objectArray(binary.architectures);
    for (const architecture of binary.architectures) {
      arrayField(architecture, "dependencies");
      architecture.segments = objectArray(architecture.segments);
      for (const segment of architecture.segments) {
        segment.sections = objectArray(segment.sections);
        const pendingSections = [...segment.sections];
        while (pendingSections.length) {
          const section = pendingSections.pop();
          section.children = objectArray(section.children);
          pendingSections.push(...section.children);
        }
      }
    }
  }

  input.locales = plainObject(input.locales);
  input.locales.rows = objectArray(input.locales.rows);

  input.capabilities = plainObject(input.capabilities);
  input.capabilities.declarations = plainObject(
    input.capabilities.declarations,
  );
  const declarations = input.capabilities.declarations;
  declarations.targets = objectArray(declarations.targets);
  declarations.privacyManifests = objectArray(declarations.privacyManifests);
  for (const target of declarations.targets) {
    for (const key of [
      "permissions",
      "backgroundModes",
      "backgroundTasks",
      "urlSchemes",
      "queriedSchemes",
      "bonjourServices",
      "transportDomains",
      "requiredDeviceCapabilities",
    ]) {
      arrayField(target, key);
    }
    target.entitlements = objectArray(target.entitlements);
    for (const entitlement of target.entitlements) {
      arrayField(entitlement, "values");
    }
  }
  for (const manifest of declarations.privacyManifests) {
    arrayField(manifest, "trackingDomains");
    manifest.accessedAPIs = objectArray(manifest.accessedAPIs);
    manifest.collectedData = objectArray(manifest.collectedData);
    for (const api of manifest.accessedAPIs) arrayField(api, "reasons");
    for (const dataType of manifest.collectedData) {
      arrayField(dataType, "purposes");
    }
  }
}

export function validateAndNormalizeReport(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("This file does not contain an OpenBundle report object.");
  }
  assertBoundedJSON(input);
  if (!input.app || typeof input.app !== "object" || Array.isArray(input.app)) {
    throw new Error("The report is missing app metadata.");
  }
  if (
    !input.metrics ||
    typeof input.metrics !== "object" ||
    Array.isArray(input.metrics)
  ) {
    throw new Error("The report is missing bundle metrics.");
  }
  if (!input.tree || typeof input.tree !== "object" || Array.isArray(input.tree)) {
    throw new Error("The report is missing its bundle tree.");
  }
  const rawSchemaVersion = input.schemaVersion;
  if (
    rawSchemaVersion != null &&
    (!Number.isInteger(Number(rawSchemaVersion)) ||
      Number(rawSchemaVersion) < 1 ||
      Number(rawSchemaVersion) > 2)
  ) {
    throw new Error("This OpenBundle report schema is not supported.");
  }
  const logicalSize = Number(input.metrics.logicalSize);
  if (!Number.isFinite(logicalSize) || logicalSize < 0) {
    throw new Error("The report has an invalid unpacked bundle size.");
  }
  const rootChildren = input.tree.children;
  if (!Array.isArray(rootChildren)) {
    throw new Error("The report bundle tree is malformed.");
  }
  const name = boundedString(input.app.name, "").trim();
  if (!name) throw new Error("The report is missing the app name.");

  // JSON parsing already gives us a detached object. Normalize the small set
  // of legacy omissions required by the current report and comparison UI.
  input.schemaVersion = rawSchemaVersion == null ? 1 : Number(rawSchemaVersion);
  input.app.name = name;
  input.app.bundleID = boundedString(input.app.bundleID, "Unknown");
  input.app.version = boundedString(input.app.version, "—", 256);
  input.app.build = boundedString(input.app.build, "—", 256);
  input.app.artifactName = boundedString(
    input.app.artifactName,
    `${name}.ipa`,
  );
  input.metrics.logicalSize = logicalSize;
  input.metrics.compressedSize = finiteSize(input.metrics.compressedSize);
  input.metrics.artifactSize = finiteSize(
    input.metrics.artifactSize,
    input.metrics.compressedSize,
  );
  input.metrics.installSize = finiteSize(
    input.metrics.installSize,
    input.metrics.logicalSize,
  );
  input.metrics.downloadSize = finiteSize(
    input.metrics.downloadSize,
    input.metrics.artifactSize,
  );
  input.categories = Array.isArray(input.categories)
    ? input.categories.filter((item) => item && typeof item === "object")
    : [];
  normalizeReportCollections(input);
  normalizeTree(input.tree);
  removeUnsafeImageURLs(input);
  return input;
}

function htmlReportText(text) {
  // Extract only the inert JSON script text. Do not construct an HTML
  // document: even an off-DOM document can initiate subresource fetches in
  // some engines.
  const match = text.match(
    /<script\b(?=[^>]*\bid\s*=\s*["']report-data["'])[^>]*>([\s\S]*?)<\/script\s*>/i,
  );
  return match?.[1] || "";
}

export function parseImportedReport(text, filename = "report") {
  if (typeof text !== "string") {
    throw new Error("The imported report could not be read as text.");
  }
  if (new Blob([text]).size > MAX_IMPORT_BYTES) {
    throw new Error("Reports larger than 64 MB are not imported.");
  }
  const trimmed = text.trim();
  if (!trimmed) throw new Error("The imported report is empty.");

  const embedded = trimmed.startsWith("<") ? htmlReportText(text) : "";
  const payload = embedded || text;
  let report;
  try {
    report = JSON.parse(payload);
  } catch {
    if (trimmed.startsWith("<")) {
      throw new Error(
        "This HTML file does not contain valid OpenBundle report data.",
      );
    }
    throw new Error("This file is not valid OpenBundle JSON.");
  }
  return {
    report: validateAndNormalizeReport(report),
    source: embedded ? "html-import" : "json-import",
    filename: boundedString(filename, "report"),
  };
}

export async function parseReportFile(file) {
  if (!file || typeof file.text !== "function") {
    throw new Error("Choose an OpenBundle HTML or JSON report.");
  }
  if (Number(file.size) > MAX_IMPORT_BYTES) {
    throw new Error("Reports larger than 64 MB are not imported.");
  }
  return parseImportedReport(await file.text(), file.name);
}

function randomID() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  return `analysis-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function metadataFor(report, options, existing = {}) {
  const savedAt = new Date().toISOString();
  const artifactName = boundedString(
    report.app.artifactName,
    `${report.app.name}.ipa`,
  );
  const hasDeliveryMetrics =
    report.metrics.delivery?.kind === "latest-iphone-thinning-estimate";
  return {
    librarySchemaVersion: LIBRARY_SCHEMA_VERSION,
    id: options.id || existing.id || randomID(),
    savedAt,
    createdAt: existing.createdAt || savedAt,
    source: boundedString(options.source, "analysis", 64),
    sourceFilename: boundedString(options.sourceFilename, artifactName),
    name: report.app.name,
    artifactName,
    bundleID: boundedString(report.app.bundleID, "Unknown"),
    version: boundedString(report.app.version, "—", 256),
    build: boundedString(report.app.build, "—", 256),
    generatedAt: boundedString(report.generatedAt, "", 256),
    modifiedAt: boundedString(report.app.modifiedAt, "", 256),
    downloadSize: finiteSize(
      report.metrics.downloadSize,
      finiteSize(
        report.metrics.artifactSize,
        finiteSize(report.metrics.compressedSize),
      ),
    ),
    ...(hasDeliveryMetrics
      ? {
          installSize: finiteSize(
            report.metrics.installSize,
            finiteSize(report.metrics.logicalSize),
          ),
          deliveryKind: "latest-iphone-thinning-estimate",
        }
      : { unpackedSize: finiteSize(report.metrics.logicalSize) }),
    schemaVersion: Number(report.schemaVersion) || 1,
  };
}

export async function saveAnalysis(reportInput, options = {}) {
  const report = validateAndNormalizeReport(reportInput);
  const database = await openDatabase();
  let existing = {};
  if (options.id) {
    existing =
      (await requestResult(
        database
          .transaction(METADATA_STORE, "readonly")
          .objectStore(METADATA_STORE)
          .get(options.id),
      )) || {};
  }
  const metadata = metadataFor(report, options, existing);
  const transaction = database.transaction(
    [METADATA_STORE, PAYLOAD_STORE],
    "readwrite",
  );
  transaction.objectStore(METADATA_STORE).put(metadata);
  // Deliberately persist report JSON only. IPA bytes and imported HTML never
  // enter browser storage; reports are re-rendered with OpenBundle's template.
  transaction.objectStore(PAYLOAD_STORE).put({ id: metadata.id, report });
  await transactionComplete(transaction);
  return metadata;
}

export async function listAnalyses() {
  const database = await openDatabase();
  const transaction = database.transaction(METADATA_STORE, "readonly");
  const records = await requestResult(
    transaction.objectStore(METADATA_STORE).getAll(),
  );
  await transactionComplete(transaction);
  return records.sort(
    (left, right) =>
      String(right.savedAt).localeCompare(String(left.savedAt)) ||
      String(left.id).localeCompare(String(right.id)),
  );
}

export async function getAnalysis(id) {
  const database = await openDatabase();
  const transaction = database.transaction(
    [METADATA_STORE, PAYLOAD_STORE],
    "readonly",
  );
  const [metadata, payload] = await Promise.all([
    requestResult(transaction.objectStore(METADATA_STORE).get(id)),
    requestResult(transaction.objectStore(PAYLOAD_STORE).get(id)),
  ]);
  await transactionComplete(transaction);
  if (!metadata || !payload?.report) return null;
  return { ...metadata, report: validateAndNormalizeReport(payload.report) };
}

export async function deleteAnalysis(id) {
  const database = await openDatabase();
  const transaction = database.transaction(
    [METADATA_STORE, PAYLOAD_STORE],
    "readwrite",
  );
  transaction.objectStore(METADATA_STORE).delete(id);
  transaction.objectStore(PAYLOAD_STORE).delete(id);
  await transactionComplete(transaction);
}

export function reportJSON(report) {
  return JSON.stringify(validateAndNormalizeReport(report), null, 2);
}
