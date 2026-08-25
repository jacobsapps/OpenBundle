import {
  deleteAnalysis,
  getAnalysis,
  listAnalyses,
  parseImportedReport,
  parseReportFile,
  reportJSON,
  saveAnalysis,
} from "./analysis-library.mjs";
import { compareReports } from "./analysis-compare.mjs";

const input = document.querySelector("#artifact-input");
const dropZone = document.querySelector("#drop-zone");
const status = document.querySelector("#status");
const statusText = document.querySelector("#status-text");
const cancelAnalysis = document.querySelector("#cancel-analysis");
const analyzer = document.querySelector("#analyzer");
const result = document.querySelector("#result");
const reportFrame = document.querySelector("#report-frame");
const analyzeAnother = document.querySelector("#analyze-another");
const downloadReport = document.querySelector("#download-report");
const library = document.querySelector("#analysis-library");
const libraryList = document.querySelector("#library-list");
const libraryMessage = document.querySelector("#library-message");
const importInput = document.querySelector("#report-import-input");
const importReport = document.querySelector("#import-report");
const comparePrompt = document.querySelector("#compare-prompt");
const comparePromptTitle = document.querySelector("#compare-prompt-title");
const compareAnalyze = document.querySelector("#compare-analyze");
const compareImport = document.querySelector("#compare-import");
const compareCancel = document.querySelector("#compare-cancel");
const comparison = document.querySelector("#comparison");
const comparisonTitle = document.querySelector("#comparison-title");
const comparisonSubtitle = document.querySelector("#comparison-subtitle");
const comparisonContent = document.querySelector("#comparison-content");
const comparisonBack = document.querySelector("#comparison-back");
const comparisonSwap = document.querySelector("#comparison-swap");
const comparisonOpenBefore = document.querySelector("#comparison-open-before");
const comparisonOpenAfter = document.querySelector("#comparison-open-after");

const MAX_BROWSER_ARCHIVE_BYTES = 700 * 1024 * 1024;

let currentReport = "";
let currentStem = "openbundle-report";
let currentAnalysis = null;
let recentAnalyses = [];
let baselineID = null;
let comparisonPair = null;
let worker = null;
let workerOperation = "idle";
let operationSequence = 0;
let activeOperationID = 0;
let renderRequestID = 0;
const pendingRenders = new Map();

function workerBusy() {
  return workerOperation !== "idle";
}

function setWorkerOperation(operation) {
  workerOperation = operation;
  const busy = workerBusy();
  dropZone.disabled = busy;
  cancelAnalysis.hidden = operation !== "analyze";
  for (const button of [
    importReport,
    compareAnalyze,
    compareImport,
    comparisonOpenBefore,
    comparisonOpenAfter,
  ]) {
    button.disabled = busy;
  }
  libraryList
    .querySelectorAll("button[data-action]")
    .forEach((button) => (button.disabled = busy));
}

function beginWorkerOperation(operation) {
  activeOperationID = ++operationSequence;
  setWorkerOperation(operation);
  return activeOperationID;
}

function finishWorkerOperation(operationID) {
  if (activeOperationID !== operationID) return false;
  activeOperationID = 0;
  setWorkerOperation("idle");
  return true;
}

function terminateWorker(target = worker) {
  if (!target) return;
  if (worker === target) worker = null;
  target.terminate();
}

function resetWorkerOperation(target = worker) {
  terminateWorker(target);
  activeOperationID = 0;
  pendingRenders.clear();
  setWorkerOperation("idle");
}

function focusDropZone() {
  window.requestAnimationFrame(() => dropZone.focus());
}

function failWorkerOperation(target, message) {
  if (target && target !== worker) return;
  const operation = workerOperation;
  resetWorkerOperation(target);
  const detail = message || "The browser analyzer stopped unexpectedly.";
  if (operation === "render") {
    setLibraryMessage(detail, "error");
  } else {
    input.value = "";
    setStatus(detail, "error");
  }
}

function handleWorkerMessage(target, { data }) {
  if (target !== worker) return;
  if (!data || typeof data !== "object") {
    failWorkerOperation(
      target,
      "The browser analyzer returned an unreadable response.",
    );
    return;
  }
  if (data.type === "progress") {
    if (workerOperation === "render") setLibraryMessage(data.message);
    else if (workerOperation === "analyze") setStatus(data.message, "working");
    return;
  }
  if (data.type === "rendered") {
    if (workerOperation !== "render") return;
    const record = pendingRenders.get(data.requestID);
    if (!record) {
      failWorkerOperation(
        target,
        "The saved report returned an unexpected response.",
      );
      return;
    }
    const operationID = activeOperationID;
    pendingRenders.clear();
    terminateWorker(target);
    finishWorkerOperation(operationID);
    setLibraryMessage("");
    showReport(data.html, record);
    return;
  }
  if (data.type === "render-error") {
    if (workerOperation !== "render") return;
    if (!pendingRenders.has(data.requestID)) {
      failWorkerOperation(
        target,
        "The saved report returned an unexpected response.",
      );
      return;
    }
    resetWorkerOperation(target);
    setLibraryMessage(
      data.message || "The saved report could not be rendered.",
      "error",
    );
    return;
  }
  if (data.type === "error") {
    failWorkerOperation(target, data.message);
    return;
  }
  if (data.type !== "result" || workerOperation !== "analyze") return;

  const operationID = activeOperationID;
  terminateWorker(target);
  setWorkerOperation("saving");
  setStatus("");
  void handleAnalysisResult(data)
    .catch((error) => {
      input.value = "";
      setStatus(error instanceof Error ? error.message : String(error), "error");
      focusDropZone();
    })
    .finally(() => finishWorkerOperation(operationID));
}

function createWorker() {
  if (worker) return worker;
  const created = new Worker(
    new URL("./analyzer-worker.mjs", import.meta.url),
    { type: "module" },
  );
  worker = created;
  created.addEventListener("message", (event) => {
    handleWorkerMessage(created, event);
  });
  created.addEventListener("error", (event) => {
    event.preventDefault();
    failWorkerOperation(
      created,
      event.message || "The browser analyzer failed to start.",
    );
  });
  created.addEventListener("messageerror", () => {
    failWorkerOperation(
      created,
      "The browser analyzer returned an unreadable response.",
    );
  });
  return created;
}

function setStatus(message, state = "idle") {
  statusText.textContent = message;
  status.hidden = !message;
  status.classList.toggle("is-working", state === "working");
  status.classList.toggle("is-error", state === "error");
}

function setLibraryMessage(message, state = "idle") {
  libraryMessage.textContent = message;
  libraryMessage.hidden = !message;
  libraryMessage.classList.toggle("is-error", state === "error");
}

function supported(file) {
  const lower = file.name.toLowerCase();
  return lower.endsWith(".ipa") || lower.endsWith(".zip");
}

function safeStem(name) {
  return (
    String(name || "bundle")
      .replace(/\.(ipa|zip|json|html?)$/i, "")
      .replace(/[^a-z0-9._-]+/gi, "-")
      .replace(/^-+|-+$/g, "") || "bundle"
  );
}

function formatBytes(value) {
  const units = ["B", "KB", "MB", "GB"];
  let number = Number(value) || 0;
  let index = 0;
  while (Math.abs(number) >= 1000 && index < units.length - 1) {
    number /= 1000;
    index += 1;
  }
  const digits =
    index === 0 || Math.abs(number) >= 100
      ? 0
      : Math.abs(number) >= 10
        ? 1
        : 2;
  return `${number.toFixed(digits)} ${units[index]}`;
}

function formatDelta(value) {
  const number = Number(value) || 0;
  if (!number) return "No change";
  return `${number > 0 ? "+" : "−"}${formatBytes(Math.abs(number))}`;
}

function deltaClass(value) {
  if (value > 0) return "delta-positive";
  if (value < 0) return "delta-negative";
  return "delta-neutral";
}

function formattedDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function download(content, type, name) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function element(tagName, className, text) {
  const node = document.createElement(tagName);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function analysisLabel(record) {
  const version =
    record.version && record.version !== "—" ? ` ${record.version}` : "";
  const build =
    record.build && record.build !== "—" ? ` (${record.build})` : "";
  return `${record.name}${version}${build}`;
}

async function analyze(file) {
  if (workerBusy()) return;
  if (!supported(file)) {
    setStatus("Choose an .ipa or .zip containing an iOS app.", "error");
    return;
  }
  if (file.size > MAX_BROWSER_ARCHIVE_BYTES) {
    setStatus("Archives over 700 MB aren't supported in the browser.", "error");
    return;
  }
  if (file.size > 500 * 1024 * 1024) {
    const proceed = window.confirm(
      "This archive is over 500 MB and may use substantial browser memory. Continue?",
    );
    if (!proceed) return;
  }

  const operationID = beginWorkerOperation("analyze");
  setStatus(`Reading ${file.name}…`, "working");
  try {
    const bytes = await file.arrayBuffer();
    if (
      activeOperationID !== operationID ||
      workerOperation !== "analyze"
    ) {
      return;
    }
    const activeWorker = createWorker();
    activeWorker.postMessage(
      {
        type: "analyze",
        name: file.name,
        modifiedAt: file.lastModified,
        bytes,
      },
      [bytes],
    );
  } catch (error) {
    if (activeOperationID !== operationID) return;
    failWorkerOperation(
      worker,
      error instanceof Error ? error.message : String(error),
    );
  }
}

function showReport(html, record) {
  currentReport = html;
  currentAnalysis = record;
  currentStem = safeStem(
    record?.artifactName || record?.report?.app?.artifactName,
  );
  reportFrame.srcdoc = currentReport;
  document.body.classList.remove("is-comparing");
  document.body.classList.add("has-result");
  comparison.hidden = true;
  analyzer.hidden = true;
  result.hidden = false;
  setStatus("");
  window.scrollTo({ top: 0 });
  window.requestAnimationFrame(() => reportFrame.focus());
}

async function openSavedAnalysis(recordOrID) {
  if (workerBusy()) return;
  const operationID = beginWorkerOperation("render");
  try {
    let record = recordOrID;
    if (typeof recordOrID === "string") {
      setLibraryMessage("Opening analysis…");
      record = await getAnalysis(recordOrID);
    }
    if (
      activeOperationID !== operationID ||
      workerOperation !== "render"
    ) {
      return;
    }
    if (!record?.report) {
      throw new Error("This saved analysis is no longer available.");
    }
    const requestID = ++renderRequestID;
    pendingRenders.set(requestID, record);
    setLibraryMessage("Rendering report…");
    createWorker().postMessage({
      type: "render",
      requestID,
      report: record.report,
    });
  } catch (error) {
    if (activeOperationID !== operationID) return;
    failWorkerOperation(
      worker,
      error instanceof Error ? error.message : String(error),
    );
  }
}

function leaveReport({ focusAnalyzer = true } = {}) {
  document.body.classList.remove("has-result", "is-comparing");
  result.hidden = true;
  comparison.hidden = true;
  analyzer.hidden = false;
  reportFrame.srcdoc = "";
  currentReport = "";
  input.value = "";
  setStatus("");
  void refreshLibrary();
  const destination = focusAnalyzer ? analyzer : library;
  window.scrollTo({
    top: Math.max(0, destination.offsetTop - 20),
    behavior: "smooth",
  });
  if (focusAnalyzer) window.requestAnimationFrame(() => dropZone.focus());
}

function focusedLibraryAction() {
  const button = document.activeElement?.closest?.(
    "button[data-action][data-analysis-id]",
  );
  if (!button || !libraryList.contains(button)) return null;
  return {
    action: button.dataset.action,
    analysisID: button.dataset.analysisId,
  };
}

function restoreLibraryFocus(target) {
  if (!target) return;
  window.requestAnimationFrame(() => {
    const button = [...libraryList.querySelectorAll("button[data-action]")].find(
      (candidate) =>
        candidate.dataset.action === target.action &&
        candidate.dataset.analysisId === target.analysisID,
    );
    (button || libraryList.querySelector("button[data-action]") || importReport)
      .focus();
  });
}

function renderLibrary({ focusAction = focusedLibraryAction() } = {}) {
  libraryList.replaceChildren();
  comparePrompt.hidden = !baselineID;
  const baseline = recentAnalyses.find((item) => item.id === baselineID);
  comparePromptTitle.textContent = baseline
    ? `Compare from ${analysisLabel(baseline)}`
    : "";

  if (!recentAnalyses.length) {
    libraryList.append(element("p", "library-empty", "No saved analyses."));
    restoreLibraryFocus(focusAction);
    return;
  }

  for (const record of recentAnalyses) {
    const row = element("article", "library-row");
    if (record.id === baselineID) row.classList.add("is-baseline");

    const identity = element("div", "library-identity");
    identity.append(element("strong", "", record.name));
    identity.append(
      element(
        "span",
        "",
        `Version ${record.version || "—"} (${record.build || "—"})`,
      ),
    );
    identity.append(element("span", "", record.artifactName));
    const saved = formattedDate(record.savedAt);
    if (saved) identity.append(element("span", "", `Saved ${saved}`));
    row.append(identity);

    const deliveryMetrics = record.installSize != null;
    for (const [label, value] of [
      [deliveryMetrics ? "Download" : "Archive", record.downloadSize],
      [
        deliveryMetrics ? "Install" : "Unpacked",
        record.installSize ?? record.unpackedSize,
      ],
    ]) {
      const metric = element("div", "library-metric");
      metric.append(element("span", "", label));
      metric.append(element("strong", "", formatBytes(value)));
      row.append(metric);
    }

    const actions = element("div", "library-actions");
    for (const [action, label] of [
      ["open", "Open"],
      [
        "compare",
        record.id === baselineID
          ? "Cancel"
          : baselineID
            ? "Use as newer"
            : "Compare",
      ],
      ["json", "Export JSON"],
      ["delete", "Delete"],
    ]) {
      const button = element("button", "", label);
      button.type = "button";
      button.disabled = workerBusy();
      button.dataset.action = action;
      button.dataset.analysisId = record.id;
      const recordLabel = analysisLabel(record);
      const ariaLabel =
        action === "open"
          ? `Open ${recordLabel}`
          : action === "compare"
            ? record.id === baselineID
              ? `Cancel comparison with ${recordLabel}`
              : baseline
                ? `Compare ${analysisLabel(baseline)} with ${recordLabel}`
                : `Compare ${recordLabel}`
            : action === "json"
              ? `Export ${recordLabel} as JSON`
              : `Delete ${recordLabel}`;
      button.setAttribute("aria-label", ariaLabel);
      if (action === "compare") {
        button.setAttribute("aria-pressed", String(record.id === baselineID));
      }
      actions.append(button);
    }
    row.append(actions);
    libraryList.append(row);
  }
  restoreLibraryFocus(focusAction);
}

async function refreshLibrary() {
  try {
    recentAnalyses = await listAnalyses();
    if (baselineID && !recentAnalyses.some((item) => item.id === baselineID)) {
      baselineID = null;
    }
    renderLibrary();
  } catch (error) {
    recentAnalyses = [];
    renderLibrary();
    setLibraryMessage(
      error instanceof Error
        ? error.message
        : "Recent analyses are unavailable.",
      "error",
    );
  }
}

function metricCard(label, value) {
  const card = element("article", "comparison-metric");
  card.append(element("span", "", label));
  card.append(
    element(
      "strong",
      "",
      `${formatBytes(value.before)} → ${formatBytes(value.after)}`,
    ),
  );
  const percent = Number.isFinite(value.percent)
    ? ` (${Math.abs(value.percent).toFixed(1)}%)`
    : "";
  card.append(
    element(
      "b",
      `metric-delta ${deltaClass(value.delta)}`,
      `${formatDelta(value.delta)}${value.delta ? percent : ""}`,
    ),
  );
  return card;
}

function changeGroup(title, items, state) {
  const group = element("section", "change-group");
  group.append(element("h4", "", title));
  const list = element("ul", "change-list");
  for (const item of items) {
    const row = element("li");
    row.append(element("strong", "", item.name));
    const detail =
      state === "changed"
        ? `${formatBytes(item.before)} → ${formatBytes(item.after)}`
        : item.path || item.kind;
    row.append(element("small", "", detail));
    const delta =
      state === "added"
        ? item.after
        : state === "removed"
          ? -item.before
          : item.delta;
    row.append(element("b", deltaClass(delta), formatDelta(delta)));
    list.append(row);
  }
  group.append(list);
  return group;
}

function appendChangeSection(holder, title, diff) {
  if (!diff.addedCount && !diff.removedCount && !diff.changedCount) return false;
  const section = element("section", "comparison-section");
  const head = element("header", "comparison-section-head");
  head.append(element("h3", "", title));
  const summary = [
    diff.addedCount ? `${diff.addedCount} added` : "",
    diff.removedCount ? `${diff.removedCount} removed` : "",
    diff.changedCount ? `${diff.changedCount} changed` : "",
  ].filter(Boolean).join(", ");
  head.append(
    element(
      "span",
      "",
      summary,
    ),
  );
  section.append(head);
  const columns = element("div", "change-columns");
  if (diff.added.length) columns.append(changeGroup("Added", diff.added, "added"));
  if (diff.removed.length) columns.append(changeGroup("Removed", diff.removed, "removed"));
  if (diff.changed.length) columns.append(changeGroup("Changed", diff.changed, "changed"));
  section.append(columns);
  holder.append(section);
  return true;
}

function comparisonTable(headers, rows) {
  const wrapper = element("div", "comparison-table-wrap");
  if (!rows.length) {
    wrapper.append(element("p", "empty-change", "No changes."));
    return wrapper;
  }
  const table = element("table", "comparison-table");
  const thead = element("thead");
  const headerRow = element("tr");
  for (const header of headers) headerRow.append(element("th", "", header));
  thead.append(headerRow);
  table.append(thead);
  const tbody = element("tbody");
  for (const values of rows) {
    const row = element("tr");
    for (const value of values) row.append(element("td", "", value));
    tbody.append(row);
  }
  table.append(tbody);
  wrapper.append(table);
  return wrapper;
}

function appendBundleSection(holder, title, bundleDiff) {
  const changes = [
    ...bundleDiff.changes.added,
    ...bundleDiff.changes.removed,
    ...bundleDiff.changes.changed,
  ].sort(
    (left, right) =>
      Math.abs(right.delta) - Math.abs(left.delta) ||
      left.name.localeCompare(right.name),
  );
  if (
    !changes.length &&
    bundleDiff.beforeCount === bundleDiff.afterCount &&
    !bundleDiff.size.delta
  ) {
    return false;
  }
  const section = element("section", "comparison-section");
  const head = element("header", "comparison-section-head");
  head.append(element("h3", "", title));
  head.append(
    element(
      "span",
      "",
      `${bundleDiff.beforeCount} → ${bundleDiff.afterCount}; ${formatDelta(bundleDiff.size.delta)}`,
    ),
  );
  section.append(head);
  section.append(
    comparisonTable(
      [title.slice(0, -1), "Before", "After", "Change"],
      changes.map((item) => {
        let name = item.name;
        if (
          item.beforeConsumerCount !== undefined &&
          item.beforeConsumerCount !== item.afterConsumerCount
        ) {
          name += ` (consumers ${item.beforeConsumerCount} → ${item.afterConsumerCount})`;
        }
        if (
          item.beforeStaticCandidate !== undefined &&
          item.beforeStaticCandidate !== item.afterStaticCandidate
        ) {
          name += item.afterStaticCandidate
            ? " (now worth a static or mergeable review)"
            : " (no longer a static or mergeable review candidate)";
        }
        return [
          name,
          formatBytes(item.before),
          formatBytes(item.after),
          formatDelta(item.delta),
        ];
      }),
    ),
  );
  holder.append(section);
  return true;
}

function appendLocaleSection(holder, localeDiff) {
  const changes = [
    ...localeDiff.changes.added,
    ...localeDiff.changes.removed,
    ...localeDiff.changes.changed,
  ].sort(
    (left, right) =>
      Math.abs(right.delta) - Math.abs(left.delta) ||
      left.name.localeCompare(right.name),
  );
  if (
    !changes.length &&
    localeDiff.beforeCount === localeDiff.afterCount &&
    !localeDiff.size.delta
  ) {
    return false;
  }
  const section = element("section", "comparison-section");
  const head = element("header", "comparison-section-head");
  head.append(element("h3", "", "Locales"));
  head.append(
    element(
      "span",
      "",
      `${localeDiff.beforeCount} → ${localeDiff.afterCount}; ${formatDelta(localeDiff.size.delta)}`,
    ),
  );
  section.append(head);
  section.append(
    comparisonTable(
      ["Locale", "Before", "After", "Change"],
      changes.map((item) => {
        let name = `${item.name} (${item.bundle || item.bundlePath || item.path})`;
        if (
          item.beforeKeyCount != null &&
          item.beforeKeyCount !== item.afterKeyCount
        ) {
          name += ` keys ${item.beforeKeyCount} → ${item.afterKeyCount}`;
        }
        if (
          item.beforeMissingKeyCount != null &&
          item.beforeMissingKeyCount !== item.afterMissingKeyCount
        ) {
          name += ` missing ${item.beforeMissingKeyCount} → ${item.afterMissingKeyCount}`;
        }
        return [
          name,
          formatBytes(item.before),
          formatBytes(item.after),
          formatDelta(item.delta),
        ];
      }),
    ),
  );
  holder.append(section);
  return true;
}

function appendRecommendationSection(holder, changes) {
  if (!changes.length) return false;
  const section = element("section", "comparison-section");
  const head = element("header", "comparison-section-head");
  head.append(element("h3", "", "Recommendations"));
  head.append(element("span", "", `${changes.length} changed`));
  section.append(head);
  section.append(
    comparisonTable(
      ["Recommendation", "Before", "After", "Change"],
      changes.slice(0, 20).map((item) => [
        item.title,
        formatBytes(item.before),
        formatBytes(item.after),
        formatDelta(item.delta),
      ]),
    ),
  );
  holder.append(section);
  return true;
}

function appendCapabilitySection(holder, changes, available) {
  if (!available || !changes.length) return false;
  const section = element("section", "comparison-section");
  const head = element("header", "comparison-section-head");
  head.append(element("h3", "", "Declared capabilities"));
  head.append(
    element(
      "span",
      "",
      `${changes.length} changed`,
    ),
  );
  section.append(head);
  section.append(
    comparisonTable(
      ["Declaration", "Earlier", "Newer"],
      changes.slice(0, 30).map((item) => [item.name, item.before, item.after]),
    ),
  );
  holder.append(section);
  return true;
}

function renderComparison(before, after) {
  const compared = compareReports(before.report, after.report);
  comparisonTitle.textContent = "Comparison";
  comparisonSubtitle.textContent = `${analysisLabel(before)} → ${analysisLabel(after)}`;
  comparisonContent.replaceChildren();

  if (
    before.bundleID &&
    after.bundleID &&
    before.bundleID !== "Unknown" &&
    after.bundleID !== "Unknown" &&
    before.bundleID !== after.bundleID
  ) {
    comparisonContent.append(
      element(
        "p",
        "comparison-warning",
        "These reports have different bundle identifiers, so path-based component matches may be incomplete.",
      ),
    );
  }

  const metrics = element("div", "comparison-metrics");
  metrics.append(
    metricCard(
      compared.deliveryMetricsAvailable ? "Download" : "Archive",
      compared.metrics.download,
    ),
  );
  metrics.append(
    metricCard(
      compared.deliveryMetricsAvailable ? "Install" : "Unpacked",
      compared.metrics.install,
    ),
  );
  comparisonContent.append(metrics);
  appendChangeSection(
    comparisonContent,
    "Biggest components",
    compared.components,
  );
  appendChangeSection(comparisonContent, "Images", compared.images);
  appendBundleSection(comparisonContent, "Frameworks", compared.frameworks);
  appendBundleSection(comparisonContent, "Targets", compared.targets);
  appendLocaleSection(comparisonContent, compared.locales);
  appendRecommendationSection(comparisonContent, compared.recommendations);
  appendCapabilitySection(
    comparisonContent,
    compared.capabilities,
    compared.capabilitiesAvailable,
  );
  if (!comparisonContent.querySelector(".comparison-section")) {
    comparisonContent.append(
      element("p", "comparison-empty", "No structural changes."),
    );
  }
}

function showComparison(before, after) {
  baselineID = null;
  comparisonPair = { before, after };
  renderLibrary();
  renderComparison(before, after);
  document.body.classList.remove("has-result");
  document.body.classList.add("is-comparing");
  result.hidden = true;
  comparison.hidden = false;
  analyzer.hidden = false;
  reportFrame.srcdoc = "";
  currentReport = "";
  window.scrollTo({ top: 0, behavior: "smooth" });
  window.requestAnimationFrame(() => comparisonBack.focus());
}

async function chooseComparison(id) {
  const focusAction = { action: "compare", analysisID: id };
  if (!baselineID) {
    baselineID = id;
    renderLibrary({ focusAction });
    comparePrompt.scrollIntoView({ behavior: "smooth", block: "nearest" });
    return;
  }
  if (baselineID === id) {
    baselineID = null;
    renderLibrary({ focusAction });
    return;
  }
  setLibraryMessage("Preparing comparison…");
  const [before, after] = await Promise.all([
    getAnalysis(baselineID),
    getAnalysis(id),
  ]);
  if (!before || !after) {
    throw new Error("One of these analyses is no longer available.");
  }
  setLibraryMessage("");
  showComparison(before, after);
}

async function importAnalysis(file) {
  setLibraryMessage(`Importing ${file.name}…`);
  const imported = await parseReportFile(file);
  const metadata = await saveAnalysis(imported.report, {
    source: imported.source,
    sourceFilename: imported.filename,
  });
  const saved = { ...metadata, report: imported.report };
  await refreshLibrary();
  if (baselineID && baselineID !== saved.id) {
    const before = await getAnalysis(baselineID);
    if (!before) {
      throw new Error("The comparison baseline is no longer available.");
    }
    setLibraryMessage("");
    showComparison(before, saved);
  } else {
    setLibraryMessage("");
  }
}

async function handleAnalysisResult(data) {
  const imported = parseImportedReport(
    data.html,
    `${data.summary?.artifactName || "analysis"}.html`,
  );
  let metadata = null;
  try {
    metadata = await saveAnalysis(imported.report, {
      source: "analysis",
      sourceFilename: data.summary?.artifactName || "",
    });
    await refreshLibrary();
  } catch (error) {
    setLibraryMessage(
      `The report completed but could not be saved: ${error instanceof Error ? error.message : String(error)}`,
      "error",
    );
  }
  const candidate = {
    ...(metadata || {
      id: "",
      name: imported.report.app.name,
      artifactName: imported.report.app.artifactName,
      bundleID: imported.report.app.bundleID,
      version: imported.report.app.version,
      build: imported.report.app.build,
    }),
    report: imported.report,
  };

  if (baselineID) {
    const before = await getAnalysis(baselineID);
    if (before) {
      setLibraryMessage("");
      showComparison(before, candidate);
      return;
    }
    baselineID = null;
  }
  showReport(data.html, candidate);
}

dropZone.addEventListener("click", () => {
  if (!workerBusy()) input.click();
});
input.addEventListener("change", () => {
  const file = input.files?.[0];
  if (file) void analyze(file);
});

for (const eventName of ["dragenter", "dragover"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.add("is-dragging");
  });
}

for (const eventName of ["dragleave", "drop"]) {
  dropZone.addEventListener(eventName, (event) => {
    event.preventDefault();
    dropZone.classList.remove("is-dragging");
  });
}

dropZone.addEventListener("drop", (event) => {
  const file = event.dataTransfer?.files?.[0];
  if (file) void analyze(file);
});

cancelAnalysis.addEventListener("click", () => {
  if (workerOperation !== "analyze") return;
  resetWorkerOperation();
  input.value = "";
  dropZone.classList.remove("is-dragging");
  setStatus("");
  focusDropZone();
});

analyzeAnother.addEventListener("click", () => leaveReport());

downloadReport.addEventListener("click", () => {
  if (currentReport) {
    download(
      currentReport,
      "text/html;charset=utf-8",
      `${currentStem}-openbundle.html`,
    );
  }
});

importReport.addEventListener("click", () => {
  if (!workerBusy()) importInput.click();
});
compareImport.addEventListener("click", () => {
  if (!workerBusy()) importInput.click();
});
compareAnalyze.addEventListener("click", () => {
  if (!workerBusy()) input.click();
});
compareCancel.addEventListener("click", () => {
  const cancelledBaselineID = baselineID;
  baselineID = null;
  renderLibrary({
    focusAction: cancelledBaselineID
      ? { action: "compare", analysisID: cancelledBaselineID }
      : null,
  });
});

importInput.addEventListener("change", () => {
  const file = importInput.files?.[0];
  importInput.value = "";
  if (!file) return;
  void importAnalysis(file).catch((error) => {
    setLibraryMessage(error instanceof Error ? error.message : String(error), "error");
  });
});

libraryList.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  if (workerBusy()) return;
  const id = button.dataset.analysisId;
  const action = button.dataset.action;
  const focusAction = { action, analysisID: id };
  button.disabled = true;
  void (async () => {
    if (action === "open") {
      await openSavedAnalysis(id);
    } else if (action === "compare") {
      await chooseComparison(id);
    } else if (action === "json") {
      const record = await getAnalysis(id);
      if (!record) {
        throw new Error("This saved analysis is no longer available.");
      }
      download(
        reportJSON(record.report),
        "application/json;charset=utf-8",
        `${safeStem(record.artifactName)}-openbundle.json`,
      );
    } else if (action === "delete") {
      const metadata = recentAnalyses.find((item) => item.id === id);
      if (
        !window.confirm(
          `Delete ${metadata?.name || "this analysis"} from this browser?`,
        )
      ) {
        return;
      }
      await deleteAnalysis(id);
      if (baselineID === id) baselineID = null;
      await refreshLibrary();
    }
  })()
    .catch((error) => {
      setLibraryMessage(
        error instanceof Error ? error.message : String(error),
        "error",
      );
    })
    .finally(() => {
      if (button.isConnected) button.disabled = workerBusy();
      if (
        !document.body.classList.contains("has-result") &&
        !document.body.classList.contains("is-comparing")
      ) {
        restoreLibraryFocus(focusAction);
      }
    });
});

comparisonBack.addEventListener("click", () => {
  document.body.classList.remove("is-comparing");
  comparison.hidden = true;
  comparisonPair = null;
  window.scrollTo({ top: library.offsetTop - 20, behavior: "smooth" });
  window.requestAnimationFrame(() => library.querySelector("button")?.focus());
});

comparisonSwap.addEventListener("click", () => {
  if (!comparisonPair) return;
  showComparison(comparisonPair.after, comparisonPair.before);
});

comparisonOpenBefore.addEventListener("click", () => {
  if (comparisonPair) void openSavedAnalysis(comparisonPair.before);
});

comparisonOpenAfter.addEventListener("click", () => {
  if (comparisonPair) void openSavedAnalysis(comparisonPair.after);
});

window.addEventListener("message", (event) => {
  if (
    event.source !== reportFrame.contentWindow ||
    event.data?.type !== "openbundle:compare-request" ||
    event.data?.version !== 1
  ) {
    return;
  }
  if (!currentAnalysis?.id) return;
  baselineID = currentAnalysis.id;
  leaveReport({ focusAnalyzer: false });
});

void refreshLibrary();
document.documentElement.dataset.openbundleReady = "true";
