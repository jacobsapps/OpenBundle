#!/usr/bin/env node
/* Exercise browser-local report imports, IndexedDB history, and comparisons. */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";

const chromePath =
  process.env.CHROME_PATH ||
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const [siteArgument, jsonArgument, htmlArgument, ipaArgument] = process.argv.slice(2);
if (!siteArgument || !jsonArgument || !htmlArgument || !ipaArgument) {
  throw new Error(
    "Usage: node scripts/smoke_library.mjs <site-url> <report.json> <report.html> <artifact.ipa>",
  );
}
const siteURL = siteArgument;
const jsonPath = resolve(jsonArgument);
const htmlPath = resolve(htmlArgument);
const ipaPath = resolve(ipaArgument);
const delay = (milliseconds) =>
  new Promise((resolveValue) => setTimeout(resolveValue, milliseconds));

const port = 12000 + Math.floor(Math.random() * 10000);
const profile = mkdtempSync(join(tmpdir(), "openbundle-library-chrome-"));
const chrome = spawn(
  chromePath,
  [
    "--headless=new",
    "--disable-gpu",
    "--no-first-run",
    "--no-default-browser-check",
    "--window-size=1440,1100",
    `--user-data-dir=${profile}`,
    `--remote-debugging-port=${port}`,
    "about:blank",
  ],
  { stdio: "ignore" },
);

let socket;
let nextID = 1;
const pending = new Map();

function command(method, params = {}) {
  const id = nextID++;
  socket.send(JSON.stringify({ id, method, params }));
  return new Promise((resolveValue, reject) => {
    pending.set(id, { resolve: resolveValue, reject });
  });
}

async function connect() {
  let targets;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      break;
    } catch {
      await delay(100);
    }
  }
  const page = targets?.find((target) => target.type === "page");
  if (!page) throw new Error("Chrome DevTools target did not start.");
  socket = new WebSocket(page.webSocketDebuggerUrl);
  socket.addEventListener("message", ({ data }) => {
    const message = JSON.parse(data);
    if (message.method === "Page.javascriptDialogOpening") {
      void command("Page.handleJavaScriptDialog", { accept: true }).catch(() => {});
      return;
    }
    if (!message.id || !pending.has(message.id)) return;
    const handler = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) handler.reject(new Error(message.error.message));
    else handler.resolve(message.result);
  });
  await new Promise((resolveValue, reject) => {
    socket.addEventListener("open", resolveValue, { once: true });
    socket.addEventListener("error", reject, { once: true });
  });
}

async function evaluate(expression, awaitPromise = false) {
  const response = await command("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise,
  });
  if (response.exceptionDetails) {
    throw new Error(response.exceptionDetails.exception?.description || "Browser evaluation failed.");
  }
  return response.result.value;
}

async function waitFor(expression, timeoutMilliseconds, description) {
  const started = Date.now();
  while (Date.now() - started < timeoutMilliseconds) {
    const result = await evaluate(expression);
    if (result) return result;
    await delay(100);
  }
  throw new Error(`Timed out waiting for ${description}.`);
}

async function setFile(selector, path) {
  const documentNode = await command("DOM.getDocument");
  const inputNode = await command("DOM.querySelector", {
    nodeId: documentNode.root.nodeId,
    selector,
  });
  if (!inputNode.nodeId) throw new Error(`Missing file input ${selector}.`);
  await command("DOM.setFileInputFiles", {
    nodeId: inputNode.nodeId,
    files: [path],
  });
}

async function screenshot(environmentKey) {
  const output = process.env[environmentKey];
  if (!output) return;
  const captured = await command("Page.captureScreenshot", {
    format: "png",
    captureBeyondViewport: false,
  });
  writeFileSync(resolve(output), captured.data, "base64");
}

try {
  await connect();
  await command("Page.enable");
  await command("DOM.enable");
  await command("Runtime.enable");
  await command("Page.addScriptToEvaluateOnNewDocument", {
    source: `(() => {
      const NativeWorker = window.Worker;
      const stats = window.__openbundleWorkerStats = { created: 0, terminated: 0 };
      window.Worker = new Proxy(NativeWorker, {
        construct(Target, argumentsList) {
          const instance = Reflect.construct(Target, argumentsList);
          const nativeTerminate = instance.terminate.bind(instance);
          let terminated = false;
          Object.defineProperty(instance, "terminate", {
            configurable: true,
            value() {
              if (!terminated) {
                terminated = true;
                stats.terminated += 1;
              }
              return nativeTerminate();
            },
          });
          stats.created += 1;
          window.__openbundleLastWorker = instance;
          return instance;
        },
      });
    })()`,
  });
  await command("Page.navigate", { url: siteURL });
  await waitFor(
    'document.documentElement.dataset.openbundleReady === "true"',
    15_000,
    "the browser host",
  );
  await waitFor(
    'document.querySelector(".library-empty")?.textContent === "No saved analyses."',
    15_000,
    "the empty analysis library",
  );
  const initialWorkerState = JSON.parse(
    await evaluate(`JSON.stringify({
      ...window.__openbundleWorkerStats,
      cancelHidden: document.querySelector("#cancel-analysis").hidden
    })`),
  );
  if (
    initialWorkerState.created !== 0 ||
    initialWorkerState.terminated !== 0 ||
    !initialWorkerState.cancelHidden
  ) {
    throw new Error(
      `Analyzer worker was not lazy at startup: ${JSON.stringify(initialWorkerState)}`,
    );
  }

  await setFile("#report-import-input", jsonPath);
  await waitFor(
    'document.querySelectorAll(".library-row").length === 1 || document.querySelector("#library-message").classList.contains("is-error")',
    30_000,
    "the JSON import",
  );
  await setFile("#report-import-input", htmlPath);
  await waitFor(
    'document.querySelectorAll(".library-row").length === 2 || document.querySelector("#library-message").classList.contains("is-error")',
    30_000,
    "the HTML import",
  );
  const importError = await evaluate(
    'document.querySelector("#library-message").classList.contains("is-error") ? document.querySelector("#library-message").textContent : ""',
  );
  if (importError) throw new Error(importError);

  await command("Page.reload");
  await waitFor(
    'document.documentElement.dataset.openbundleReady === "true" && document.querySelectorAll(".library-row").length === 2',
    30_000,
    "IndexedDB history after reload",
  );
  const historyActionsLabeled = await evaluate(`[
    ...document.querySelectorAll(".library-row")
  ].every(row => {
    const appName = row.querySelector(".library-identity strong").textContent;
    return [...row.querySelectorAll("button[data-action]")].every(button =>
      button.getAttribute("aria-label")?.includes(appName)
    );
  })`);
  if (!historyActionsLabeled) {
    throw new Error("History actions do not have app-specific accessible names.");
  }

  await evaluate(`(() => {
    const button = document.querySelector(".library-row button[data-action=compare]");
    window.__openbundleFocusAnalysisID = button.dataset.analysisId;
    button.focus();
    button.click();
  })()`);
  await waitFor(
    'document.querySelector(".library-row.is-baseline") && document.activeElement?.dataset.analysisId === window.__openbundleFocusAnalysisID && document.activeElement?.dataset.action === "compare"',
    15_000,
    "comparison selection focus restoration",
  );
  await evaluate(`(() => {
    const button = document.querySelector("#compare-cancel");
    button.focus();
    button.click();
  })()`);
  await waitFor(
    'document.querySelector("#compare-prompt").hidden && document.activeElement?.dataset.analysisId === window.__openbundleFocusAnalysisID && document.activeElement?.dataset.action === "compare"',
    15_000,
    "comparison cancellation focus restoration",
  );
  await screenshot("LIBRARY_SCREENSHOT_PATH");

  await evaluate(
    'document.querySelector(".library-row button[data-action=open]").click()',
  );
  await waitFor(
    '!document.querySelector("#result").hidden && document.querySelector("#report-frame").srcdoc.length > 50000',
    180_000,
    "a saved report to re-render",
  );
  const renderedWorkerState = JSON.parse(
    await evaluate(`JSON.stringify({
      ...window.__openbundleWorkerStats,
      cancelHidden: document.querySelector("#cancel-analysis").hidden
    })`),
  );
  if (
    renderedWorkerState.created !== 1 ||
    renderedWorkerState.terminated !== 1 ||
    !renderedWorkerState.cancelHidden
  ) {
    throw new Error(
      `Saved-report worker was not disposed: ${JSON.stringify(renderedWorkerState)}`,
    );
  }

  await evaluate(`(() => {
    const frame = document.querySelector("#report-frame");
    if (!frame.srcdoc.includes('id="compare-nav"')) return false;
    frame.srcdoc = frame.srcdoc.replace(
      "</body>",
      '<script>document.querySelector("#compare-nav").click()<\\/script></body>',
    );
    return true;
  })()`);
  await waitFor(
    '!document.body.classList.contains("has-result") && !document.querySelector("#compare-prompt").hidden && document.querySelectorAll(".library-row").length === 2',
    15_000,
    "the report-side comparison bridge",
  );
  await setFile("#artifact-input", ipaPath);
  await waitFor(
    'window.__openbundleWorkerStats.created === 2 && !document.querySelector("#cancel-analysis").hidden',
    180_000,
    "an IPA analysis worker",
  );
  await evaluate(
    'window.__openbundleLastWorker.dispatchEvent(new MessageEvent("messageerror"))',
  );
  await waitFor(
    'window.__openbundleWorkerStats.terminated === 2 && document.querySelector("#cancel-analysis").hidden && !document.querySelector("#drop-zone").disabled && !document.querySelector("#artifact-input").value && document.querySelector("#status").classList.contains("is-error")',
    15_000,
    "worker message-error recovery",
  );
  await setFile("#artifact-input", ipaPath);
  await waitFor(
    'window.__openbundleWorkerStats.created === 3 && !document.querySelector("#cancel-analysis").hidden',
    180_000,
    "a cancelable IPA analysis",
  );
  await evaluate('document.querySelector("#cancel-analysis").click()');
  await waitFor(
    'window.__openbundleWorkerStats.terminated === 3 && document.querySelector("#cancel-analysis").hidden && document.querySelector("#drop-zone") === document.activeElement && !document.querySelector("#drop-zone").disabled && !document.querySelector("#artifact-input").value && document.querySelector("#status").hidden',
    15_000,
    "analysis cancellation cleanup",
  );
  await setFile("#artifact-input", ipaPath);
  await waitFor(
    '!document.querySelector("#comparison").hidden || document.querySelector("#status").classList.contains("is-error")',
    600_000,
    "IPA analysis comparison",
  );
  const analysisError = await evaluate(
    'document.querySelector("#status").classList.contains("is-error") ? document.querySelector("#status-text").textContent : ""',
  );
  if (analysisError) throw new Error(analysisError);
  const analysisWorkerState = JSON.parse(
    await evaluate(`JSON.stringify({
      ...window.__openbundleWorkerStats,
      cancelHidden: document.querySelector("#cancel-analysis").hidden,
      dropDisabled: document.querySelector("#drop-zone").disabled
    })`),
  );
  if (
    analysisWorkerState.created !== 4 ||
    analysisWorkerState.terminated !== 4 ||
    !analysisWorkerState.cancelHidden ||
    analysisWorkerState.dropDisabled
  ) {
    throw new Error(
      `Completed-analysis worker was not disposed: ${JSON.stringify(analysisWorkerState)}`,
    );
  }

  const comparisonState = JSON.parse(
    await evaluate(`JSON.stringify({
      metrics: document.querySelectorAll(".comparison-metric").length,
      changeGroups: document.querySelectorAll(".change-group").length,
      sections: [...document.querySelectorAll(".comparison-section h3")].map(node => node.textContent),
      title: document.querySelector("#comparison-subtitle").textContent
    })`),
  );
  if (
    comparisonState.metrics !== 2 ||
    comparisonState.sections.some(
      (title) => !["Biggest components", "Images", "Frameworks", "Targets", "Locales", "Recommendations", "Declared capabilities"].includes(title),
    )
  ) {
    throw new Error(`Comparison UI is incomplete: ${JSON.stringify(comparisonState)}`);
  }
  await screenshot("COMPARISON_SCREENSHOT_PATH");

  await evaluate('document.querySelector("#comparison-back").click()');
  await waitFor(
    'document.querySelector("#comparison").hidden && document.querySelectorAll(".library-row").length >= 3',
    15_000,
    "the updated analysis library",
  );
  await evaluate(
    'document.querySelector(".library-row button[data-action=open]").click()',
  );
  await waitFor(
    '!document.querySelector("#result").hidden && document.querySelector("#report-frame").srcdoc.length > 50000',
    180_000,
    "saved rendering after completed analysis",
  );
  const recreatedWorkerState = JSON.parse(
    await evaluate("JSON.stringify(window.__openbundleWorkerStats)"),
  );
  if (
    recreatedWorkerState.created !== 5 ||
    recreatedWorkerState.terminated !== 5
  ) {
    throw new Error(
      `Analyzer worker was not recreated and disposed: ${JSON.stringify(recreatedWorkerState)}`,
    );
  }
  await evaluate('document.querySelector("#analyze-another").click()');
  await waitFor(
    '!document.body.classList.contains("has-result") && document.querySelectorAll(".library-row").length >= 3',
    30_000,
    "the library after re-rendering a saved analysis",
  );
  await evaluate(
    'document.querySelectorAll(".library-row button[data-action=compare]")[0].click()',
  );
  await evaluate(
    'document.querySelectorAll(".library-row button[data-action=compare]")[1].click()',
  );
  await waitFor(
    '!document.querySelector("#comparison").hidden',
    30_000,
    "saved-to-saved comparison",
  );

  const storage = JSON.parse(
    await evaluate(
      `new Promise((resolve,reject) => {
        const request = indexedDB.open("openbundle-analysis-library",1);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
          const database = request.result;
          const transaction = database.transaction(["analyses","payloads"],"readonly");
          const metadata = transaction.objectStore("analyses").getAll();
          const payloads = transaction.objectStore("payloads").getAll();
          transaction.oncomplete = () => resolve(JSON.stringify({
            metadataCount: metadata.result.length,
            payloadCount: payloads.result.length,
            payloadKeys: payloads.result.map(item => Object.keys(item).sort()),
            cookie: document.cookie,
            localStorageCount: localStorage.length
          }));
          transaction.onerror = () => reject(transaction.error);
        };
      })`,
      true,
    ),
  );
  if (
    storage.metadataCount < 3 ||
    storage.payloadCount !== storage.metadataCount ||
    storage.payloadKeys.some((keys) => JSON.stringify(keys) !== JSON.stringify(["id", "report"])) ||
    storage.cookie !== "" ||
    storage.localStorageCount !== 0
  ) {
    throw new Error(`Unexpected browser persistence: ${JSON.stringify(storage)}`);
  }

  process.stdout.write(
    `${JSON.stringify({ comparison: comparisonState, storage }, null, 2)}\n`,
  );
} finally {
  try {
    socket?.close();
  } catch {
    // Best effort.
  }
  chrome.kill("SIGTERM");
  await Promise.race([
    new Promise((resolveValue) => chrome.once("exit", resolveValue)),
    delay(2000),
  ]);
  rmSync(profile, {
    recursive: true,
    force: true,
    maxRetries: 10,
    retryDelay: 100,
  });
}
