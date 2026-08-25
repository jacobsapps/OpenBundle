import { loadPyodide } from "./vendor/pyodide/pyodide.mjs";
import {
  analyzeAssetCatalog,
  analyzeLooseImage,
  imageEncodingCapabilities,
  initializeCarRuntime,
} from "./car-analysis.mjs";
import { isCgbiPng } from "./cgbi.mjs";

const coreURL = new URL("./openbundle-core.zip", import.meta.url);
const pyodideBaseURL = new URL("./vendor/pyodide/", import.meta.url).href;
const MAX_BROWSER_ARCHIVE_BYTES = 700 * 1024 * 1024;
const MAX_BROWSER_ASSET_BYTES = 64 * 1024 * 1024;
let runtimePromise;
let operationQueue = Promise.resolve();

function progress(message) {
  self.postMessage({ type: "progress", message: String(message) });
}

function describeError(error) {
  if (error instanceof Error) return error.message;
  try {
    const serialized = JSON.stringify(error);
    if (serialized && serialized !== "{}") return serialized;
  } catch {
    // Fall through to the JavaScript string representation.
  }
  return String(error);
}

async function runtime() {
  if (!runtimePromise) {
    runtimePromise = (async () => {
      progress("Loading analyzer…");
      const pyodide = await loadPyodide({
        indexURL: pyodideBaseURL,
        packageBaseUrl: pyodideBaseURL,
      });
      const coreResponse = await fetch(coreURL);
      if (!coreResponse.ok) {
        throw new Error(`Could not load OpenBundle core (${coreResponse.status}).`);
      }
      pyodide.FS.writeFile(
        "/openbundle-core.zip",
        new Uint8Array(await coreResponse.arrayBuffer()),
      );
      pyodide.runPython(`
import sys
if "/openbundle-core.zip" not in sys.path:
    sys.path.insert(0, "/openbundle-core.zip")
      `);
      pyodide.globals.set("web_progress", progress);
      return pyodide;
    })();
  }
  return runtimePromise;
}

function formatBytes(value) {
  const units = ["B", "KB", "MB", "GB"];
  let size = Number(value);
  let unit = 0;
  while (size >= 1000 && unit < units.length - 1) {
    size /= 1000;
    unit += 1;
  }
  return `${size.toFixed(unit ? 2 : 0)} ${units[unit]}`;
}

async function prepareManifest(pyodide) {
  const payload = await pyodide.runPythonAsync(`
import json
import plistlib
from openbundle.artifact import prepare_artifact

web_prepared = prepare_artifact(input_path)
app_root = web_prepared.app_root
try:
    with (app_root / "Info.plist").open("rb") as handle:
        web_info = plistlib.load(handle)
except (OSError, plistlib.InvalidFileException):
    web_info = {}

catalogs = []
images = []
for candidate in app_root.rglob("*"):
    if not candidate.is_file() or candidate.is_symlink():
        continue
    relative = candidate.relative_to(app_root).as_posix()
    size = candidate.stat().st_size
    if candidate.suffix.lower() == ".car":
        catalogs.append({
            "absolutePath": str(candidate),
            "relativePath": relative,
            "size": size,
        })
    elif (
        candidate.suffix.lower() in {".png", ".jpg", ".jpeg"}
        and size >= 64 * 1024
        and "appicon" not in relative.lower()
    ):
        images.append({
            "absolutePath": str(candidate),
            "relativePath": relative,
            "size": size,
        })

json.dumps({
    "minimumOS": str(web_info.get("MinimumOSVersion") or ""),
    "catalogs": sorted(catalogs, key=lambda item: item["size"], reverse=True),
    "images": sorted(images, key=lambda item: item["size"], reverse=True)[:80],
    "looseImageCandidateCount": len(images),
})
  `);
  return JSON.parse(payload);
}

async function readPreparedFile(pyodide, absolutePath) {
  // Python 3.14's WASI filesystem is not exposed through the legacy
  // `pyodide.FS` facade. Read the extracted tempfile on the Python side and
  // explicitly copy its buffer into JavaScript, then release the PyProxy.
  pyodide.globals.set("browser_measurement_path", absolutePath);
  const proxy = await pyodide.runPythonAsync(`
from pathlib import Path
Path(browser_measurement_path).read_bytes()
  `);
  try {
    const converted =
      proxy && typeof proxy.toJs === "function"
        ? proxy.toJs({ create_pyproxies: false })
        : proxy;
    if (converted instanceof Uint8Array) return converted;
    if (ArrayBuffer.isView(converted)) {
      return new Uint8Array(
        converted.buffer,
        converted.byteOffset,
        converted.byteLength,
      );
    }
    return new Uint8Array(converted);
  } finally {
    if (proxy && typeof proxy.destroy === "function") proxy.destroy();
    pyodide.globals.delete("browser_measurement_path");
  }
}

async function browserMeasurements(pyodide, manifest) {
  const major = Number.parseInt(manifest.minimumOS, 10);
  const allowHeic = !Number.isFinite(major) || major >= 12;
  const catalogResults = {};
  const imageResults = {};
  const assetCatalogDiagnostics = {
    digestFailureCount: 0,
    canvasFailureCount: 0,
    conversionFailureCount: 0,
    conversionBoundaryFailureCount: 0,
    iconFailureCount: 0,
    previewFailureCount: 0,
    oversizedInputCount: 0,
  };
  let catalogAnalysisAvailable = false;
  let imageAnalysisAvailable =
    typeof OffscreenCanvas === "function" &&
    typeof createImageBitmap === "function";
  const encoders = imageAnalysisAvailable
    ? await imageEncodingCapabilities()
    : { jpeg: false, heic: false };
  let looseImageAnalyzedCount = 0;
  let looseImageMeasuredCount = 0;
  let looseImageDecodeFailureCount = 0;
  let looseImageCgbiCandidateCount = 0;
  let looseImageCgbiDecodedCount = 0;
  let looseImageCgbiFailureCount = 0;
  let looseImageOversizedCount = 0;
  let looseImageSafetySkipCount = 0;
  const looseImageCgbiFailureReasons = {};

  if (manifest.catalogs.length) {
    try {
      progress("Loading asset catalogs…");
      await initializeCarRuntime();
      catalogAnalysisAvailable = true;
      let conversionBudget = 80;
      let previewBudget = 96;
      for (let index = 0; index < manifest.catalogs.length; index += 1) {
        const catalog = manifest.catalogs[index];
        progress(
          `Inspecting asset catalogs (${index + 1}/${manifest.catalogs.length})…`,
        );
        if (Number(catalog.size || 0) > MAX_BROWSER_ASSET_BYTES) {
          assetCatalogDiagnostics.oversizedInputCount += 1;
          catalogResults[catalog.relativePath] = {
            children: [],
            renditions: [],
            diagnostics: {
              parser: "car-parser-wasm",
              failed: true,
              oversized: true,
              message: "Asset catalog exceeds the 64 MB browser limit.",
            },
          };
          continue;
        }
        try {
          const bytes = await readPreparedFile(pyodide, catalog.absolutePath);
          const result = await analyzeAssetCatalog(bytes, catalog.relativePath, {
            allowHeic: allowHeic && encoders.heic,
            conversionBudget,
            previewBudget,
            onProgress: progress,
          });
          catalogResults[catalog.relativePath] = result;
          for (const key of Object.keys(assetCatalogDiagnostics)) {
            assetCatalogDiagnostics[key] += Number(
              result.diagnostics?.[key] || 0,
            );
          }
          conversionBudget = Math.max(
            0,
            conversionBudget - Number(result.conversionAttemptCount || 0),
          );
          previewBudget = Math.max(
            0,
            previewBudget - Number(result.previewAttemptCount || 0),
          );
        } catch (error) {
          catalogResults[catalog.relativePath] = {
            children: [],
            renditions: [],
            diagnostics: {
              parser: "car-parser-wasm",
              failed: true,
              message: `${catalog.absolutePath}: ${describeError(error)}`,
            },
          };
        }
      }
    } catch {
      catalogAnalysisAvailable = false;
    }
  } else {
    // The capability exists even when this particular app has no catalog.
    try {
      await initializeCarRuntime();
      catalogAnalysisAvailable = true;
    } catch {
      catalogAnalysisAvailable = false;
    }
  }

  if (imageAnalysisAvailable && manifest.images.length) {
    progress("Measuring loose-image conversions…");
    for (let index = 0; index < manifest.images.length; index += 1) {
      const image = manifest.images[index];
      let cgbiCandidate = false;
      try {
        if (Number(image.size || 0) > MAX_BROWSER_ASSET_BYTES) {
          looseImageOversizedCount += 1;
          looseImageDecodeFailureCount += 1;
          continue;
        }
        const bytes = await readPreparedFile(pyodide, image.absolutePath);
        cgbiCandidate = isCgbiPng(bytes);
        if (cgbiCandidate) looseImageCgbiCandidateCount += 1;
        const result = await analyzeLooseImage(bytes, image.relativePath, {
          allowHeic: allowHeic && encoders.heic,
        });
        if (result) {
          imageResults[image.relativePath] = result;
          looseImageAnalyzedCount += 1;
          if (result.diagnostics?.skipped) looseImageSafetySkipCount += 1;
          if (cgbiCandidate) looseImageCgbiDecodedCount += 1;
          if (Object.keys(result.conversions || {}).length) {
            looseImageMeasuredCount += 1;
          }
        } else {
          looseImageDecodeFailureCount += 1;
          if (cgbiCandidate) {
            looseImageCgbiFailureCount += 1;
            looseImageCgbiFailureReasons["decode-failed"] =
              Number(looseImageCgbiFailureReasons["decode-failed"] || 0) + 1;
          }
        }
      } catch (error) {
        // An unsupported image remains in inventory; no saving is claimed.
        looseImageDecodeFailureCount += 1;
        if (cgbiCandidate) {
          looseImageCgbiFailureCount += 1;
          const candidateCode = String(error?.code || "decode-failed");
          const code = /^[a-z0-9-]{1,64}$/.test(candidateCode)
            ? candidateCode
            : "decode-failed";
          looseImageCgbiFailureReasons[code] =
            Number(looseImageCgbiFailureReasons[code] || 0) + 1;
        }
      }
    }
  }

  return {
    catalogResults,
    imageResults,
    catalogAnalysisAvailable,
    imageAnalysisAvailable,
    diagnostics: {
      encoders,
      assetCatalog: assetCatalogDiagnostics,
      looseImageCandidateCount: Number(manifest.looseImageCandidateCount || 0),
      looseImageAttemptCount: manifest.images.length,
      looseImageAnalyzedCount,
      looseImageMeasuredCount,
      looseImageDecodeFailureCount,
      looseImageCgbiCandidateCount,
      looseImageCgbiDecodedCount,
      looseImageCgbiFailureCount,
      looseImageCgbiFailureReasons,
      looseImageOversizedCount,
      looseImageSafetySkipCount,
    },
  };
}

async function cleanupPrepared(pyodide) {
  try {
    await pyodide.runPythonAsync(`
if "web_prepared" in globals() and web_prepared is not None:
    web_prepared.cleanup()
    web_prepared = None
    `);
  } catch {
    // The Pyodide worker is disposable; cleanup is best-effort on failure.
  }
}

async function renderSavedReport(data) {
  const pyodide = await runtime();
  pyodide.globals.set("saved_report_json", JSON.stringify(data.report));
  try {
    const html = await pyodide.runPythonAsync(`
import json
from openbundle.report import render_report_html

saved_analysis = json.loads(saved_report_json)
render_report_html(saved_analysis)
    `);
    self.postMessage({
      type: "rendered",
      requestID: data.requestID,
      html,
    });
  } finally {
    pyodide.globals.delete("saved_report_json");
  }
}

async function handleMessage(data) {
  if (data.type === "render") {
    try {
      await renderSavedReport(data);
    } catch (error) {
      self.postMessage({
        type: "render-error",
        requestID: data.requestID,
        message: describeError(error),
      });
    }
    return;
  }
  if (data.type !== "analyze") return;

  let inputPath;
  try {
    if (!(data.bytes instanceof ArrayBuffer)) {
      throw new Error("The selected archive could not be read.");
    }
    if (data.bytes.byteLength > MAX_BROWSER_ARCHIVE_BYTES) {
      throw new Error("Archives over 700 MB aren't supported in the browser.");
    }
    const pyodide = await runtime();
    const suffix = data.name.toLowerCase().endsWith(".ipa") ? ".ipa" : ".zip";
    inputPath = `/tmp/openbundle-input${suffix}`;
    let inputBytes = new Uint8Array(data.bytes);
    pyodide.FS.writeFile(inputPath, inputBytes);
    inputBytes = null;
    data.bytes = null;
    pyodide.globals.set("input_path", inputPath);
    pyodide.globals.set("input_name", data.name);
    pyodide.globals.set("input_modified", Number(data.modifiedAt) / 1000);
    await pyodide.runPythonAsync(`
import os
os.utime(input_path, (input_modified, input_modified))
    `);

    const manifest = await prepareManifest(pyodide);
    const measurements = await browserMeasurements(pyodide, manifest);
    pyodide.globals.set(
      "catalog_results_json",
      JSON.stringify(measurements.catalogResults),
    );
    pyodide.globals.set(
      "image_results_json",
      JSON.stringify(measurements.imageResults),
    );
    pyodide.globals.set(
      "catalog_analysis_available",
      measurements.catalogAnalysisAvailable,
    );
    pyodide.globals.set(
      "image_analysis_available",
      measurements.imageAnalysisAvailable,
    );
    pyodide.globals.set(
      "host_diagnostics_json",
      JSON.stringify(measurements.diagnostics),
    );

    const payload = await pyodide.runPythonAsync(`
import json
from openbundle.analyzer import BundleAnalyzer
from openbundle.platform import BrowserAnalysisPlatform
from openbundle.report import render_report_html

analysis = BundleAnalyzer(
    progress=lambda message: web_progress(message),
    platform=BrowserAnalysisPlatform(
        catalog_results=json.loads(catalog_results_json),
        image_results=json.loads(image_results_json),
        catalog_analysis_available=bool(catalog_analysis_available),
        image_analysis_available=bool(image_analysis_available),
        host_diagnostics=json.loads(host_diagnostics_json),
    ),
).analyze(input_path, prepared=web_prepared)
web_prepared = None
analysis["app"]["artifactName"] = input_name
json.dumps(
    {
        "html": render_report_html(analysis),
        "summary": {
            "name": analysis["app"]["name"],
            "artifactName": input_name,
            "installSize": analysis["metrics"]["installSize"],
        },
    },
    ensure_ascii=False,
)
    `);
    const result = JSON.parse(payload);
    result.summary.installSize = formatBytes(result.summary.installSize);
    self.postMessage({ type: "result", ...result });
  } catch (error) {
    self.postMessage({
      type: "error",
      message: describeError(error),
    });
  } finally {
    try {
      const pyodide = await runtime();
      await cleanupPrepared(pyodide);
    } catch {
      // Ignore cleanup failures while reporting the original error.
    }
    if (inputPath) {
      try {
        const pyodide = await runtime();
        pyodide.FS.unlink(inputPath);
      } catch {
        // The temporary virtual file disappears with the worker either way.
      }
    }
  }
}

self.addEventListener("message", ({ data }) => {
  // Pyodide globals and its temporary filesystem are shared by this worker.
  // Serialize render and analysis requests so a second UI action cannot
  // overwrite an active artifact or its measurement payloads.
  operationQueue = operationQueue.then(
    () => handleMessage(data),
    () => handleMessage(data),
  );
});
