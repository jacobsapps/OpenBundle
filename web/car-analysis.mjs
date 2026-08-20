import initCarWasm, {
  WasmArchive,
} from "./vendor/car-parser/car_wasm.js";
import { isCgbiPng, normalizeCgbiPng } from "./cgbi.mjs";

const MIN_DUPLICATE_BYTES = 1024;
const MIN_IMAGE_BYTES = 64 * 1024;
const MIN_SAVING_BYTES = 4 * 1024;
const MAX_DECODE_PIXELS = 16 * 1024 * 1024;
const MAX_DECODE_DIMENSION = 8192;
const MAX_HEADER_SCAN_BYTES = 1024 * 1024;
const encoder = new TextEncoder();

let carRuntimePromise;

export function initializeCarRuntime() {
  if (!carRuntimePromise) carRuntimePromise = initCarWasm();
  return carRuntimePromise;
}

function positiveInteger(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : 0;
}

function nonNegativeInteger(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= 0 ? number : -1;
}

function scalePreference(scale) {
  const normalized = positiveInteger(scale);
  if (normalized === 3) return [0, 0];
  if (normalized < 3 && normalized > 0) return [1, -normalized];
  if (normalized > 3) return [2, normalized];
  return [3, 0];
}

function comparePixelArea(left, right) {
  const leftArea =
    BigInt(positiveInteger(left.width)) * BigInt(positiveInteger(left.height));
  const rightArea =
    BigInt(positiveInteger(right.width)) * BigInt(positiveInteger(right.height));
  if (leftArea === rightArea) return 0;
  return leftArea > rightArea ? -1 : 1;
}

function compareTextDescending(left, right) {
  const leftText = String(left || "");
  const rightText = String(right || "");
  if (leftText === rightText) return 0;
  return leftText > rightText ? -1 : 1;
}

/**
 * Pick the one physical rendition whose conversion can represent a facet.
 *
 * The analyzer uses one device-scale headline per logical image. Selecting it
 * before any decode keeps lower scales from consuming the bounded conversion
 * budget. Internal references are storage aliases, not conversion work.
 */
export function selectPhysicalConversionRendition(renditions) {
  const candidates = Array.from(renditions || []).filter(
    (item) =>
      item &&
      item.entry_kind === "image" &&
      item.logical_layout !== "internal-reference" &&
      positiveInteger(item.size_on_disk) > 0,
  );
  candidates.sort((left, right) => {
    const leftScale = scalePreference(left.scale);
    const rightScale = scalePreference(right.scale);
    return (
      leftScale[0] - rightScale[0] ||
      leftScale[1] - rightScale[1] ||
      comparePixelArea(left, right) ||
      positiveInteger(right.size_on_disk) -
        positiveInteger(left.size_on_disk) ||
      compareTextDescending(left.rendition_name, right.rendition_name) ||
      compareTextDescending(left.id, right.id)
    );
  });
  return candidates[0] || null;
}

function mimeForPath(path) {
  const lower = path.toLowerCase();
  if (lower.endsWith(".png")) return "image/png";
  if (lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return "image/jpeg";
  if (lower.endsWith(".webp")) return "image/webp";
  if (lower.endsWith(".heic") || lower.endsWith(".heif")) return "image/heic";
  return "application/octet-stream";
}

function pngHasAlpha(bytes) {
  if (bytes.length < 29) return true;
  const signature = [137, 80, 78, 71, 13, 10, 26, 10];
  if (!signature.every((value, index) => bytes[index] === value)) return true;
  const colorType = bytes[25];
  if (colorType === 4 || colorType === 6) return true;
  // Indexed/RGB PNGs may carry transparency in a tRNS chunk.
  for (let index = 8; index + 12 <= bytes.length; ) {
    const length =
      ((bytes[index] << 24) |
        (bytes[index + 1] << 16) |
        (bytes[index + 2] << 8) |
        bytes[index + 3]) >>>
      0;
    if (index + 12 + length > bytes.length) break;
    const type = String.fromCharCode(
      bytes[index + 4],
      bytes[index + 5],
      bytes[index + 6],
      bytes[index + 7],
    );
    if (type === "tRNS") return true;
    if (type === "IDAT") break;
    index += 12 + length;
  }
  return false;
}

function looseImageHasAlpha(bytes, mimeType) {
  if (mimeType === "image/jpeg") return false;
  if (mimeType === "image/png") return pngHasAlpha(bytes);
  // Animated/less predictable formats are inventoried but not converted.
  return true;
}

async function sha256(parts) {
  const normalized = parts.map((part) =>
    part instanceof Uint8Array ? part : new Uint8Array(part),
  );
  const length = normalized.reduce((total, part) => total + part.byteLength, 0);
  const payload = new Uint8Array(length);
  let offset = 0;
  for (const part of normalized) {
    payload.set(part, offset);
    offset += part.byteLength;
  }
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", payload));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function digestWithIdentity(identity, body) {
  // Hash the large decoded body without first concatenating another full-size
  // JavaScript buffer. The second hash binds its digest to the pixel identity.
  const bodyDigest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", body),
  );
  return sha256([identity, bodyDigest]);
}

export function pixelsAreSafe(width, height) {
  const safeWidth = positiveInteger(width);
  const safeHeight = positiveInteger(height);
  return (
    safeWidth > 0 &&
    safeHeight > 0 &&
    safeWidth <= MAX_DECODE_DIMENSION &&
    safeHeight <= MAX_DECODE_DIMENSION &&
    safeWidth <= Math.floor(MAX_DECODE_PIXELS / safeHeight)
  );
}

function imageBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  return new Uint8Array();
}

function readBigEndian32(bytes, offset) {
  return (
    bytes[offset] * 0x1000000 +
    (bytes[offset + 1] << 16) +
    (bytes[offset + 2] << 8) +
    bytes[offset + 3]
  );
}

function pngDimensions(value) {
  const bytes = imageBytes(value);
  const signature = [137, 80, 78, 71, 13, 10, 26, 10];
  if (
    bytes.length < 24 ||
    !signature.every((byte, index) => bytes[index] === byte)
  ) {
    return null;
  }
  const scanEnd = Math.min(bytes.length, MAX_HEADER_SCAN_BYTES);
  let offset = 8;
  for (let count = 0; count < 16 && offset + 12 <= scanEnd; count += 1) {
    const length = readBigEndian32(bytes, offset);
    const dataOffset = offset + 8;
    const chunkEnd = dataOffset + length + 4;
    if (!Number.isSafeInteger(chunkEnd) || chunkEnd > bytes.length) return null;
    const type = String.fromCharCode(
      bytes[offset + 4],
      bytes[offset + 5],
      bytes[offset + 6],
      bytes[offset + 7],
    );
    if (type === "IHDR") {
      if (length !== 13 || dataOffset + 8 > bytes.length) return null;
      return {
        width: readBigEndian32(bytes, dataOffset),
        height: readBigEndian32(bytes, dataOffset + 4),
      };
    }
    offset = chunkEnd;
  }
  return null;
}

function jpegDimensions(value) {
  const bytes = imageBytes(value);
  if (bytes.length < 4 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return null;
  const scanEnd = Math.min(bytes.length, MAX_HEADER_SCAN_BYTES);
  let offset = 2;
  while (offset + 3 < scanEnd) {
    if (bytes[offset] !== 0xff) return null;
    while (offset < scanEnd && bytes[offset] === 0xff) offset += 1;
    if (offset >= scanEnd) return null;
    const marker = bytes[offset];
    offset += 1;
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      continue;
    }
    if (marker === 0xd9 || marker === 0xda || offset + 2 > scanEnd) return null;
    const length = (bytes[offset] << 8) | bytes[offset + 1];
    if (length < 2 || offset + length > bytes.length) return null;
    const isStartOfFrame =
      marker >= 0xc0 &&
      marker <= 0xcf &&
      ![0xc4, 0xc8, 0xcc].includes(marker);
    if (isStartOfFrame) {
      if (length < 7 || offset + 7 > bytes.length) return null;
      return {
        width: (bytes[offset + 5] << 8) | bytes[offset + 6],
        height: (bytes[offset + 3] << 8) | bytes[offset + 4],
      };
    }
    offset += length;
  }
  return null;
}

export function encodedImageDimensions(bytes, mimeType) {
  if (mimeType === "image/png") return pngDimensions(bytes);
  if (mimeType === "image/jpeg") return jpegDimensions(bytes);
  return null;
}

export function serializedConversionEstimate(
  serializedSize,
  payloadSize,
  serializedOverhead,
  convertedPayloadSize,
) {
  const total = positiveInteger(serializedSize);
  const payload = positiveInteger(payloadSize);
  const overhead = nonNegativeInteger(serializedOverhead);
  const converted = positiveInteger(convertedPayloadSize);
  if (
    !total ||
    !payload ||
    overhead < 0 ||
    !converted ||
    !Number.isSafeInteger(payload + overhead) ||
    payload + overhead !== total ||
    !Number.isSafeInteger(overhead + converted)
  ) {
    return null;
  }
  const optimizedSize = overhead + converted;
  return {
    optimizedSize,
    saving: total - optimizedSize,
  };
}

function asUint8Array(value) {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  // Backward compatibility for an old cached WASM module. New builds always
  // cross the bridge as Uint8Array via serde_bytes.
  if (Array.isArray(value)) return Uint8Array.from(value);
  return null;
}

async function canvasForDisplay(display, width, height) {
  if (
    typeof OffscreenCanvas !== "function" ||
    !pixelsAreSafe(width, height)
  ) {
    return null;
  }
  const canvas = new OffscreenCanvas(width, height);
  const context = canvas.getContext("2d", { alpha: true });
  if (!context) return null;

  if (display.preview_strategy === "canvas-rgba") {
    const bytes = asUint8Array(display.rgba);
    if (!bytes) return null;
    const rgba = new Uint8ClampedArray(
      bytes.buffer,
      bytes.byteOffset,
      bytes.byteLength,
    );
    if (rgba.byteLength !== width * height * 4) return null;
    context.putImageData(new ImageData(rgba, width, height), 0, 0);
    return canvas;
  }

  if (display.preview_strategy === "img-binary") {
    const bytes = asUint8Array(display.bytes);
    if (!bytes) return null;
    const blob = new Blob([bytes], {
      type: display.mime_type || "application/octet-stream",
    });
    const bitmap = await createImageBitmap(blob);
    try {
      context.drawImage(bitmap, 0, 0, width, height);
    } finally {
      bitmap.close();
    }
    return canvas;
  }
  return null;
}

function displayBytes(display) {
  if (display.preview_strategy === "canvas-rgba") {
    return asUint8Array(display.rgba);
  }
  if (display.preview_strategy === "img-binary") {
    return asUint8Array(display.bytes);
  }
  return null;
}

async function tryCanvasEncoding(canvas, type, quality) {
  if (!canvas || typeof canvas.convertToBlob !== "function") return null;
  try {
    const blob = await canvas.convertToBlob({ type, quality });
    // Browsers are allowed to fall back to PNG for an unsupported type.  Such
    // a result is not evidence that they encoded HEIC or JPEG.
    if (!blob || blob.size <= 0 || blob.type.toLowerCase() !== type) return null;
    return blob.size;
  } catch {
    return null;
  }
}

export async function imageEncodingCapabilities() {
  if (typeof OffscreenCanvas !== "function") {
    return { jpeg: false, heic: false };
  }
  const canvas = new OffscreenCanvas(2, 2);
  const context = canvas.getContext("2d", { alpha: true });
  if (!context) return { jpeg: false, heic: false };
  context.fillStyle = "rgba(255, 103, 25, 0.5)";
  context.fillRect(0, 0, 2, 2);
  const jpeg = Boolean(await tryCanvasEncoding(canvas, "image/jpeg", 0.85));
  let heic = false;
  for (const type of ["image/heic", "image/heif"]) {
    if (await tryCanvasEncoding(canvas, type, 0.85)) {
      heic = true;
      break;
    }
  }
  return { jpeg, heic };
}

async function bestConversion(canvas, { allowHeic, opaque }) {
  const attempts = [];
  if (allowHeic) {
    for (const type of ["image/heic", "image/heif"]) {
      const size = await tryCanvasEncoding(canvas, type, 0.85);
      if (size) attempts.push({ size, method: "HEIC quality 85" });
      if (size) break;
    }
  }
  if (opaque) {
    const size = await tryCanvasEncoding(canvas, "image/jpeg", 0.85);
    if (size) attempts.push({ size, method: "JPEG quality 85" });
  }
  attempts.sort((left, right) => left.size - right.size);
  return attempts[0] || null;
}

async function iconPNGBase64(canvas) {
  if (!canvas || typeof OffscreenCanvas !== "function") return null;
  const preview = new OffscreenCanvas(128, 128);
  const context = preview.getContext("2d", { alpha: true });
  if (!context) return null;
  context.drawImage(canvas, 0, 0, 128, 128);
  const blob = await preview.convertToBlob({ type: "image/png" });
  if (!blob || blob.type !== "image/png" || blob.size <= 0) return null;
  const bytes = new Uint8Array(await blob.arrayBuffer());
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

async function thumbnailDataURL(canvas) {
  if (!canvas || typeof OffscreenCanvas !== "function") return null;
  const maximum = 112;
  const scale = Math.min(1, maximum / Math.max(canvas.width, canvas.height));
  const width = Math.max(1, Math.round(canvas.width * scale));
  const height = Math.max(1, Math.round(canvas.height * scale));
  const preview = new OffscreenCanvas(width, height);
  const context = preview.getContext("2d", { alpha: true });
  if (!context) return null;
  context.drawImage(canvas, 0, 0, width, height);
  let blob = await preview.convertToBlob({ type: "image/webp", quality: 0.74 });
  if (!blob || blob.size <= 0 || blob.type !== "image/webp") {
    blob = await preview.convertToBlob({ type: "image/png" });
  }
  if (!blob || blob.size <= 0 || blob.size > 64 * 1024) return null;
  const bytes = new Uint8Array(await blob.arrayBuffer());
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return `data:${blob.type};base64,${btoa(binary)}`;
}

function safeName(value, fallback) {
  const text = String(value || "").trim();
  return text || fallback;
}

/**
 * Analyze one compiled asset catalog without uploading it.
 *
 * The result intentionally contains only compact metadata and hashes. Decoded
 * pixels are released after each rendition, keeping large IPAs bounded.
 */
export async function analyzeAssetCatalog(
  bytes,
  relativePath,
  {
    allowHeic = true,
    conversionBudget = 80,
    previewBudget = 96,
    onProgress = null,
  } = {},
) {
  await initializeCarRuntime();
  const archive = WasmArchive.fromBytes(bytes);
  const childrenByPath = new Map();
  const renditions = [];
  let convertedCount = 0;
  let conversionAttemptCount = 0;
  let decodedCount = 0;
  let decodeFailureCount = 0;
  let decodeSkippedCount = 0;
  let digestFailureCount = 0;
  let canvasFailureCount = 0;
  let conversionFailureCount = 0;
  let conversionBoundaryFailureCount = 0;
  let iconFailureCount = 0;
  let previewFailureCount = 0;
  let duplicateCandidateCount = 0;
  let duplicateDigestCount = 0;
  let conversionCandidateCount = 0;
  let conversionMeasuredCount = 0;
  let previewAttemptCount = 0;
  let previewCount = 0;
  let normalizedIcon = null;
  const previewedFacets = new Set();

  try {
    const diagnostics = archive.diagnosticsSummary();
    const entries = archive
      .listEntries()
      .slice()
      .sort(
        (left, right) =>
          positiveInteger(right.size_on_disk) - positiveInteger(left.size_on_disk),
      );
    const conversionGroups = new Map();
    for (let index = 0; index < entries.length; index += 1) {
      const item = entries[index];
      const facet = safeName(item.facet_name, `Asset ${index + 1}`);
      if (!conversionGroups.has(facet)) conversionGroups.set(facet, []);
      conversionGroups.get(facet).push(item);
    }
    const selectedConversionRenditions = new Set();
    for (const group of conversionGroups.values()) {
      const selected = selectPhysicalConversionRendition(group);
      if (selected) selectedConversionRenditions.add(selected);
    }

    for (let index = 0; index < entries.length; index += 1) {
      const item = entries[index];
      const size = positiveInteger(item.size_on_disk);
      const payloadSize = positiveInteger(item.payload_size);
      const serializedOverhead = nonNegativeInteger(item.serialized_overhead);
      const hasValidSizeBoundary = Boolean(
        serializedConversionEstimate(
          size,
          payloadSize,
          serializedOverhead,
          payloadSize,
        ),
      );
      const facet = safeName(item.facet_name, `Asset ${index + 1}`);
      const renditionName = safeName(item.rendition_name, facet);
      const entryPath = `${relativePath}::${facet}`;
      const displayPath = `${entryPath}/${renditionName} [${item.id}]`;
      let child = childrenByPath.get(entryPath);
      if (!child) {
        child = {
          name: facet,
          path: entryPath,
          kind: "asset",
          category: "asset_catalog",
          size: 0,
          compressedSize: 0,
          allocatedSize: 0,
          children: [],
          metadata: {
            assetType: item.entry_kind,
            renditionCount: 0,
          },
          insights: [],
        };
        childrenByPath.set(entryPath, child);
      }
      child.size += size;
      child.compressedSize += size;
      child.allocatedSize += size;
      child.metadata.renditionCount += 1;

      const physical = item.logical_layout !== "internal-reference";
      const rendition = {
        entryPath,
        name: facet,
        renditionName,
        path: entryPath,
        displayPath,
        size,
        payloadSize,
        serializedOverhead: Math.max(0, serializedOverhead),
        digest: null,
        assetType: item.entry_kind,
        pixelWidth: positiveInteger(item.width),
        pixelHeight: positiveInteger(item.height),
        scale: positiveInteger(item.scale),
        encoding: String(item.resolved_encoding || "unknown"),
        opaque: Boolean(item.opaque),
        physical,
      };

      const image = item.entry_kind === "image";
      const sourceName = `${facet}/${renditionName}`.toLowerCase();
      const vectorSource =
        item.logical_layout === "vector" ||
        ["svg", "pdf"].includes(rendition.encoding.toLowerCase()) ||
        /\.(svg|pdf)(?:$|[?#])/.test(sourceName);
      const wantsIcon =
        image &&
        physical &&
        !normalizedIcon &&
        facet.toLowerCase().includes("appicon");
      const safeToDecode = pixelsAreSafe(
        rendition.pixelWidth,
        rendition.pixelHeight,
      );
      const duplicateCandidate = image && physical && size >= MIN_DUPLICATE_BYTES;
      const conversionCandidate =
        selectedConversionRenditions.has(item) &&
        image &&
        physical &&
        size >= MIN_IMAGE_BYTES &&
        !vectorSource &&
        !["heif", "heic"].includes(rendition.encoding.toLowerCase()) &&
        !facet.toLowerCase().includes("appicon");
      if (duplicateCandidate) duplicateCandidateCount += 1;
      if (conversionCandidate) conversionCandidateCount += 1;
      if (conversionCandidate && !hasValidSizeBoundary) {
        conversionBoundaryFailureCount += 1;
      }
      if (!safeToDecode && (duplicateCandidate || conversionCandidate || wantsIcon)) {
        decodeSkippedCount += 1;
      }
      const wantsDigest = duplicateCandidate && safeToDecode;
      const wantsConversion =
        conversionCandidate &&
        hasValidSizeBoundary &&
        safeToDecode &&
        conversionAttemptCount < conversionBudget;
      const wantsIconDecode = wantsIcon && safeToDecode;
      const wantsPreview =
        image &&
        physical &&
        safeToDecode &&
        !previewedFacets.has(facet) &&
        previewAttemptCount < previewBudget;

      if (wantsDigest || wantsConversion || wantsIconDecode || wantsPreview) {
        if (wantsConversion) conversionAttemptCount += 1;
        if (wantsPreview) {
          previewAttemptCount += 1;
          previewedFacets.add(facet);
        }
        let display = null;
        let body = null;
        try {
          display = archive.getDisplayPayload(item.id);
          body = displayBytes(display);
          if (!body) throw new Error("display payload has no binary bytes");
          decodedCount += 1;
        } catch {
          decodeFailureCount += 1;
        }

        if (body && wantsDigest) {
          try {
            const identity = encoder.encode(
              `${rendition.pixelWidth}x${rendition.pixelHeight}@${rendition.scale}:${display.preview_strategy}:`,
            );
            rendition.digest = await digestWithIdentity(identity, body);
            duplicateDigestCount += 1;
          } catch {
            digestFailureCount += 1;
          }
        }

        let canvas = null;
        if (body && (wantsConversion || wantsIconDecode || wantsPreview)) {
          try {
            canvas = await canvasForDisplay(
              display,
              rendition.pixelWidth,
              rendition.pixelHeight,
            );
            if (!canvas) canvasFailureCount += 1;
          } catch {
            canvasFailureCount += 1;
          }
        }

        // Savings are authoritative. Optional presentation work below must not
        // suppress a valid conversion measurement.
        if (canvas && wantsConversion) {
          try {
            const conversion = await bestConversion(canvas, {
              allowHeic,
              opaque: rendition.opaque,
            });
            if (conversion) conversionMeasuredCount += 1;
            const estimate = conversion
              ? serializedConversionEstimate(
                  size,
                  payloadSize,
                  serializedOverhead,
                  conversion.size,
                )
              : null;
            if (estimate && estimate.saving >= MIN_SAVING_BYTES) {
              rendition.optimizedSize = estimate.optimizedSize;
              rendition.optimizationMethod = conversion.method;
              convertedCount += 1;
            }
          } catch {
            conversionFailureCount += 1;
          }
        }

        if (canvas && wantsIconDecode) {
          try {
            normalizedIcon = await iconPNGBase64(canvas);
          } catch {
            iconFailureCount += 1;
          }
        }

        if (canvas && wantsPreview) {
          try {
            rendition.thumbnailDataURL = await thumbnailDataURL(canvas);
            if (rendition.thumbnailDataURL) previewCount += 1;
          } catch {
            previewFailureCount += 1;
          }
        }
      }
      renditions.push(rendition);
      if (onProgress && index > 0 && index % 500 === 0) {
        onProgress(`Inspecting ${relativePath} (${index.toLocaleString()}/${entries.length.toLocaleString()} renditions)…`);
      }
    }

    return {
      children: Array.from(childrenByPath.values()),
      renditions,
      conversionCount: convertedCount,
      conversionAttemptCount,
      previewCount,
      previewAttemptCount,
      iconPNGBase64: normalizedIcon,
      diagnostics: {
        parser: "car-parser-wasm",
        entries: entries.length,
        supportedOutputs: positiveInteger(diagnostics.supported_outputs),
        unsupportedOutputs: positiveInteger(diagnostics.unsupported_outputs),
        decodedCount,
        decodeFailureCount,
        decodeSkippedCount,
        digestFailureCount,
        canvasFailureCount,
        conversionFailureCount,
        conversionBoundaryFailureCount,
        iconFailureCount,
        previewFailureCount,
        duplicateCandidateCount,
        duplicateDigestCount,
        conversionCandidateCount,
        conversionMeasuredCount,
        previewCount,
      },
    };
  } finally {
    archive.free();
  }
}

export async function analyzeLooseImage(
  bytes,
  relativePath,
  { allowHeic = true } = {},
) {
  const mimeType = mimeForPath(relativePath);
  if (!["image/png", "image/jpeg"].includes(mimeType)) return null;
  const encodedDimensions = encodedImageDimensions(bytes, mimeType);
  if (!encodedDimensions) return null;
  if (!pixelsAreSafe(encodedDimensions.width, encodedDimensions.height)) {
    return {
      properties: {
        pixelWidth: encodedDimensions.width,
        pixelHeight: encodedDimensions.height,
        hasAlpha: looseImageHasAlpha(bytes, mimeType),
      },
      conversions: {},
      diagnostics: {
        decoder: "image-header",
        skipped: "unsafe-dimensions",
      },
    };
  }
  const cgbi = mimeType === "image/png" && isCgbiPng(bytes);
  let hasAlpha = looseImageHasAlpha(bytes, mimeType);
  let bitmap;
  try {
    let width;
    let height;
    let canvas;
    let diagnostics = { decoder: "browser-image-bitmap" };
    if (cgbi) {
      const normalized = await normalizeCgbiPng(bytes);
      width = normalized.width;
      height = normalized.height;
      hasAlpha = normalized.hasAlpha;
      diagnostics = normalized.diagnostics;
      if (typeof OffscreenCanvas === "function") {
        canvas = new OffscreenCanvas(width, height);
        const context = canvas.getContext("2d", { alpha: true });
        if (!context) return null;
        const rgba = new Uint8ClampedArray(
          normalized.rgba.buffer,
          normalized.rgba.byteOffset,
          normalized.rgba.byteLength,
        );
        context.putImageData(new ImageData(rgba, width, height), 0, 0);
      }
    } else {
      const blob = new Blob([bytes], { type: mimeType });
      bitmap = await createImageBitmap(blob);
      width = bitmap.width;
      height = bitmap.height;
      if (
        width !== encodedDimensions.width ||
        height !== encodedDimensions.height
      ) {
        return null;
      }
    }
    if (!pixelsAreSafe(width, height) || typeof OffscreenCanvas !== "function") {
      return {
        properties: { pixelWidth: width, pixelHeight: height, hasAlpha },
        conversions: {},
        diagnostics,
      };
    }
    if (!canvas) {
      canvas = new OffscreenCanvas(width, height);
      const context = canvas.getContext("2d", { alpha: true });
      if (!context) return null;
      context.drawImage(bitmap, 0, 0);
    }
    const attempts = {};
    if (allowHeic) {
      const heic = await bestConversion(canvas, { allowHeic: true, opaque: false });
      if (heic?.method.startsWith("HEIC")) attempts.heic = heic.size;
    }
    if (!hasAlpha) {
      const jpeg = await tryCanvasEncoding(canvas, "image/jpeg", 0.85);
      if (jpeg) attempts.jpeg = jpeg;
    }
    return {
      properties: { pixelWidth: width, pixelHeight: height, hasAlpha },
      conversions: attempts,
      diagnostics,
    };
  } catch (error) {
    // Surface CgBI failures to the worker so it can preserve an honest failure
    // count and a bounded diagnostic code. Native browser decoder failures keep
    // the historical null result.
    if (cgbi) throw error;
    return null;
  } finally {
    bitmap?.close();
  }
}
