// A deliberately narrow decoder for Apple's non-standard, pngcrush-generated
// CgBI PNGs. It normalizes validated BGRA/premultiplied scanlines to straight
// RGBA pixels in memory; the signed bundle bytes are never rewritten.

const PNG_SIGNATURE = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
const KNOWN_CGBI_HEADERS = new Set(["50002002", "50002006"]);
const MAX_INPUT_BYTES = 128 * 1024 * 1024;
const MAX_COMPRESSED_BYTES = 128 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 160 * 1024 * 1024;
const MAX_PIXELS = 40_000_000;
const MAX_DIMENSION = 16_384;
const MAX_CHUNKS = 4096;

let crcTable;

export class CgbiDecodeError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "CgbiDecodeError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new CgbiDecodeError(code, message);
}

function bytesView(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  fail("invalid-input", "CgBI input must be an ArrayBuffer or byte view.");
}

function readU32(bytes, offset) {
  return (
    bytes[offset] * 0x1000000 +
    (bytes[offset + 1] << 16) +
    (bytes[offset + 2] << 8) +
    bytes[offset + 3]
  );
}

function chunkType(bytes, offset) {
  return String.fromCharCode(
    bytes[offset],
    bytes[offset + 1],
    bytes[offset + 2],
    bytes[offset + 3],
  );
}

function isPngSignature(bytes) {
  return (
    bytes.length >= PNG_SIGNATURE.length &&
    PNG_SIGNATURE.every((value, index) => bytes[index] === value)
  );
}

export function isCgbiPng(value) {
  let bytes;
  try {
    bytes = bytesView(value);
  } catch {
    return false;
  }
  return (
    bytes.length >= 24 &&
    isPngSignature(bytes) &&
    chunkType(bytes, 12) === "CgBI"
  );
}

function getCrcTable() {
  if (crcTable) return crcTable;
  crcTable = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    crcTable[index] = value >>> 0;
  }
  return crcTable;
}

function crc32(bytes, start, end) {
  const table = getCrcTable();
  let crc = 0xffffffff;
  for (let index = start; index < end; index += 1) {
    crc = table[(crc ^ bytes[index]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function bytesHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function isCriticalChunk(type) {
  return type.length === 4 && (type.charCodeAt(0) & 0x20) === 0;
}

function parseCgbi(bytes) {
  if (bytes.length > MAX_INPUT_BYTES) {
    fail("input-too-large", "CgBI PNG exceeds the 128 MiB input limit.");
  }
  if (!isPngSignature(bytes)) fail("not-png", "Input has no PNG signature.");

  let offset = 8;
  let chunkCount = 0;
  let width = 0;
  let height = 0;
  let colorType = -1;
  let bytesPerPixel = 0;
  let cgbiHeader = "";
  let seenCgbi = false;
  let seenIhdr = false;
  let seenPlte = false;
  let seenIdat = false;
  let idatEnded = false;
  let seenIend = false;
  let compressedBytes = 0;
  const idatParts = [];

  while (offset < bytes.length) {
    chunkCount += 1;
    if (chunkCount > MAX_CHUNKS) {
      fail("too-many-chunks", `CgBI PNG exceeds the ${MAX_CHUNKS}-chunk limit.`);
    }
    if (offset + 12 > bytes.length) {
      fail("truncated-chunk", "CgBI PNG ends inside a chunk header.");
    }

    const length = readU32(bytes, offset);
    const typeOffset = offset + 4;
    const dataOffset = offset + 8;
    const dataEnd = dataOffset + length;
    const chunkEnd = dataEnd + 4;
    if (!Number.isSafeInteger(chunkEnd) || chunkEnd > bytes.length) {
      fail("truncated-chunk", "CgBI PNG contains a truncated chunk payload.");
    }

    const type = chunkType(bytes, typeOffset);
    if (!/^[A-Za-z]{4}$/.test(type)) {
      fail("invalid-chunk-type", "CgBI PNG contains an invalid chunk type.");
    }
    if ((type.charCodeAt(2) & 0x20) !== 0) {
      fail("invalid-chunk-type", `PNG chunk ${type} has a lowercase reserved byte.`);
    }
    const expectedCrc = readU32(bytes, dataEnd);
    const actualCrc = crc32(bytes, typeOffset, dataEnd);
    if (expectedCrc !== actualCrc) {
      fail("crc-mismatch", `CgBI PNG ${type} chunk has an invalid CRC.`);
    }

    if (chunkCount === 1 && type !== "CgBI") {
      fail("not-cgbi", "CgBI must be the first PNG chunk.");
    }
    if (chunkCount === 2 && type !== "IHDR") {
      fail("missing-ihdr", "CgBI PNG must place IHDR immediately after CgBI.");
    }

    if (type === "CgBI") {
      if (seenCgbi || chunkCount !== 1 || length !== 4) {
        fail("invalid-cgbi", "CgBI PNG has an invalid CgBI chunk.");
      }
      cgbiHeader = bytesHex(bytes.subarray(dataOffset, dataEnd));
      if (!KNOWN_CGBI_HEADERS.has(cgbiHeader)) {
        fail(
          "unsupported-cgbi-version",
          `Unsupported CgBI bitmap header 0x${cgbiHeader}.`,
        );
      }
      seenCgbi = true;
    } else if (type === "IHDR") {
      if (!seenCgbi || seenIhdr || length !== 13) {
        fail("invalid-ihdr", "CgBI PNG has an invalid IHDR chunk.");
      }
      width = readU32(bytes, dataOffset);
      height = readU32(bytes, dataOffset + 4);
      const bitDepth = bytes[dataOffset + 8];
      colorType = bytes[dataOffset + 9];
      const compression = bytes[dataOffset + 10];
      const filter = bytes[dataOffset + 11];
      const interlace = bytes[dataOffset + 12];
      if (bitDepth !== 8) {
        fail("unsupported-bit-depth", "Only 8-bit CgBI PNGs are supported.");
      }
      if (colorType !== 2 && colorType !== 6) {
        fail(
          "unsupported-color-type",
          "Only RGB and RGBA CgBI PNGs are supported.",
        );
      }
      if (compression !== 0) {
        fail("unsupported-compression", "Unsupported CgBI compression method.");
      }
      if (filter !== 0) {
        fail("unsupported-filter-method", "Unsupported CgBI filter method.");
      }
      if (interlace !== 0) {
        fail("unsupported-interlace", "Interlaced CgBI PNGs are not supported.");
      }
      if (
        width < 1 ||
        height < 1 ||
        width > MAX_DIMENSION ||
        height > MAX_DIMENSION ||
        width > Math.floor(MAX_PIXELS / height)
      ) {
        fail(
          "dimensions-too-large",
          `CgBI dimensions exceed ${MAX_DIMENSION}px or ${MAX_PIXELS.toLocaleString()} pixels.`,
        );
      }
      bytesPerPixel = colorType === 6 ? 4 : 3;
      const filteredSize = (width * bytesPerPixel + 1) * height;
      const rgbaSize = width * height * 4;
      if (filteredSize > MAX_OUTPUT_BYTES || rgbaSize > MAX_OUTPUT_BYTES) {
        fail("output-too-large", "CgBI decoded output exceeds the 160 MiB limit.");
      }
      seenIhdr = true;
    } else if (type === "PLTE") {
      if (!seenIhdr || seenPlte || seenIdat || length < 3 || length > 768 || length % 3) {
        fail("invalid-plte", "CgBI PNG has an invalid PLTE chunk.");
      }
      seenPlte = true;
    } else if (type === "IDAT") {
      if (!seenIhdr || idatEnded || seenIend) {
        fail("invalid-chunk-order", "CgBI PNG has non-consecutive IDAT chunks.");
      }
      seenIdat = true;
      compressedBytes += length;
      if (compressedBytes > MAX_COMPRESSED_BYTES) {
        fail("compressed-data-too-large", "CgBI IDAT data exceeds 128 MiB.");
      }
      if (length) idatParts.push(bytes.subarray(dataOffset, dataEnd));
    } else if (type === "IEND") {
      if (!seenIdat || seenIend || length !== 0) {
        fail("invalid-iend", "CgBI PNG has an invalid IEND chunk.");
      }
      seenIend = true;
      if (chunkEnd !== bytes.length) {
        fail("trailing-data", "CgBI PNG contains data after IEND.");
      }
    } else {
      if (["acTL", "fcTL", "fdAT"].includes(type)) {
        fail("unsupported-animation", "Animated CgBI PNGs are not supported.");
      }
      if (["tRNS", "iCCP", "sRGB", "gAMA", "cHRM"].includes(type)) {
        fail(
          "unsupported-color-metadata",
          `CgBI PNG ${type} metadata cannot be safely preserved by this decoder.`,
        );
      }
      if (isCriticalChunk(type)) {
        fail("unknown-critical-chunk", `Unsupported critical PNG chunk ${type}.`);
      }
      if (seenIdat) idatEnded = true;
    }

    offset = chunkEnd;
    if (seenIend) break;
  }

  if (!seenCgbi) fail("not-cgbi", "Input has no CgBI chunk.");
  if (!seenIhdr) fail("missing-ihdr", "CgBI PNG has no IHDR chunk.");
  if (!seenIdat || compressedBytes === 0) {
    fail("missing-idat", "CgBI PNG has no compressed image data.");
  }
  if (!seenIend) fail("missing-iend", "CgBI PNG has no IEND chunk.");

  return {
    width,
    height,
    colorType,
    bytesPerPixel,
    cgbiHeader,
    idatParts,
    compressedBytes,
    chunkCount,
  };
}

function paeth(left, above, upperLeft) {
  const estimate = left + above - upperLeft;
  const leftDistance = Math.abs(estimate - left);
  const aboveDistance = Math.abs(estimate - above);
  const upperLeftDistance = Math.abs(estimate - upperLeft);
  if (leftDistance <= aboveDistance && leftDistance <= upperLeftDistance) {
    return left;
  }
  return aboveDistance <= upperLeftDistance ? above : upperLeft;
}

function straightChannel(value, alpha) {
  // Match Apple's own pngcrush reversal. Alpha-zero source colour cannot be
  // reconstructed, so retain the stored channel after swapping R/B.
  if (alpha === 0 || alpha === 255) return value;
  return Math.min(255, Math.floor((value * 255) / alpha));
}

async function inflatePixels(parsed) {
  if (typeof DecompressionStream !== "function") {
    fail(
      "inflate-unavailable",
      "This browser does not provide raw DEFLATE decompression.",
    );
  }

  const rowBytes = parsed.width * parsed.bytesPerPixel;
  const expectedInflatedBytes = (rowBytes + 1) * parsed.height;
  const rgba = new Uint8Array(parsed.width * parsed.height * 4);
  let previous = new Uint8Array(rowBytes);
  let current = new Uint8Array(rowBytes);
  let row = 0;
  let column = -1;
  let filterType = -1;
  let inflatedBytes = 0;
  let hasAlpha = false;

  let reader;
  try {
    const stream = new Blob(parsed.idatParts)
      .stream()
      .pipeThrough(new DecompressionStream("deflate-raw"));
    reader = stream.getReader();
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      for (let index = 0; index < value.length; index += 1) {
        inflatedBytes += 1;
        if (inflatedBytes > expectedInflatedBytes) {
          fail("inflated-data-too-large", "CgBI produced more scanline data than declared.");
        }

        const byte = value[index];
        if (column === -1) {
          if (byte > 4) {
            fail("unsupported-row-filter", `CgBI row ${row} uses PNG filter ${byte}.`);
          }
          filterType = byte;
          column = 0;
          continue;
        }

        const left = column >= parsed.bytesPerPixel
          ? current[column - parsed.bytesPerPixel]
          : 0;
        const above = row > 0 ? previous[column] : 0;
        const upperLeft = row > 0 && column >= parsed.bytesPerPixel
          ? previous[column - parsed.bytesPerPixel]
          : 0;
        let reconstructed;
        if (filterType === 0) reconstructed = byte;
        else if (filterType === 1) reconstructed = byte + left;
        else if (filterType === 2) reconstructed = byte + above;
        else if (filterType === 3) {
          reconstructed = byte + Math.floor((left + above) / 2);
        } else {
          reconstructed = byte + paeth(left, above, upperLeft);
        }
        current[column] = reconstructed & 0xff;
        column += 1;

        if (column === rowBytes) {
          let source = 0;
          let destination = row * parsed.width * 4;
          for (let pixel = 0; pixel < parsed.width; pixel += 1) {
            const blue = current[source];
            const green = current[source + 1];
            const red = current[source + 2];
            if (parsed.colorType === 6) {
              const alpha = current[source + 3];
              rgba[destination] = straightChannel(red, alpha);
              rgba[destination + 1] = straightChannel(green, alpha);
              rgba[destination + 2] = straightChannel(blue, alpha);
              rgba[destination + 3] = alpha;
              if (alpha !== 255) hasAlpha = true;
              source += 4;
            } else {
              rgba[destination] = red;
              rgba[destination + 1] = green;
              rgba[destination + 2] = blue;
              rgba[destination + 3] = 255;
              source += 3;
            }
            destination += 4;
          }
          const swap = previous;
          previous = current;
          current = swap;
          row += 1;
          column = -1;
          filterType = -1;
        }
      }
    }
  } catch (error) {
    if (error instanceof CgbiDecodeError) throw error;
    fail("inflate-failed", `Could not inflate CgBI image data: ${error?.message || error}`);
  } finally {
    if (reader && row !== parsed.height) {
      try {
        await reader.cancel();
      } catch {
        // Best effort: the worker is disposable and the fixed buffers are bounded.
      }
    }
  }

  if (
    inflatedBytes !== expectedInflatedBytes ||
    row !== parsed.height ||
    column !== -1
  ) {
    fail(
      "inflated-size-mismatch",
      `CgBI decoded ${inflatedBytes} scanline bytes; expected ${expectedInflatedBytes}.`,
    );
  }
  return { rgba, hasAlpha, inflatedBytes };
}

/**
 * Normalize a safely supported CgBI PNG to straight, conventional RGBA pixels.
 * Unsupported or malformed variants throw CgbiDecodeError and claim no saving.
 */
export async function normalizeCgbiPng(value) {
  const bytes = bytesView(value);
  const parsed = parseCgbi(bytes);
  const decoded = await inflatePixels(parsed);
  return {
    width: parsed.width,
    height: parsed.height,
    rgba: decoded.rgba,
    hasAlpha: decoded.hasAlpha,
    diagnostics: {
      decoder: "cgbi-rgba8",
      cgbiHeader: parsed.cgbiHeader,
      colorType: parsed.colorType === 6 ? "rgba" : "rgb",
      chunkCount: parsed.chunkCount,
      idatChunkCount: parsed.idatParts.length,
      compressedBytes: parsed.compressedBytes,
      inflatedBytes: decoded.inflatedBytes,
    },
  };
}
