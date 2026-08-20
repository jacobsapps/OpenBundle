import assert from "node:assert/strict";
import test from "node:test";
import { deflateRawSync } from "node:zlib";

import {
  CgbiDecodeError,
  isCgbiPng,
  normalizeCgbiPng,
} from "../web/cgbi.mjs";

const SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data = Buffer.alloc(0)) {
  const name = Buffer.from(type, "ascii");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const checksum = Buffer.alloc(4);
  checksum.writeUInt32BE(crc32(Buffer.concat([name, data])));
  return Buffer.concat([length, name, data, checksum]);
}

function paeth(left, above, upperLeft) {
  const estimate = left + above - upperLeft;
  const distances = [
    Math.abs(estimate - left),
    Math.abs(estimate - above),
    Math.abs(estimate - upperLeft),
  ];
  if (distances[0] <= distances[1] && distances[0] <= distances[2]) return left;
  return distances[1] <= distances[2] ? above : upperLeft;
}

function filteredRow(row, previous, bytesPerPixel, filter) {
  const output = Buffer.alloc(row.length + 1);
  output[0] = filter;
  for (let index = 0; index < row.length; index += 1) {
    const left = index >= bytesPerPixel ? row[index - bytesPerPixel] : 0;
    const above = previous?.[index] || 0;
    const upperLeft = previous && index >= bytesPerPixel
      ? previous[index - bytesPerPixel]
      : 0;
    let prediction = 0;
    if (filter === 1) prediction = left;
    else if (filter === 2) prediction = above;
    else if (filter === 3) prediction = Math.floor((left + above) / 2);
    else if (filter === 4) prediction = paeth(left, above, upperLeft);
    output[index + 1] = (row[index] - prediction) & 0xff;
  }
  return output;
}

function premultiply(value, alpha) {
  return Math.round((value * alpha) / 255);
}

function makeCgbi({ width, height, colorType, pixels, filters, splitIdat = false }) {
  const bytesPerPixel = colorType === 6 ? 4 : 3;
  const rows = [];
  let previous;
  for (let y = 0; y < height; y += 1) {
    const bgra = Buffer.alloc(width * bytesPerPixel);
    for (let x = 0; x < width; x += 1) {
      const source = (y * width + x) * 4;
      const destination = x * bytesPerPixel;
      const red = pixels[source];
      const green = pixels[source + 1];
      const blue = pixels[source + 2];
      const alpha = pixels[source + 3];
      if (colorType === 6) {
        bgra[destination] = premultiply(blue, alpha);
        bgra[destination + 1] = premultiply(green, alpha);
        bgra[destination + 2] = premultiply(red, alpha);
        bgra[destination + 3] = alpha;
      } else {
        bgra[destination] = blue;
        bgra[destination + 1] = green;
        bgra[destination + 2] = red;
      }
    }
    rows.push(filteredRow(bgra, previous, bytesPerPixel, filters[y]));
    previous = bgra;
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = colorType;
  const compressed = deflateRawSync(Buffer.concat(rows));
  const idats = splitIdat
    ? [
        chunk("IDAT", compressed.subarray(0, Math.floor(compressed.length / 2))),
        chunk("IDAT", compressed.subarray(Math.floor(compressed.length / 2))),
      ]
    : [chunk("IDAT", compressed)];
  return Buffer.concat([
    SIGNATURE,
    chunk("CgBI", Buffer.from([0x50, 0x00, 0x20, 0x06])),
    chunk("IHDR", ihdr),
    chunk("iDOT", Buffer.alloc(28)),
    ...idats,
    chunk("IEND"),
  ]);
}

test("normalizes filtered, split-IDAT RGBA CgBI without mutating input", async () => {
  const pixels = Buffer.from([
    255, 120, 0, 255,
    120, 60, 30, 85,
    0, 90, 180, 255,
    0, 0, 0, 0,
    30, 60, 90, 255,
    150, 90, 30, 170,
    210, 180, 150, 255,
    60, 120, 180, 255,
    12, 24, 36, 255,
    240, 210, 180, 255,
  ]);
  const input = makeCgbi({
    width: 2,
    height: 5,
    colorType: 6,
    pixels,
    filters: [0, 1, 2, 3, 4],
    splitIdat: true,
  });
  const before = Buffer.from(input);

  assert.equal(isCgbiPng(input), true);
  const result = await normalizeCgbiPng(input);

  assert.equal(result.width, 2);
  assert.equal(result.height, 5);
  assert.equal(result.hasAlpha, true);
  assert.deepEqual(Buffer.from(result.rgba), pixels);
  assert.deepEqual(input, before);
  assert.equal(result.diagnostics.idatChunkCount, 2);
  assert.equal(result.diagnostics.colorType, "rgba");
});

test("normalizes opaque RGB CgBI and reports no alpha", async () => {
  const pixels = Buffer.from([
    10, 20, 30, 255,
    40, 50, 60, 255,
  ]);
  const input = makeCgbi({
    width: 2,
    height: 1,
    colorType: 2,
    pixels,
    filters: [1],
  });
  const result = await normalizeCgbiPng(input);
  assert.deepEqual(Buffer.from(result.rgba), pixels);
  assert.equal(result.hasAlpha, false);
  assert.equal(result.diagnostics.colorType, "rgb");
});

test("fails closed on unsupported and malformed CgBI variants", async () => {
  const pixels = Buffer.from([10, 20, 30, 255]);
  const valid = makeCgbi({
    width: 1,
    height: 1,
    colorType: 6,
    pixels,
    filters: [0],
  });

  const badCrc = Buffer.from(valid);
  badCrc[20] ^= 0xff;
  await assert.rejects(
    normalizeCgbiPng(badCrc),
    (error) => error instanceof CgbiDecodeError && error.code === "crc-mismatch",
  );

  const interlaced = Buffer.from(valid);
  const ihdrDataOffset = 8 + 12 + 4 + 8;
  interlaced[ihdrDataOffset + 12] = 1;
  const ihdrTypeOffset = ihdrDataOffset - 4;
  interlaced.writeUInt32BE(
    crc32(interlaced.subarray(ihdrTypeOffset, ihdrDataOffset + 13)),
    ihdrDataOffset + 13,
  );
  await assert.rejects(
    normalizeCgbiPng(interlaced),
    (error) => error instanceof CgbiDecodeError && error.code === "unsupported-interlace",
  );

  const oversized = Buffer.from(valid);
  oversized.writeUInt32BE(16_385, ihdrDataOffset);
  oversized.writeUInt32BE(
    crc32(oversized.subarray(ihdrTypeOffset, ihdrDataOffset + 13)),
    ihdrDataOffset + 13,
  );
  await assert.rejects(
    normalizeCgbiPng(oversized),
    (error) => error instanceof CgbiDecodeError && error.code === "dimensions-too-large",
  );

  const unsupportedFilter = makeCgbi({
    width: 1,
    height: 1,
    colorType: 6,
    pixels,
    filters: [5],
  });
  await assert.rejects(
    normalizeCgbiPng(unsupportedFilter),
    (error) => error instanceof CgbiDecodeError && error.code === "unsupported-row-filter",
  );

  assert.equal(isCgbiPng(Buffer.from("not a png")), false);
});
