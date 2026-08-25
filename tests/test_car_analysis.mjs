import assert from "node:assert/strict";
import test from "node:test";

import {
  encodedImageDimensions,
  estimateLatestIPhoneCatalog,
  pixelsAreSafe,
  selectPhysicalConversionRendition,
  serializedConversionEstimate,
} from "../web/car-analysis.mjs";

function thinningEntry(
  name,
  size,
  traits,
  { layout = "one-part-scale", extension = ".png", extra = [] } = {},
) {
  return {
    facet_name: name,
    rendition_name: `${name}${extension}`,
    size_on_disk: size,
    logical_layout: layout,
    attributes: [
      { tag: 17, value: 100 },
      { tag: 1, value: 85 },
      ...extra.map(([tag, value]) => ({ tag, value })),
      ...Object.entries(traits).map(([tag, value]) => ({
        tag: Number(tag),
        value,
      })),
    ],
  };
}

function pngHeader(width, height, { cgbi = false } = {}) {
  const prefix = [137, 80, 78, 71, 13, 10, 26, 10];
  const chunk = (type, payload) => [
    0, 0, 0, payload.length,
    ...new TextEncoder().encode(type),
    ...payload,
    0, 0, 0, 0,
  ];
  const u32 = (value) => [
    (value >>> 24) & 255,
    (value >>> 16) & 255,
    (value >>> 8) & 255,
    value & 255,
  ];
  return new Uint8Array([
    ...prefix,
    ...(cgbi ? chunk("CgBI", [0x50, 0, 0x20, 0x02]) : []),
    ...chunk("IHDR", [...u32(width), ...u32(height), 8, 6, 0, 0, 0]),
  ]);
}

function jpegHeader(width, height) {
  return new Uint8Array([
    0xff, 0xd8,
    0xff, 0xe0, 0, 4, 0, 0,
    0xff, 0xc0, 0, 11, 8,
    (height >>> 8) & 255, height & 255,
    (width >>> 8) & 255, width & 255,
    1, 1, 0x11, 0,
  ]);
}

function rendition(
  id,
  scale,
  {
    width = 100,
    height = 100,
    size = 100_000,
    kind = "image",
    layout = "one-part-scale",
    name = id,
  } = {},
) {
  return {
    id,
    entry_kind: kind,
    logical_layout: layout,
    rendition_name: name,
    scale,
    width,
    height,
    size_on_disk: size,
  };
}

test("CAR decode limits bound both dimensions and total pixels", () => {
  assert.equal(pixelsAreSafe(4096, 4096), true);
  assert.equal(pixelsAreSafe(8192, 2048), true);
  assert.equal(pixelsAreSafe(8193, 1), false);
  assert.equal(pixelsAreSafe(4097, 4096), false);
  assert.equal(pixelsAreSafe(0, 100), false);
  assert.equal(pixelsAreSafe(Number.MAX_SAFE_INTEGER, 1), false);
});

test("reads bounded PNG, CgBI PNG, and JPEG dimensions before decode", () => {
  assert.deepEqual(encodedImageDimensions(pngHeader(1200, 800), "image/png"), {
    width: 1200,
    height: 800,
  });
  assert.deepEqual(
    encodedImageDimensions(pngHeader(9000, 1, { cgbi: true }), "image/png"),
    { width: 9000, height: 1 },
  );
  assert.deepEqual(encodedImageDimensions(jpegHeader(640, 480), "image/jpeg"), {
    width: 640,
    height: 480,
  });
  assert.equal(encodedImageDimensions(new Uint8Array([1, 2, 3]), "image/png"), null);
});

test("conversion savings preserve serialized CoreUI overhead", () => {
  assert.deepEqual(serializedConversionEstimate(1100, 900, 200, 500), {
    optimizedSize: 700,
    saving: 400,
  });
});

test("conversion savings fail closed on inconsistent size boundaries", () => {
  assert.equal(serializedConversionEstimate(1100, 899, 200, 500), null);
  assert.equal(serializedConversionEstimate(1100, 900, -1, 500), null);
  assert.equal(serializedConversionEstimate(1100, 900, 200, 0), null);
  assert.equal(
    serializedConversionEstimate(
      Number.MAX_SAFE_INTEGER,
      Number.MAX_SAFE_INTEGER - 1,
      1,
      Number.MAX_SAFE_INTEGER,
    ),
    null,
  );
});

test("conversion selection prefers the exact physical 3x rendition", () => {
  const two = rendition("two", 2, { width: 4000, height: 4000, size: 900_000 });
  const three = rendition("three", 3, { width: 30, height: 30, size: 1_000 });
  const four = rendition("four", 4, { width: 5000, height: 5000, size: 1_000_000 });
  const internalThree = rendition("reference", 3, {
    width: 6000,
    height: 6000,
    size: 2_000_000,
    layout: "internal-reference",
  });

  assert.equal(
    selectPhysicalConversionRendition([
      four,
      internalThree,
      two,
      three,
    ]),
    three,
  );
});

test("conversion selection follows bounded scale fallbacks", () => {
  const one = rendition("one", 1, { size: 500_000 });
  const two = rendition("two", 2, { size: 1_000 });
  const four = rendition("four", 4, { size: 900_000 });
  const five = rendition("five", 5, { size: 1_000_000 });
  const unscaled = rendition("unscaled", 0, { size: 2_000_000 });

  assert.equal(
    selectPhysicalConversionRendition([unscaled, five, four, one, two]),
    two,
  );
  assert.equal(
    selectPhysicalConversionRendition([unscaled, five, four]),
    four,
  );
  assert.equal(selectPhysicalConversionRendition([unscaled]), unscaled);
});

test("conversion selection breaks same-scale ties by area then size", () => {
  const small = rendition("small", 3, { width: 100, height: 100, size: 900_000 });
  const largeArea = rendition("large-area", 3, {
    width: 200,
    height: 100,
    size: 1_000,
  });
  const largeAreaAndSize = rendition("large-area-size", 3, {
    width: 100,
    height: 200,
    size: 2_000,
  });

  assert.equal(
    selectPhysicalConversionRendition([small, largeArea, largeAreaAndSize]),
    largeAreaAndSize,
  );
});

test("conversion selection has an input-order-independent final tie break", () => {
  const alpha = rendition("alpha", 3, { name: "Alpha" });
  const zulu = rendition("zulu", 3, { name: "Zulu" });
  assert.equal(selectPhysicalConversionRendition([alpha, zulu]), zulu);
  assert.equal(selectPhysicalConversionRendition([zulu, alpha]), zulu);
});

test("conversion selection ignores non-images, references, and empty payloads", () => {
  assert.equal(
    selectPhysicalConversionRendition([
      rendition("document", 3, { kind: "document" }),
      rendition("reference", 3, { layout: "internal-reference" }),
      rendition("empty", 3, { size: 0 }),
    ]),
    null,
  );
});

test("latest-iPhone catalog estimate selects 3x P3 rendition bytes", () => {
  const entries = [
    thinningEntry("Artwork", 100, { 12: 2, 15: 0, 24: 0 }),
    thinningEntry("Artwork", 200, { 12: 2, 15: 0, 24: 1 }),
    thinningEntry("Artwork", 300, { 12: 3, 15: 0, 24: 0 }),
    thinningEntry("Artwork", 400, { 12: 3, 15: 0, 24: 1 }),
  ];

  assert.deepEqual(estimateLatestIPhoneCatalog(entries, 1_500), {
    complete: true,
    target: "latest-iphone",
    estimatedSize: 525,
    universalSize: 1_500,
    universalRenditionSize: 1_000,
    selectedRenditionSize: 400,
    metadataSize: 125,
    entryCount: 4,
    selectedEntryCount: 1,
  });
});

test("latest-iPhone catalog estimate drops tablet idioms but keeps lone-scale fallbacks", () => {
  const entries = [
    thinningEntry("AppMark", 200, { 12: 1, 15: 1, 24: 0 }),
    thinningEntry("AppMark", 180, { 12: 1, 15: 1, 24: 1 }),
    thinningEntry("AppMark", 220, { 12: 1, 15: 2, 24: 0 }),
    thinningEntry("AppMark", 210, { 12: 1, 15: 2, 24: 1 }),
  ];

  const estimate = estimateLatestIPhoneCatalog(entries, 1_210);
  assert.equal(estimate.selectedRenditionSize, 380);
  assert.equal(estimate.selectedEntryCount, 2);
  assert.equal(estimate.estimatedSize, 580);
});

test("latest-iPhone catalog estimate retains vector source references", () => {
  const entries = [
    thinningEntry("VectorMark", 250, { 12: 1, 15: 0 }, {
      layout: "vector",
      extension: ".svg",
      extra: [[2, 42]],
    }),
    thinningEntry("VectorMark", 20, { 12: 1, 15: 0 }, {
      layout: "internal-reference",
      extension: ".svg",
      extra: [[2, 181]],
    }),
    thinningEntry("VectorMark", 20, { 12: 2, 15: 0 }, {
      layout: "internal-reference",
      extension: ".svg",
      extra: [[2, 181]],
    }),
    thinningEntry("VectorMark", 20, { 12: 3, 15: 0 }, {
      layout: "internal-reference",
      extension: ".svg",
      extra: [[2, 181]],
    }),
  ];

  const estimate = estimateLatestIPhoneCatalog(entries, 510);
  assert.equal(estimate.selectedRenditionSize, 290);
  assert.equal(estimate.selectedEntryCount, 3);
  assert.equal(estimate.estimatedSize, 440);
});

test("latest-iPhone catalog estimate fails closed on incomplete entries", () => {
  assert.deepEqual(
    estimateLatestIPhoneCatalog(
      [{ facet_name: "Broken", size_on_disk: 0, attributes: [] }],
      900,
    ),
    {
      complete: false,
      estimatedSize: 900,
      universalSize: 900,
      entryCount: 0,
      selectedEntryCount: 0,
    },
  );
});
