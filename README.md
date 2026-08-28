# OpenBundle

OpenBundle is a browser-local iOS bundle analyzer. Drop an `.ipa` or zipped app
archive into the page and it produces an interactive treemap and evidence-backed
recommendations without uploading the bundle.

The product is deliberately browser-only. The Python analysis engine and HTML
report renderer stay host-neutral so another thin host can be added later, but
there is no supported CLI or macOS executable.

## What the browser checks

| Check | Browser implementation |
| --- | --- |
| Remove duplicate files | SHA-256 and exact byte size for files, plus decoded rendition identity for asset catalogs; same-runtime copies are recommendations, cross-target file repeats stay Architecture evidence, and cross-target catalog overlap is also marked in the treemap |
| Enable image thinning | Groups loose `@1x`/`@2x`/`@3x` sets by path and estimates the per-device unpacked bytes asset-catalog thinning can avoid |
| Optimize images | Measures quality-85 conversions for loose images and supported catalog renditions; requires at least 4 KB of measured saving |
| Strip binary symbols | Parses 32- and 64-bit Mach-O symbol and string tables and models `strip -rSTx` without invoking Apple tools |
| Remove binary symbol metadata | Parses modern and legacy dyld export tries, counts executable exports, and estimates reducible metadata |
| Review static linking | Resolves `LC_RPATH` load commands to embedded frameworks and ranks one-consumer review candidates by shipped size |

The report shows recommendations of 100 KB or more, ordered by saving. Each
recommendation expands into its measured files, binaries, renditions, or scale
sets.

## Download and install size

The headline **Download** and **Install** values model the bundle delivered to
a current 3x P3 iPhone, rather than reporting the universal IPA and `.app`
sizes under App Store labels. OpenBundle selects device-compatible CoreUI
renditions, retains runtime fallbacks, selects the arm64/arm64e slice from fat
Mach-O files, and recomputes the parent hierarchy from those delivered bytes.

Install is the uncompressed thinned app payload. Download is the corresponding
compressed payload plus ZIP container overhead. CoreUI metadata and compressed
member sizes are estimated because the browser cannot run Apple's App Store
processing pipeline. The report keeps the raw universal, compressed-member,
and source-artifact sizes in JSON for auditability and marks the headline
values as a latest-iPhone estimate.

## Report views

- Bundle map and size-ranked recommendations
- Images with one representative rendition per asset
- Targets, embedded frameworks, linker consumers, cross-target repeats, and static/mergeable reviews
- Mach-O binaries with strip/export opportunities and section composition
- Declared capabilities, privacy manifests, and entitlements
- App and component localizations

Completed analyses are saved as report JSON in IndexedDB. IPA bytes and imported
HTML are never stored. Saved reports can be reopened, exported, or compared with
another saved/imported report or a newly analyzed IPA. This library belongs to
the current browser profile and origin; clearing site data removes it.

## Run the browser app locally

```bash
python3 scripts/build_web.py
python3 -m http.server 8000 --directory dist/web
```

Open <http://localhost:8000> and choose an `.ipa` or `.zip`. Do not open the
HTML through a `file:` URL: Web Workers and the packaged core require an HTTP
origin.

`dist/web` is a static site with relative application URLs, so it can be copied
to a subpath such as `/openbundle/` on Vercel, GitHub Pages, S3, or any other
static host. There is no analysis API and no uploaded bundle to secure.

`vercel.json` builds that directory directly and applies the production CSP and
privacy headers. A dedicated origin is recommended because IndexedDB is scoped
to an origin, not to a URL path.

## Architecture

```text
Browser page
  └─ Web Worker
       ├─ Pyodide → shared Python inventory, Mach-O checks, recommendations
       ├─ pinned CAR WASM → asset rendition metadata, decoding, content hashes
       └─ Canvas encoders → measured HEIC/JPEG opportunities when supported
            └─ self-contained report JSON + HTML → treemap UI
```

The boundaries are intentional:

- `src/openbundle/analyzer.py` owns policy and recommendation thresholds.
- `src/openbundle/macho.py` is a bounded, platform-neutral Mach-O parser.
- `src/openbundle/platform.py` injects host measurements into the shared engine.
- `web/analyzer-worker.mjs` owns browser orchestration and memory lifecycle.
- `web/car-analysis.mjs` turns asset-catalog WASM output into compact evidence.
- `web/cgbi.mjs` safely normalizes Apple-crushed loose PNGs for measurement.
- `src/openbundle/templates/report.html` is the self-contained report UI.

The browser extracts an artifact in Pyodide's temporary filesystem, processes
catalog renditions sequentially, and passes compact measurements back to the
Python engine. Full decoded pixels are released after each rendition. The
standalone report retains bounded thumbnails for up to 96 image assets. Very
large archives still require substantial memory while their compressed upload,
expanded app, and transient WASM image buffers coexist, so the page warns
before opening an archive over 500 MB and rejects archives over 700 MB.

## Asset-catalog accuracy

The CAR parser is vendored at an exact upstream commit and patched to expose
physical rendition sizes and opacity. Its license, pin, patch, and rebuild
instructions live under `vendor/car-parser/`; the deployable WASM runtime lives
under `web/vendor/car-parser/`.

Compiled asset catalogs contain several Apple-specific codecs. OpenBundle
records supported/unsupported output counts and decode failures in the report.
An unsupported rendition never becomes a claimed duplicate or image saving.

Loose Apple CgBI PNGs are normalized in the worker by a bounded decoder before
measurement. It validates chunk CRCs and dimensions, supports only known 8-bit
RGB/RGBA non-interlaced variants, and fails closed on malformed input.

HEIC is used only when the current browser actually returns HEIC bytes. Opaque
images can use a measured JPEG quality-85 fallback; transparent images are not
silently flattened. Full transparent-image parity will require a reviewed,
alpha-capable HEIC WASM encoder.

## Binary checks

Symbol stripping and exported-symbol analysis do not shell out. The parser
handles thin and fat binaries, both `nlist` layouts, `LC_DYSYMTAB`, modern
`LC_DYLD_EXPORTS_TRIE`, and legacy `LC_DYLD_INFO(_ONLY)` export tries with
strict range and traversal limits.

The two findings are intentionally separate:

- `strip-symbols` estimates removable local, debug, and eligible Swift symbol
  records plus their referenced string-table bytes. Matching dSYMs must be
  generated and uploaded before stripping.
- `exported-symbols` estimates export-trie and external-symbol metadata that a
  reviewed `EXPORTED_SYMBOLS_FILE` may remove. It preserves `_main` in its model,
  calls out `__mh_execute_header`/Crashlytics, and warns about `dlsym` and plug-in
  entry points.

The bundle map and expanded Binaries view also split non-section
`__LINKEDIT` data by its load-command file ranges. One `LC_SYMTAB` parent
contains the fixed-size Symbol records and separate Symbol string table;
export tries, fixups, dynamic-linking tables, code signatures, and remaining
`__LINKEDIT` bytes are attributed without double-counting.

The Architecture view resolves load-command consumers but does not invent a
static-linking saving. Predicting dead stripping requires the original static
archive, link map, or dSYM; an IPA alone cannot reconstruct linker object
boundaries safely.

See Emerge's original explanations for the build-setting context:

- [Strip binary symbols](https://docs.emergetools.com/docs/strip-binary-symbols)
- [Exported-symbol metadata](https://docs.emergetools.com/docs/export-symbols-metadata)
- [Remove duplicate files](https://docs.emergetools.com/docs/remove-duplicates)
- [Optimize images](https://docs.emergetools.com/docs/optimize-images)

## Development

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m py_compile src/openbundle/*.py
node --check web/app.js
node --check web/analyzer-worker.mjs
node --check web/car-analysis.mjs
python3 scripts/build_web.py
```

To rebuild the vendored CAR runtime, install Rust, `wasm-pack`, and
`wasm-opt`, then run:

```bash
scripts/build_car_wasm.sh
```

The six local test IPAs and generated browser reports belong in `ipas/` and
`exports/`; both directories are ignored by Git.

## Privacy and runtime dependencies

Bundle analysis stays in the tab. The Pyodide runtime, asset-catalog decoder,
and landing-page typefaces are pinned and self-hosted; selected files never
reach third-party code. Downloaded reports contain their CSS and JavaScript
inline and need no server to remain interactive.

OpenBundle is MIT licensed. The vendored CAR parser retains its upstream MIT
notice, the self-hosted Pyodide runtime retains its MPL-2.0 notice, and the
typefaces retain their Apache-2.0/OFL-1.1 notices in every built static
distribution.

OpenBundle is an independent project and is not affiliated with or endorsed by
Emerge Tools or Sentry.
