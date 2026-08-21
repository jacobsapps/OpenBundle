# OpenBundle browser host

This is the OpenBundle product host. Pyodide runs the portable Python analysis
engine in a Web Worker, while a pinned Rust/WASM helper inspects compiled Apple
asset catalogs. The worker produces a self-contained HTML report; bundle bytes
never leave the browser.

The worker also contains a bounded decoder for Apple CgBI-crushed loose PNGs.
Unsupported catalog codecs and image encoders are excluded from findings.
Compiled image assets retain compact rendition metadata and up to 96 bounded
thumbnails for the report's image inspector.

The host keeps completed report JSON in IndexedDB for History and Compare. It
does not persist IPA bytes or imported HTML. Storage is local to the current
browser profile and site origin.

The landing-page fonts are served from `web/fonts`; loading OpenBundle does not
contact a third-party font CDN.

Build it from the repository root:

```bash
python3 scripts/build_web.py
python3 -m http.server 8000 --directory dist/web
```

Then open <http://localhost:8000>. Do not open `index.html` with a `file:` URL:
workers and the packaged core require an HTTP origin.

Every runtime URL is relative, so the output can be deployed at a subpath such
as `/openbundle/`. The built site has no server-side analyzer: any ordinary
static host is sufficient.
