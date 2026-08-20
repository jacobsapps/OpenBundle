# Vendored Pyodide runtime

OpenBundle self-hosts Pyodide `314.0.4` so executable code that receives an IPA
does not come from a third-party CDN at runtime.

Run `python3 scripts/vendor_pyodide.py` to reproduce the files and
`python3 scripts/vendor_pyodide.py --check` to verify their SHA-256 digests.
The runtime is distributed under the Mozilla Public License 2.0; its unmodified
license is copied beside the runtime and into every web build.
