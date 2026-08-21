#!/usr/bin/env python3
"""Build the static browser host and its shared Python core archive."""

from __future__ import annotations

from argparse import ArgumentParser
from pathlib import Path
import shutil
import zipfile


ROOT = Path(__file__).resolve().parents[1]
WEB_SOURCE = ROOT / "web"
PACKAGE_SOURCE = ROOT / "src" / "openbundle"
DEFAULT_OUTPUT = ROOT / "dist" / "web"
STATIC_FILES = (
    ".nojekyll",
    "index.html",
    "app.css",
    "app.js",
    "analysis-compare.mjs",
    "analysis-library.mjs",
    "analyzer-worker.mjs",
    "car-analysis.mjs",
    "cgbi.mjs",
    "tavern-logo.png",
)
PYODIDE_FILES = (
    "LICENSE",
    "pyodide-lock.json",
    "pyodide.asm.mjs",
    "pyodide.asm.wasm",
    "pyodide.mjs",
    "python_stdlib.zip",
)


def build(output: Path) -> Path:
    output.mkdir(parents=True, exist_ok=True)
    for name in STATIC_FILES:
        shutil.copy2(WEB_SOURCE / name, output / name)

    # The asset-catalog decoder is deliberately vendored and pinned.  Copy its
    # small browser runtime plus the upstream MIT notice into every deployable
    # build so a static host needs no package manager or build server.
    runtime_source = WEB_SOURCE / "vendor" / "car-parser"
    runtime_output = output / "vendor" / "car-parser"
    runtime_output.mkdir(parents=True, exist_ok=True)
    for name in ("car_wasm.js", "car_wasm_bg.wasm"):
        shutil.copy2(runtime_source / name, runtime_output / name)
    shutil.copy2(
        ROOT / "vendor" / "car-parser" / "LICENSE",
        runtime_output / "LICENSE",
    )

    font_source = WEB_SOURCE / "fonts"
    font_output = output / "fonts"
    if font_output.exists():
        shutil.rmtree(font_output)
    shutil.copytree(font_source, font_output)

    # Pyodide is self-hosted so the worker never executes remote code before
    # receiving the user's IPA bytes.
    pyodide_source = ROOT / "vendor" / "pyodide"
    pyodide_output = output / "vendor" / "pyodide"
    pyodide_output.mkdir(parents=True, exist_ok=True)
    for name in PYODIDE_FILES:
        shutil.copy2(pyodide_source / name, pyodide_output / name)

    core_path = output / "openbundle-core.zip"
    with zipfile.ZipFile(
        core_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for source in sorted(PACKAGE_SOURCE.rglob("*")):
            if not source.is_file() or "__pycache__" in source.parts:
                continue
            if source.suffix not in {".py", ".html"}:
                continue
            relative = source.relative_to(PACKAGE_SOURCE.parent)
            archive.write(source, relative.as_posix())
    return output


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Static output directory (default: {DEFAULT_OUTPUT})",
    )
    args = parser.parse_args()
    output = build(args.output.expanduser().resolve())
    print(output)


if __name__ == "__main__":
    main()
