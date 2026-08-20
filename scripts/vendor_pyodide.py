#!/usr/bin/env python3
"""Download or verify the exact Pyodide runtime shipped by OpenBundle."""

from __future__ import annotations

from argparse import ArgumentParser
import hashlib
from pathlib import Path
import tempfile
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "vendor" / "pyodide"
VERSION = "314.0.4"
BASE_URL = f"https://cdn.jsdelivr.net/pyodide/v{VERSION}/full"
FILES = {
    "pyodide.mjs": "c75dd73bb0c70674135f9f4ab746c9b5316e9fe027cafacb2be445e658f04c92",
    "pyodide.asm.mjs": "fd7a3cefa122ff6463dcf2997961eb341250e4cc4ed60281448390f0a767cca2",
    "pyodide.asm.wasm": "6c8986a8ee583401069aa403e76ee79d4633a1478ab11cea76030bc299aded9f",
    "python_stdlib.zip": "b5ca2308e9fa72eda319889a1ddf086389e9f1234ced279cc71267fe9ba56e54",
    "pyodide-lock.json": "c963d22858f6bcb8f41586a2142f03905ab370c88ea22a86a2736e95fac2a8f3",
    "LICENSE": "1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5",
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def source_url(name: str) -> str:
    if name == "LICENSE":
        return f"https://raw.githubusercontent.com/pyodide/pyodide/{VERSION}/LICENSE"
    return f"{BASE_URL}/{name}"


def verify(directory: Path) -> None:
    for name, expected in FILES.items():
        path = directory / name
        if not path.is_file() or digest(path) != expected:
            raise SystemExit(f"Missing or invalid vendored Pyodide file: {path}")


def download() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="openbundle-pyodide-") as temporary:
        staging = Path(temporary)
        for name, expected in FILES.items():
            target = staging / name
            with urlopen(source_url(name), timeout=120) as response:
                target.write_bytes(response.read())
            if digest(target) != expected:
                raise SystemExit(f"Checksum mismatch while downloading {name}")
        for name in FILES:
            (OUTPUT / name).write_bytes((staging / name).read_bytes())
    verify(OUTPUT)


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify without downloading")
    args = parser.parse_args()
    if args.check:
        verify(OUTPUT)
    else:
        download()
    print(f"Pyodide {VERSION}: {OUTPUT}")


if __name__ == "__main__":
    main()
