#!/usr/bin/env python3
"""Serve a built OpenBundle site with the headers declared in vercel.json."""

from __future__ import annotations

from argparse import ArgumentParser
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import json


def production_headers(config_path: Path) -> list[tuple[str, str]]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    for rule in config.get("headers", []):
        if rule.get("source") == "/(.*)":
            return [
                (str(item["key"]), str(item["value"]))
                for item in rule.get("headers", [])
            ]
    raise ValueError("vercel.json does not contain the global production headers")


def main() -> None:
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--config", type=Path, default=Path("vercel.json"))
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    headers = production_headers(args.config.resolve())

    class Handler(SimpleHTTPRequestHandler):
        def end_headers(self) -> None:
            for key, value in headers:
                self.send_header(key, value)
            super().end_headers()

        def log_message(self, *_: object) -> None:
            pass

    handler = partial(Handler, directory=str(args.directory.resolve()))
    ThreadingHTTPServer(("127.0.0.1", args.port), handler).serve_forever()


if __name__ == "__main__":
    main()
