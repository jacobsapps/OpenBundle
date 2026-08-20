"""Render a self-contained, offline HTML report."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
import json


def render_report_html(data: dict) -> str:
    """Return the complete report document without assuming a host filesystem."""

    template = (
        files("openbundle")
        .joinpath("templates")
        .joinpath("report.html")
        .read_text(encoding="utf-8")
    )
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    # Prevent a malicious bundle filename from ending the JSON script tag.
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    return template.replace("__REPORT_DATA__", payload)


def render_report(data: dict, output_path: str | Path) -> Path:
    output = Path(output_path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_report_html(data), encoding="utf-8")
    return output


def write_json(data: dict, output_path: str | Path) -> Path:
    output = Path(output_path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return output
