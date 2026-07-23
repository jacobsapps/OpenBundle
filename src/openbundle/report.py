"""Render a self-contained, offline HTML report."""

from __future__ import annotations

from pathlib import Path
import json


TEMPLATE_PATH = Path(__file__).with_name("templates") / "report.html"


def render_report(data: dict, output_path: str | Path) -> Path:
    output = Path(output_path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    # Prevent a malicious bundle filename from ending the JSON script tag.
    payload = payload.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    output.write_text(
        template.replace("__REPORT_DATA__", payload),
        encoding="utf-8",
    )
    return output


def write_json(data: dict, output_path: str | Path) -> Path:
    output = Path(output_path).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return output

