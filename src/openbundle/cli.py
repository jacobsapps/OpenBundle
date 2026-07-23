"""Command-line interface for OpenBundle."""

from __future__ import annotations

from pathlib import Path
import argparse
import sys
import webbrowser

from . import __version__
from .analyzer import BundleAnalyzer
from .artifact import ArtifactError
from .report import render_report, write_json


def _default_output(input_path: str) -> Path:
    name = Path(input_path).expanduser().name
    for suffix in (".xcarchive", ".app", ".ipa", ".zip"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]
            break
    return Path.cwd() / f"{name or 'app'}-openbundle.html"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="openbundle",
        description=(
            "Analyze an iOS .ipa, .app, or .xcarchive entirely on this Mac and "
            "produce a self-contained interactive HTML report."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command")
    analyze = subparsers.add_parser("analyze", help="Analyze an Apple app artifact")
    analyze.add_argument("input", help="Path to an .ipa, .app, .xcarchive, or zip")
    analyze.add_argument(
        "-o",
        "--output",
        help="HTML output path (default: <artifact>-openbundle.html in the current directory)",
    )
    analyze.add_argument(
        "--json",
        nargs="?",
        const=True,
        metavar="PATH",
        help="Also write the raw analysis JSON; optionally choose its path",
    )
    analyze.add_argument(
        "--open",
        action="store_true",
        help="Open the finished local report in the default browser",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    # Keep the common one-shot invocation pleasantly short:
    #   ./openbundle MyApp.ipa --open
    if arguments and arguments[0] not in {"analyze", "-h", "--help", "--version"}:
        arguments.insert(0, "analyze")
    parser = _parser()
    args = parser.parse_args(arguments)
    if args.command != "analyze":
        parser.print_help()
        return 0

    output = (
        Path(args.output).expanduser().resolve()
        if args.output
        else _default_output(args.input).resolve()
    )

    def progress(message: str) -> None:
        print(f"  {message}", file=sys.stderr, flush=True)

    try:
        data = BundleAnalyzer(progress=progress).analyze(args.input)
        report_path = render_report(data, output)
        if args.json:
            json_path = (
                Path(args.json).expanduser().resolve()
                if isinstance(args.json, str)
                else report_path.with_suffix(".json")
            )
            write_json(data, json_path)
            print(f"JSON:   {json_path}")
        print(f"Report: {report_path}")
        print("Privacy: analysis stayed local; no bundle bytes were uploaded.")
        if args.open:
            webbrowser.open(report_path.as_uri())
        return 0
    except (ArtifactError, OSError, ValueError) as error:
        print(f"openbundle: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("openbundle: cancelled", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
