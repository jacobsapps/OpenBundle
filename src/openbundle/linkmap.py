"""Parse Xcode link maps into compile-unit size attribution."""

from __future__ import annotations

from pathlib import Path
import re


OBJECT_RE = re.compile(r"^\[\s*(\d+)\]\s+(.+)$")
SYMBOL_RE = re.compile(
    r"^0x[0-9A-Fa-f]+\s+0x([0-9A-Fa-f]+)\s+\[\s*(\d+)\]\s+"
)


def _display_name(raw_path: str) -> str:
    path = raw_path.strip()
    # Archive members often look like libSomething.a(File.o).
    archive_match = re.search(r"([^/]+\.a)\(([^)]+)\)$", path)
    if archive_match:
        return f"{archive_match.group(1)}/{archive_match.group(2)}"

    parts = Path(path).parts
    for marker in ("SourcePackages", "checkouts"):
        if marker in parts:
            index = parts.index(marker)
            return "/".join(parts[index + 1 :][-4:])
    return "/".join(parts[-3:]) if len(parts) >= 3 else path


def parse_linkmap(path: Path) -> list[dict[str, int | str]]:
    """Return compile units sorted by attributed symbol bytes."""

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []

    objects: dict[int, str] = {}
    sizes: dict[int, int] = {}
    section = ""
    for line in lines:
        if line.startswith("# Object files:"):
            section = "objects"
            continue
        if line.startswith("# Symbols:"):
            section = "symbols"
            continue
        if line.startswith("# Dead Stripped Symbols:"):
            section = "dead"
            continue
        if line.startswith("#"):
            continue

        if section == "objects":
            match = OBJECT_RE.match(line)
            if match:
                objects[int(match.group(1))] = _display_name(match.group(2))
        elif section == "symbols":
            match = SYMBOL_RE.match(line)
            if match:
                byte_count = int(match.group(1), 16)
                object_index = int(match.group(2))
                sizes[object_index] = sizes.get(object_index, 0) + byte_count

    grouped: dict[str, int] = {}
    for index, byte_count in sizes.items():
        name = objects.get(index, f"Object {index}")
        grouped[name] = grouped.get(name, 0) + byte_count
    return [
        {"name": name, "size": size}
        for name, size in sorted(grouped.items(), key=lambda item: item[1], reverse=True)
        if size > 0
    ]

