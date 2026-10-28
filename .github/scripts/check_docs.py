#!/usr/bin/env python3
"""Check local links, CLI references, and Spanish source-commit citations."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[2]
LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
FLAG = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]*")
COMMAND = re.compile(r"\birmind(?:\.exe)?\s+([a-z][a-z0-9-]*)(?:\s+([a-z][a-z0-9-]*))?")
NON_IRMIND_FLAGS = {
    "--all",
    "--all-features",
    "--all-targets",
    "--amend",
    "--check",
    "--config",
    "--example",
    "--features",
    "--ignore",
    "--locked",
    "--manifest-path",
    "--release",
    "--sanitizer",
    "--target",
    "--test-threads",
    "--workspace",
}
TRANSLATIONS = {
    ROOT / "README.es.md": ROOT / "README.md",
    ROOT / "docs/es/roadmap.md": ROOT / "docs/development/roadmap.md",
    **{
        ROOT / "docs/es" / name: ROOT / "docs" / name
        for name in ("getting-started.md", "configuration.md", "modules.md", "security-model.md", "platforms.md")
    },
}


def check_translations() -> list[str]:
    warnings: list[str] = []
    for translation, source in TRANSLATIONS.items():
        first = translation.read_text(encoding="utf-8").splitlines()[0]
        match = re.fullmatch(
            rf"Traducción de {re.escape(source.relative_to(ROOT).as_posix())} en el commit ([0-9a-f]{{40}}); si hay diferencias, prevalece la versión en inglés\.",
            first,
        )
        if match is None:
            warnings.append(f"{translation.relative_to(ROOT)}: missing or malformed source citation")
            continue
        last = subprocess.check_output(
            ["git", "log", "-1", "--format=%H", "--", source.relative_to(ROOT).as_posix()],
            cwd=ROOT, text=True,
        ).strip()
        if match.group(1) != last:
            warnings.append(
                f"{translation.relative_to(ROOT)}: translation may be stale; "
                f"English source was last changed in {last}"
            )
    return warnings


def markdown_files() -> list[Path]:
    return sorted(ROOT.glob("*.md")) + sorted((ROOT / "docs").rglob("*.md"))


def anchors(path: Path) -> set[str]:
    found: set[str] = set()
    seen: dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^#{1,6}\s+(.+?)\s*#*\s*$", line)
        if not match:
            continue
        title = re.sub(r"<[^>]+>", "", match.group(1))
        title = re.sub(r"[^\w\s-]", "", title.lower(), flags=re.UNICODE)
        slug = re.sub(r"\s+", "-", title.strip())
        repeat = seen.get(slug, 0)
        seen[slug] = repeat + 1
        found.add(f"{slug}-{repeat}" if repeat else slug)
    return found


def check_links(paths: list[Path]) -> tuple[int, list[str]]:
    count = 0
    errors: list[str] = []
    for source in paths:
        text = source.read_text(encoding="utf-8")
        for raw in LINK.findall(text):
            target = raw.strip().split(" ", 1)[0].strip("<>")
            if target.startswith(("https://", "http://", "mailto:")):
                continue
            file_part, _, fragment = target.partition("#")
            destination = (source.parent / unquote(file_part)).resolve() if file_part else source
            count += 1
            if not destination.is_file() or not destination.is_relative_to(ROOT):
                errors.append(f"{source.relative_to(ROOT)}: missing local link {target}")
            elif fragment and unquote(fragment).lower() not in anchors(destination):
                errors.append(f"{source.relative_to(ROOT)}: missing anchor {target}")
    return count, errors


def help_text(binary: Path, *parts: str) -> str:
    result = subprocess.run(
        [str(binary), *parts, "--help"],
        text=True,
        capture_output=True,
        check=True,
        timeout=15,
    )
    return result.stdout


def command_names(output: str) -> set[str]:
    block = output.split("Commands:", 1)
    if len(block) < 2:
        return set()
    block = block[1].split("Options:", 1)[0]
    return set(re.findall(r"^\s{2}([a-z][a-z0-9-]+)\s", block, re.MULTILINE))


def source_command_names(source: str, enum_name: str) -> set[str]:
    header = re.search(rf"\benum {re.escape(enum_name)}\s*\{{", source)
    if header is None:
        raise ValueError(f"missing CLI enum {enum_name}")
    depth = 1
    variants: set[str] = set()
    for line in source[header.end() :].splitlines():
        if depth == 1:
            match = re.match(r"\s{4}([A-Z][A-Za-z0-9]*)\s*[,({]", line)
            if match:
                variants.add(re.sub(r"(?<!^)(?=[A-Z])", "-", match.group(1)).lower())
        depth += line.count("{") - line.count("}")
        if depth == 0:
            break
    return variants


def source_cli() -> tuple[set[str], set[str], set[str]]:
    source = (ROOT / "crates/bin/src/cli.rs").read_text(encoding="utf-8")
    filter_source = (ROOT / "crates/bin/src/cli/graph_filter.rs").read_text(encoding="utf-8")
    root_commands = source_command_names(source, "Command")
    case_commands = source_command_names(source, "CaseCommand")
    fields = re.findall(
        r"#\[arg\(long(?:,|\))[^\]]*\]\s*(?:pub\([^)]*\)\s*)?([a-z][a-z0-9_]*)\s*:",
        source + filter_source,
    )
    flags = {"--help", "--version"} | {"--" + field.replace("_", "-") for field in fields}
    return root_commands, case_commands, flags


def source_tui_flags() -> set[str]:
    source = (ROOT / "crates/tui/src/case/commands/export.rs").read_text(encoding="utf-8")
    return set(re.findall(r'strip_prefix\("/[a-z-]+ (--[a-z-]+)"\)', source))


def check_cli(paths: list[Path], binary: Path | None) -> tuple[int, list[str]]:
    if binary is None:
        root_commands, case_commands, available_flags = source_cli()
    else:
        root_commands, case_commands, available_flags = binary_cli(binary)
    available_flags |= source_tui_flags()
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    cited_flags = set(FLAG.findall(text)) - NON_IRMIND_FLAGS
    errors = [f"unknown IRMind flag {flag}" for flag in sorted(cited_flags - available_flags)]
    cited_commands = COMMAND.findall(text)
    for command, nested in cited_commands:
        if command not in root_commands:
            errors.append(f"unknown IRMind command {command}")
        elif command == "case" and nested and nested not in case_commands:
            errors.append(f"unknown IRMind case command {nested}")
    return len(cited_flags) + len(cited_commands), errors


def binary_cli(binary: Path) -> tuple[set[str], set[str], set[str]]:
    root_help = help_text(binary)
    root_commands = command_names(root_help)
    case_commands = command_names(help_text(binary, "case"))
    help_outputs = [root_help, help_text(binary, "case")]
    for command in sorted(root_commands - {"help", "case"}):
        help_outputs.append(help_text(binary, command))
    for command in sorted(case_commands - {"help"}):
        help_outputs.append(help_text(binary, "case", command))
    available_flags = set().union(*(set(FLAG.findall(output)) for output in help_outputs))
    return root_commands, case_commands, available_flags


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve() if args.binary else None
    if binary is not None and not binary.is_file():
        print(f"missing IRMind binary: {binary}", file=sys.stderr)
        return 2
    paths = markdown_files()
    link_count, link_errors = check_links(paths)
    cli_count, cli_errors = check_cli(paths, binary)
    translation_warnings = check_translations()
    for error in link_errors + cli_errors:
        print(error, file=sys.stderr)
    for warning in translation_warnings:
        print(f"warning: {warning}", file=sys.stderr)
    print(f"Checked {len(paths)} Markdown files, {link_count} local links, {cli_count} CLI references, and {len(TRANSLATIONS)} translation citations")
    return int(bool(link_errors or cli_errors))


if __name__ == "__main__":
    raise SystemExit(main())
