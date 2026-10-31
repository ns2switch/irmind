#!/usr/bin/env python3
"""Run one public HuntEval episode with an explicitly configured IRMind model.

The hidden answer is opened only after all IRMind subprocesses have finished.
No approval is granted automatically. This is a manual development command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

PINNED_COMMIT = "4cbb555a56bc17cb03b988ad2f15b1374eecf183"
CASE_ID = re.compile(r"^[0-9a-f-]{36}$")
EVENT_ID = re.compile(r"\bevt-[0-9]{4}\b")
TECHNIQUE = re.compile(r"\bT[0-9]{4}(?:\.[0-9]{3})?\b")


def verify_checksum(root: Path, relative: Path) -> None:
    checksum_file = Path(__file__).with_name("hunteval.sha256")
    checksums = {
        path: digest for digest, path in (
            line.split(maxsplit=1) for line in checksum_file.read_text().splitlines()
        )
    }
    expected = checksums.get(relative.as_posix())
    if expected is None:
        raise ValueError("Unknown episode or missing pinned checksum")
    actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError(f"HuntEval checksum mismatch: {relative}")


def checked_files(root: Path, episode: str) -> tuple[Path, Path]:
    commit = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if commit != PINNED_COMMIT:
        raise ValueError("HuntEval checkout is not at the pinned commit")
    provider = episode.split("-", 1)[0]
    base = Path("datasets") / provider / episode
    public = base / "source/events.json"
    hidden = base / "private/ground-truth.json"
    verify_checksum(root, public)
    return root / public, root / hidden


def invoke(binary: Path, home: Path, *arguments: str) -> str:
    result = subprocess.run(
        [str(binary), "--home", str(home), *arguments],
        check=True, capture_output=True, text=True,
    )
    return result.stdout.strip()


def score(expected: set[str], reported: set[str]) -> dict[str, object]:
    matched = expected & reported
    return {
        "matched": len(matched),
        "expected": len(expected),
        "reported": len(reported),
        "precision": len(matched) / len(reported) if reported else None,
        "recall": len(matched) / len(expected) if expected else 1.0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("hunteval_root", type=Path)
    parser.add_argument("episode", choices=[
        f"{provider}-iam-{number:03}"
        for provider in ("aws", "azure", "gcp") for number in range(1, 7)
    ])
    parser.add_argument("binary", type=Path)
    parser.add_argument("home", type=Path,
                        help="Dedicated test data directory with an explicitly configured model")
    parser.add_argument("llm_module",
                        help="Explicit configured module ID; never a key or passphrase")
    args = parser.parse_args()
    source, private = checked_files(args.hunteval_root, args.episode)
    args.home.mkdir(parents=True, exist_ok=True)
    created = invoke(args.binary, args.home, "case", "new", args.episode, "--scope", "local")
    case_id = created.splitlines()[-1]
    if not CASE_ID.fullmatch(case_id):
        raise ValueError("IRMind did not return a case ID")
    invoke(args.binary, args.home, "ingest", case_id, str(source))
    question = (
        "Investigate this synthetic cloud episode using only its ingested evidence. "
        "Report malicious event IDs, entities, and ATT&CK techniques as case findings "
        "with evidence hashes. State uncertainty."
    )
    result = subprocess.run(
        [str(args.binary), "--home", str(args.home), "--llm-module", args.llm_module,
         "ask", case_id, question],
        check=True, capture_output=True, text=True,
    )
    findings = invoke(args.binary, args.home, "findings", case_id)
    invoke(args.binary, args.home, "verify", case_id, "--source-root", str(source.parent))
    # Ground truth is never read before the model run, nor passed to IRMind.
    verify_checksum(args.hunteval_root, private.relative_to(args.hunteval_root))
    truth = json.loads(private.read_text())
    public_events = json.loads(source.read_text())
    public_entities = {
        event[field] for event in public_events
        for field in ("principal", "account_id", "resource", "source_ip", "user_agent")
    }
    lines = findings.splitlines()
    reported_events = set(EVENT_ID.findall("\n".join(line for line in lines if " Timeline " in line)))
    reported_entities = {
        entity for entity in public_entities
        if any(entity in line for line in lines if " Timeline " not in line)
    }
    reported_techniques = set(TECHNIQUE.findall("\n".join(
        line for line in lines if " Technique " in line
    )))
    summary = {
        "case_id": case_id,
        "episode": args.episode,
        "events": score(set(truth["malicious_event_ids"]), reported_events),
        "entities": score(set(truth["malicious_entity_ids"]), reported_entities),
        "techniques": score(set(truth["expected_attack_techniques"]), reported_techniques),
        "note": "Exact-ID finding score; inspect narrative and evidence citations manually.",
    }
    print(result.stdout)
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
