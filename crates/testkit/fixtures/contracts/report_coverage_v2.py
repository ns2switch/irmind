#!/usr/bin/env python3
"""Independent report coverage and V11 publication vectors."""
import json

from sigma_report_objects import (descriptor, entries, generate, ref, report_coverage_prefix, sha, tag, text, u64, vector)


def vectors():
    approved = {name: bytes.fromhex(value["bytes_hex"]) for name, value in generate().items()}
    prefix = report_coverage_prefix()

    def child(checkpoint, task, sequence=3):
        return (
            ref(checkpoint, f"checkpoint-{task}".encode())
            + sha(f"task-{task}".encode())
            + u64(sequence)
            + sha(f"load-{task}".encode())
            + u64(0)
        )

    first = child(21, "A")
    second = child(24, "B")
    coverage = prefix + entries(first, second)
    report = approved["report_rendered"]
    citations = approved["report_citations"]
    analyst = approved["report_analyst_sections"]
    objects = [(0, citations), (1, analyst), (2, coverage), (3, report)]
    checkpoint = text("00000000-0000-4000-8000-000000000010") + ref(30, b"report-input-checkpoint")
    proof_set = sha(tag("irmind-report-proof-set-v1") + entries(*(descriptor(kind, body) for kind, body in objects)))
    publication = (
        tag("irmind-report-published-v1")
        + checkpoint + sha(citations) + bytes([0, 1]) + sha(analyst)
        + sha(coverage) + bytes([0]) + text("irmind-report-renderer-v1") + bytes([0])
        + u64(len(report)) + sha(report) + proof_set
    )
    section = entries(*(descriptor(kind, body) + body for kind, body in objects))
    return {
        name: vector(body)
        for name, body in {
            "report_coverage_v2_empty_delegated": prefix + entries(),
            "report_coverage_v2_two_tasks_same_local_sequence": coverage,
            "reject_duplicate_branch_gap": prefix + entries(first, first),
            "reject_zero_branch_sequence": prefix + entries(child(21, "A", 0)),
            "reject_omitted_branch_gap": prefix + entries(first),
            "report_published_v1_with_coverage_v2": publication,
            "report_section_v10_with_coverage_v2": section,
        }.items()
    }


if __name__ == "__main__":
    print(json.dumps(vectors(), indent=2, sort_keys=True))
