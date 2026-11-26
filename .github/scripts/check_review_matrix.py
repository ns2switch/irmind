"""Check the native matrix of this exact pull request workflow execution."""
import json
import os
from pathlib import Path

from select_ci_scope import command, missing_review_jobs, run_data


def main() -> None:
    if (os.environ["SCOPE_RESULT"], os.environ["LINUX_RESULT"]) != ("success", "success"):
        raise SystemExit("Scope selection and Linux must succeed.")
    payload = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    repo = os.environ["GITHUB_REPOSITORY"]
    number = int(payload["number"])
    review = json.loads(command("gh", "api", f"repos/{repo}/pulls/{number}"))
    snapshot = payload["pull_request"]
    if any(review[side]["sha"] != snapshot[side]["sha"] for side in ("base", "head")):
        raise SystemExit("This check is stale. Run it on the current PR base and head.")
    full_ci = os.environ["FULL_CI"] == "true"
    labelled = any(item["name"] == "full-ci" for item in review["labels"])
    if labelled and (review["draft"] or not full_ci):
        raise SystemExit("The current full-ci label requires a matrix of the review-ready PR.")
    if full_ci:
        missing = missing_review_jobs(run_data(int(os.environ["GITHUB_RUN_ID"]), "jobs"))
        if missing:
            raise SystemExit("Required matrix jobs without success: " + ", ".join(sorted(missing)))


if __name__ == "__main__":
    main()
