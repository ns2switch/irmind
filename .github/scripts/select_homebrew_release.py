"""Select published stable SemVer tags for the protected Homebrew deployment."""
import json
import sys

from release_version import release_kind


def eligible(tag, release):
    try:
        kind = release_kind(tag)
    except ValueError:
        return False
    return (
        kind == "stable"
        and type(release) is dict
        and release.get("tagName") == tag
        and release.get("isDraft") is False
        and release.get("isPrerelease") is False
    )


if __name__ == "__main__":
    print("eligible=" + str(eligible(sys.argv[1], json.load(sys.stdin))).lower())
