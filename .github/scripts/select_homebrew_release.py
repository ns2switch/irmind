"""Select published stable SemVer tags for the protected Homebrew deployment."""
import json
import re
import sys


def eligible(tag, release):
    return (
        re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", tag)
        is not None
        and type(release) is dict
        and release.get("tagName") == tag
        and release.get("isDraft") is False
        and release.get("isPrerelease") is False
    )


if __name__ == "__main__":
    print("eligible=" + str(eligible(sys.argv[1], json.load(sys.stdin))).lower())
