"""Classify tags before publishing signed GitHub releases."""
import re
import sys


_VERSION = r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"


def release_kind(tag):
    if re.fullmatch(_VERSION, tag):
        return "stable"
    if re.fullmatch(_VERSION + r"-(?:alpha|beta|rc)(?:\.(?:0|[1-9][0-9]*))*", tag):
        return "prerelease"
    raise ValueError("expected a stable version or an alpha, beta, or rc tag")


if __name__ == "__main__":
    try:
        print(release_kind(sys.argv[1]))
    except ValueError as error:
        sys.exit(str(error))
