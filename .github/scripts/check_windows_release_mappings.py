"""Compare the Windows ThinLTO build with the default deterministic profile."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile

from reproduce_release_profile import mapping_identities


def main():
    optimized = mapping_identities(Path(sys.argv[1]))
    with tempfile.TemporaryDirectory(prefix="windows-profile-", dir=os.environ["RUNNER_TEMP"]) as temp:
        env = os.environ | {"CARGO_TARGET_DIR": temp, "RUSTFLAGS": "-C link-arg=/Brepro"}
        env.pop("CARGO_PROFILE_RELEASE_LTO", None)
        env.pop("CARGO_PROFILE_RELEASE_CODEGEN_UNITS", None)
        subprocess.run(["cargo", "build", "--release", "-p", "irmind", "--locked"],
                       env=env, check=True)
        baseline = mapping_identities(Path(temp) / env["CARGO_BUILD_TARGET"] / "release" / "build")
    if optimized != baseline:
        raise SystemExit("Windows ThinLTO changed native mapping identities")
    print(f"Windows ThinLTO preserves all {len(baseline)} native mapping identities")


if __name__ == "__main__":
    main()
