#!/usr/bin/env python3
"""Capture all ten live presentation scenes with the reviewed, offline VHS image."""
from __future__ import annotations

import argparse
import getpass
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "ghcr.io/charmbracelet/vhs@sha256:9d5fc3dc0c160b0fb1d2212baff07e6bdf3fa9438c504a3237484567302fcf93"
SCENES = ("welcome", "case", "evidence", "explore", "agent", "approval", "findings", "check", "custody", "next")


def container(directory: Path, *args: str, entrypoint: str | None = None) -> str:
    command = [
        "docker", "run", "--rm", "--init", "--network", "none", "--pull=never",
        "--memory", "1g", "--cpus", "2", "--pids-limit", "256",
        "--name", f"irmind-presentation-{os.getpid()}",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--env", "HOME=/tmp/irmind-demo-home",
        "--env", "PATH=/app/tools:/usr/local/bin:/usr/bin:/bin",
        "--env", "GOMAXPROCS=2",
        "--env", "TMPDIR=/app/capture-tmp",
        "--mount", f"type=bind,src={directory},dst=/app", "--workdir", "/app",
    ]
    if entrypoint:
        command += ["--entrypoint", entrypoint]
    try:
        result = subprocess.run(command + [IMAGE, *args], text=True, capture_output=True, timeout=900)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "stop", "--time", "5", f"irmind-presentation-{os.getpid()}"],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        raise
    if result.returncode:
        raise ValueError("VHS capture failed: " + result.stderr[-2000:] + result.stdout[-1000:])
    return result.stdout


def renderer_wrapper(directory: Path) -> None:
    (directory / "capture-tmp").mkdir(mode=0o700)
    tools = directory / "tools"
    tools.mkdir()
    wrapper = tools / "ffmpeg"
    wrapper.write_text(
        '#!/bin/sh\nexec /usr/bin/flock /app/render.lock /usr/bin/ffmpeg '
        '-threads 1 -filter_threads 1 -filter_complex_threads 1 "$@"\n'
    )
    wrapper.chmod(0o755)


def encode_gif(directory: Path) -> None:
    # Encode only after VHS/Chromium exits, within a separate memory limit.
    container(directory, "-v", "error", "-y", "-threads", "1", "-filter_complex_threads", "1",
              "-framerate", "6", "-start_number", "1", "-i", "frames/frame-text-%05d.png",
              "-threads", "1", "-framerate", "6", "-start_number", "1", "-i", "frames/frame-cursor-%05d.png",
              "-filter_complex", "[0:v][1:v]overlay=shortest=1,pad=ceil(iw/2)*2:ceil(ih/2)*2,format=yuv420p[v]",
              "-map", "[v]", "-c:v", "libx264", "-threads", "1", "-preset", "veryfast", "-crf", "20",
              "demo.mp4", entrypoint="ffmpeg")
    # Separate passes avoid buffering the whole presentation for a palette.
    for fps, width in ((4, 984), (3, 984), (2, 984), (2, 860)):
        container(directory, "-v", "error", "-y", "-threads", "1", "-filter_threads", "1",
                  "-i", "demo.mp4", "-vf", f"fps={fps},scale={width}:-2:flags=lanczos,palettegen=max_colors=128:stats_mode=diff",
                  "-frames:v", "1", "palette.png", entrypoint="ffmpeg")
        container(directory, "-v", "error", "-y", "-threads", "1", "-filter_complex_threads", "1",
                  "-i", "demo.mp4", "-i", "palette.png", "-lavfi",
                  f"[0:v]fps={fps},scale={width}:-2:flags=lanczos[v];[v][1:v]paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle",
                  "-loop", "0", "demo.gif", entrypoint="ffmpeg")
        if 0 < (directory / "demo.gif").stat().st_size < 5_000_000:
            return


def validate(directory: Path, version: str) -> None:
    transcript = (directory / "demo.ascii").read_text(errors="replace")
    for private in (str(Path.home()), getpass.getuser(), os.uname().nodename, "/home/", "/Users/", "C:\\Users\\", "api_key"):
        if private and private in transcript:
            raise ValueError("capture contains an environment-specific value")
    required = [f"Step {step} of 10" for step in range(1, 11)]
    required += [f"IRMind v{version}", "90% confidence", "Source SHA-256:", "Approval:", "Seal:", "Exported", "Verify export:", "Demo data deleted"]
    for term in required:
        if term not in transcript:
            raise ValueError("capture is missing a real result: " + term)
    for scene in SCENES:
        if not (directory / f"{scene}.png").is_file():
            raise ValueError("missing presentation screenshot: " + scene)
    gif = directory / "demo.gif"
    if not gif.is_file() or gif.stat().st_size >= 5_000_000:
        raise ValueError("presentation GIF is missing or exceeds 5 MB")
    duration = float(container(directory, "-v", "error", "-show_entries", "format=duration", "-of", "default=noprint_wrappers=1:nokey=1", "demo.gif", entrypoint="ffprobe").strip())
    if not 100 <= duration <= 600:
        raise ValueError(f"expected a complete 100–600 second presentation, got {duration:.2f}")
    print(f"Verified all ten scenes: {duration:.2f} seconds, GIF {gif.stat().st_size:,} bytes; ten full-resolution PNGs.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
    parser.add_argument("--binary", type=Path, default=target / "debug/irmind")
    args = parser.parse_args()
    version = tomllib.loads((ROOT / "crates/bin/Cargo.toml").read_text())["package"]["version"]
    actual = subprocess.check_output([args.binary, "--version"], text=True).strip()
    if actual != f"irmind {version}":
        raise ValueError("rebuild the current version before capturing")
    with tempfile.TemporaryDirectory(prefix="irmind-presentation-") as temporary:
        output = Path(temporary)
        renderer_wrapper(output)
        executable = output / "irmind"
        shutil.copyfile(args.binary, executable)
        executable.chmod(0o755)
        shutil.copyfile(ROOT / "docs/demo/community.tape", output / "community.tape")
        if "v0.11.0" not in container(output, "--version", entrypoint="vhs"):
            raise ValueError("unexpected VHS version")
        container(output, "community.tape")
        encode_gif(output)
        validate(output, version)
        shutil.copyfile(output / "demo.gif", ROOT / "docs/assets/demo.gif")
        for scene in SCENES:
            shutil.copyfile(output / f"{scene}.png", ROOT / f"docs/ux/demo-guide/{scene}.png")
    print("Captured the complete offline presentation; temporary files removed.")


if __name__ == "__main__":
    main()
