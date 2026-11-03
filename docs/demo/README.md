# Reproducing the offline presentation

This page is for maintainers updating the README GIF and the ten scene captures. The tape drives the real, current binary through its isolated synthetic case. It never selects a real provider or opens a network connection.

Build the binary and regenerate from the repository root:

```sh
cargo build -p irmind --locked
docker pull ghcr.io/charmbracelet/vhs@sha256:9d5fc3dc0c160b0fb1d2212baff07e6bdf3fa9438c504a3237484567302fcf93
python3 docs/demo/generate_community.py
```

Set `CARGO_TARGET_DIR` if the build directory is elsewhere, or see the generator help for a binary path override. [community.tape](community.tape) is the full presentation; [generate_community.py](generate_community.py) validates it before replacing the GIF and scene PNGs.

The official VHS v0.11.0 image is pinned by digest. It includes `ttyd`, Chromium, ffmpeg and Source Code Pro. The tape fixes a 120 × 40 terminal, font, theme and frame rate. The container has no network, a 1 GiB memory limit, two CPUs and a process limit. It receives only the binary and tape in a disposable directory, with fixed HOME, prompt and identity variables. No host configuration or signing key is mounted.

The generator checks the actual version, all ten narrations, signed-operation results, cleanup, duration, size and capture privacy. The full presentation replaces the older 20–30 second highlight clip. PNGs retain full resolution; the GIF uses a bounded frame-rate/width ladder to stay under 5 MB without shortening the presentation. It serializes VHS screenshot/video encoders with the `flock` already present in that image and limits filter threads. VHS saves raw text/cursor frames and exits before video encoding, releasing Chromium memory. The same pinned image then encodes MP4 and runs two single-threaded ffmpeg passes to build a palette and GIF. This avoids retaining every uncompressed frame in memory for palette generation. Raw frames, intermediate video, palette, transcripts and temporary demo data are removed after success or error.

The manual [demo workflow](../../.github/workflows/demo.yml) uses this generator on Linux and opens a PR containing both the GIF and scene captures. It never pushes directly to main. It keeps its existing permissions.

## Early review checkpoint

[presentation-preview.tape](presentation-preview.tape) and [its generator](generate_presentation_preview.py) capture just the first three scenes. They were published in draft PR #165 while the rest of the presentation was being completed. [The design notes](../development/demo-presentation.md) explain completion gates, isolation and coverage.

## Non-demo workspace screenshots

The older [generate.py](generate.py) drives a synthetic example to capture settings, forms and the first-run wizard. It uses the same pinned VHS image and a reviewed fixture hash. Its 120 × 32 workspace and short-clip checks apply to that example, not to the full presentation. Running it also replaces the GIF, so regenerate the current presentation afterward before publishing README assets.
