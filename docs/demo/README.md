# Reproducing the offline demo

This guide is for maintainers updating the README visuals. The tape drives a
synthetic case through the same TUI used by analysts. It never selects a real
provider or opens a network connection.

Build the example and regenerate the images from the repository root:

```sh
cargo build -p irmind --example demo --locked
docker pull ghcr.io/charmbracelet/vhs@sha256:9d5fc3dc0c160b0fb1d2212baff07e6bdf3fa9438c504a3237484567302fcf93
python3 docs/demo/generate.py
```

The generator uses the official VHS v0.11.0 container pinned by digest
`sha256:9d5fc3dc0c160b0fb1d2212baff07e6bdf3fa9438c504a3237484567302fcf93`.
That immutable image includes VHS, `ttyd`, Chromium, `ffmpeg`, and the Source
Code Pro font. The tape fixes a 120×32 terminal, font size, theme, and frame
rate. Docker runs without network access. The example creates a temporary
encrypted-file keystore with a demo-only passphrase and removes its data when
it exits. The generator validates the flow, dimensions, duration, size, and
capture text before replacing the published images. It also checks the SHA-256
of the reviewed synthetic example. Its scratch files are
deleted automatically.

The manual [demo workflow](../../.github/workflows/demo.yml) regenerates the
images on Linux and opens a pull request. It never pushes to `main`.
