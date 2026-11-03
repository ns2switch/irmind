# Automatic demo presentation

This page is for maintainers reviewing the synthetic presentation. It records the early three-scene checkpoint; the complete custody tour and cross-platform playback tests are still being finished in this PR.

## Script and playback

The versioned [English script](../../crates/tui/assets/demo-presentation.en.json) contains ten scene IDs, short titles, narration, commands and required completion events. Narration can change without rewriting the playback controller. Future translation follows [issue #146](https://github.com/ns2switch/irmind/issues/146); no locale implementation is included here.

The TUI types into its ordinary composer and dispatches the same registered commands as an analyst. It waits for actual work to complete and for the corresponding result event. Reading time scales with narration length, with a six-second minimum at normal speed. The development `--presentation-speed` option accelerates timing for PTY tests; it does not change policy or skip work.

Enter advances, Backspace goes back, Space pauses or resumes playback, and Esc/Ctrl+C cancels work and exits. Completed actions are retained when navigating back. The full-width narration stays below the transcript; terminals smaller than 100 × 40 show a resize notice. Ordinary cases retain their existing smaller-terminal support.

The demo's composition root creates the signed temporary case before entering the presentation. Scene two explains that case and executes `/scope`; scene three visibly executes `/ingest events.json`. That exact alias is resolved to the bundled file inside the demo directory, then uses ordinary parser selection, ingestion and SourceManifestV2. Other paths remain rejected; no original is copied.

## Isolation and trust

Presentation playback requires the explicitly isolated demo workspace. Normal workspace and application port signatures stay unchanged. The added TUI entry point passes presentation timing through private presentation state, not a global variable.

The presentation always uses the scripted model and does not even probe loopback Ollama. The external-enrichment example uses the existing in-memory synthetic connector. It still goes through policy and signed approval with the temporary analyst key. Expected answers are loaded only by `/demo check`; narration and evaluation data never enter a model prompt.

The private temporary directory and ephemeral file keystore are deleted when the demo returns, including error and cancellation. Terminal restoration remains protected by the existing session guard. The SSH/GUI terminal matrix for Ctrl+O is documented separately in [platforms](../platforms.md#card-expansion-and-terminal-keymaps).

## Three-scene review checkpoint

The real-binary PTY test reaches the ingestion result and checks parser confidence, exits with Esc, and checks both the existing real-data directory and temporary parent. The screenshots below use the reviewed, digest-pinned VHS image with network disabled, bounded container resources and fixed identity variables. They show the actual 0.1.5 development binary, not a mockup.

![Automatic presentation introduction with a large narration panel under the live case.](../ux/demo-guide/presentation-preview/01-welcome.png)

![Synthetic AWS case scope after the presentation types and runs the scope command.](../ux/demo-guide/presentation-preview/02-case.png)

![Completed synthetic evidence ingestion with parser-json and 90 percent confidence.](../ux/demo-guide/presentation-preview/03-evidence.png)

Reproduce with the [preview generator](../demo/generate_presentation_preview.py), passing the current development binary through its binary option; see the script help. The generator removes its scratch directory after capture or error. This checkpoint is not release-ready; all ten scenes, updated legacy tutorial tests, full recording, documentation and three-platform CI must pass before merge and v0.1.5.
