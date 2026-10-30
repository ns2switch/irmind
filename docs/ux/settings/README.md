# Settings screen comparison

These captures are for reviewers of the unified settings flow. The before images came from the existing synthetic TUI demo and prior versioned synthetic UI captures. The after images use the offline VHS fixture in `docs/demo/` with an ephemeral file keystore and fake model. No real provider, incident data, or network is involved.

| Screen | Before | After |
| --- | --- | --- |
| Settings navigation | Separate screens; no entry screen | ![Unified Settings navigation with four sections](after/settings.png) |
| Model selection | ![Previous model selection dialog](before/model.png) | ![Model selection under Settings with local and remote presets](after/model.png) |
| Connectors | ![Previous module view with a hidden default URL](before/connectors.png) | ![Connector view with DeepSeek's default URL visible](after/connectors.png) |
| Keystore | ![Previous keystore view](before/keystore.png) | ![Keystore under Settings with credential actions](after/keystore.png) |
| Preferences | ![Previous configuration dialog](before/preferences.png) | ![Preferences under Settings with resume, mouse, and theme](after/preferences.png) |

The before images show synthetic UI states from earlier commits, not a live machine. The latest after images are also published under `docs/assets/` for the user guide.
