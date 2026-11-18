# Product roadmap

## v1.0.0-rc.4 — Encrypted backup management
- [x] Tauri 2 desktop shell and dark dashboard
- [x] ADB device discovery for supported emulator serials
- [x] Gardenscapes package and root checks
- [x] Read-only capture of the two observed save files after the game process exits
- [x] Argon2id + AES-256-GCM offline vault container
- [x] SHA-256 integrity metadata
- [x] Windows x64 NSIS build workflow
- [x] Browse locally stored encrypted snapshots
- [x] Export a selected `.gvault` file unchanged through a native Windows Save As dialog

## Next milestones
1. Add authenticated vault inspection and a separately confirmed restore workflow after compatibility tests.
2. Analyze controlled before/after snapshots with read-only diagnostics.
3. Implement a data reader only if the format is documented or otherwise legitimately accessible.
4. Add opt-in monitoring for Gardenscapes process exit and duplicate-capture protection.
5. Evaluate mobile support, plugin API, notifications, cloud sync, analytics, and account features only after privacy and threat-model review.

A decoded save editor, live game Apply, cross-platform sync, cloud analytics, and 24/7 support are not part of this MVP.
