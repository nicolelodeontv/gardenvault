# Product roadmap

## v1.0.0-rc.3 — LDPlayer profile reader MVP
- [x] Tauri 2 desktop shell and dark dashboard
- [x] ADB device discovery for supported emulator serials
- [x] Gardenscapes package and root checks
- [x] Read-only capture of the two observed save files after the game process exits
- [x] Argon2id + AES-256-GCM offline vault container
- [x] SHA-256 integrity metadata
- [x] Windows x64 NSIS build workflow

## Next milestones
1. Add a vault browser and authenticated restore/export of encrypted backups.
2. Analyze controlled before/after snapshots with read-only diagnostics.
3. Implement a data reader only if the format is documented or otherwise legitimately accessible.
4. Add opt-in monitoring for Gardenscapes process exit and duplicate-capture protection.
5. Evaluate mobile support, plugin API, notifications, cloud sync, analytics, and account features only after privacy and threat-model review.

A decoded save editor, live game Apply, cross-platform sync, cloud analytics, and 24/7 support are not part of this MVP.
