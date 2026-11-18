# Product roadmap

## v1.0.0-rc.5 — LDPlayer capture fix
- [x] Tauri 2 desktop shell and dark dashboard
- [x] ADB device discovery for supported emulator serials
- [x] Gardenscapes package and root checks
- [x] Read-only capture of the two configured save files after the game process exits
- [x] Argon2id + AES-256-GCM offline vault container
- [x] SHA-256 integrity metadata
- [x] Browse locally stored encrypted snapshots
- [x] Export a selected `.gvault` file unchanged through a native Windows Save As dialog
- [x] Quote the complete `su -c 'cat ...'` command to prevent the path being parsed as a user ID
- [x] Use `adb exec-out` for raw binary output
- [x] Add Rust regression coverage for both allowed capture filenames and rejected arbitrary paths

## Next milestones
1. Verify the actual save-file locations on LDPlayer and inspect controlled before/after snapshots without modifying them.
2. Add authenticated vault inspection and a separately confirmed restore workflow after compatibility tests.
3. Implement a data reader only if the format is documented or otherwise legitimately accessible.
4. Add opt-in monitoring for Gardenscapes process exit and duplicate-capture protection.
5. Continue the no-root Android vault manager separately from rooted game-file capture.

A decoded save editor, live game Apply, cross-platform sync, cloud analytics, and 24/7 support are not part of this MVP.
