# Product roadmap

## v1.0.0-rc.7 — Local binary diagnostics
- [x] Tauri 2 desktop shell and dark dashboard
- [x] ADB device discovery for supported LDPlayer serials
- [x] Read-only capture of the configured Gardenscapes files after the game process exits
- [x] Argon2id + AES-256-GCM encrypted offline snapshots
- [x] SHA-256 integrity checks before inspection
- [x] Local-only authenticated snapshot inspection
- [x] Conservative file signature and embedded magic scanning
- [x] Shannon byte entropy, printable-byte ratio, zero-byte ratio, and unique-byte count
- [x] Multi-line forensic report without writing any game data

## Next milestones
1. Use RC7 diagnostics to determine whether the captured file looks structured, compressed, or high-entropy.
2. Add snapshot-to-snapshot differential analysis to compare a stable capture with a later capture, without modifying either source.
3. If necessary, add an explicitly confirmed export of a decrypted copy for user-controlled offline tooling.
4. Identify whether the local file contains playable progress or only a local cache; do not assume editing it changes server-side progress.
5. Implement any parser only after the file structure and integrity rules are verified.

A decoded save editor, live game Apply, cross-platform sync, cloud analytics, and 24/7 support are not part of this milestone.
