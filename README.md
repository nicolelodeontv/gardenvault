# GardenVault

GardenVault is a local-first Windows desktop utility for reading Gardenscapes profile files from an authorized LDPlayer 14 instance and creating encrypted offline snapshots.

## v1.0.0-rc.8 — Read-only binary forensics

- Detect connected LDPlayer emulators through ADB and verify the Gardenscapes package and root availability.
- Capture the configured `GameData.db` and `GameData.db.bak` files after the game process exits.
- Encrypt snapshots locally with Argon2id + AES-256-GCM and preserve SHA-256 integrity metadata.
- Browse encrypted snapshots and export byte-identical encrypted copies through the Windows Save As dialog.
- Decrypt a selected snapshot only in memory after passphrase entry and verify embedded file size and SHA-256.
- Scan the complete captured file for every strong signature offset, including signatures that straddle the 64 KiB boundary or occur in the final four bytes.
- Report first-256-byte, remainder, whole-file, and tail entropy; printable/zero-byte ratios; unique byte count; size alignment; and tail hex.
- Parse little-endian u32 words following each PLXE magic and compare plausible lengths with the file, candidate payload, and successfully decoded output sizes.
- Attempt bounded streaming Zstandard decoding at candidate offsets. Report explicit statuses (`signature-only`, `incomplete`, `decode-failed`, `limit-hit`, `decoded-size-matches`, and `decoded-size-mismatch`), frame offsets, declared/observed sizes, compressed frame sizes, trailing bytes, and diagnostics for complete decoded output.
- Skip candidate magic that falls inside an already measured frame, while still attempting a new frame exactly at the prior frame boundary.
- Limit aggregate decoded output to 64 MiB per file, cap the Zstandard back-reference window at 64 MiB, and attempt at most 32 candidate offsets per file. Inspection never extracts files to disk or writes to the game directory.

## Compatibility limits

The supplied `GameData.db` has not yet been confirmed as SQLite, a PLXE container, or any other known format. SQLite inspection only runs after the standard SQLite header is detected. A PLXE/Zstandard signature match is only a candidate until the frame validates and decompresses cleanly. High entropy alone does not prove encryption because compressed data can also have high entropy.

Even a successfully decoded local database would not prove it is the authoritative record for coins, boosters, or level progress. Gardenscapes can synchronize progress with Playrix services. Editing, restore-to-game, and live Apply remain disabled until the file structure, integrity rules, and relationship to server-synced progress are independently verified.

A community reverse-engineering post documents PLXE + Zstandard wrapping for certain Playrix XML/assets; this remains a format clue, not confirmation about `GameData.db`: [format discussion](https://www.zenhax.com/viewtopic.php@t=16964.html).

Playrix says progress is automatically saved while connected to the internet: [Playrix support](https://playrix.helpshift.com/hc/en/5-gardenscapes/faq/718-saving-game-progress/).

## Build on Windows

Requirements: Node.js 22+, Rust stable with the MSVC target, Visual Studio C++ Build Tools + Windows SDK, and NSIS.

Run `build_windows.bat` from the repository root. GitHub Actions builds an unsigned Windows x64 installer and uploads it as an artifact.

## LDPlayer 14

ADB discovery checks `GARDENVAULT_ADB`, then `C:\LDPlayer\LDPlayer14\adb.exe`, then `adb.exe` on PATH. Enable ADB debugging and LDPlayer root access. Close Gardenscapes completely before reading.

## Security

The frontend cannot pass arbitrary shell commands or file paths. Native code uses a fixed ADB command allowlist against the known package and two file names. The passphrase is not saved. No telemetry, cloud sync, account service, plugin server, or automatic update is included.

See [docs/SECURITY.md](docs/SECURITY.md) and [docs/ROADMAP.md](docs/ROADMAP.md).
