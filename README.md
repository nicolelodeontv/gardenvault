# GardenVault

GardenVault is a local-first Windows desktop utility for reading Gardenscapes profile files from an authorized LDPlayer 14 instance and creating encrypted offline snapshots.

## v1.0.0-rc.9 — Read-only binary forensics

- Detect connected LDPlayer emulators through ADB and verify the Gardenscapes package and root availability.
- Capture `GameData.db` and `GameData.db.bak` only after confirming the game process is stopped. GardenVault does not force-stop the game; close it manually so its save can finish. If `GameData.db-wal` exists, compare main-database hashes before/after the WAL capture and compare WAL hashes from reads immediately before and after the selected WAL snapshot; reject the snapshot if either file changes. This is a consistency guard, not a filesystem-atomic snapshot.
- Encrypt snapshots locally with Argon2id + AES-256-GCM and preserve SHA-256 integrity metadata.
- Browse encrypted snapshots and export byte-identical encrypted copies through the Windows Save As dialog.
- Decrypt a selected snapshot only in memory after passphrase entry and verify embedded file size and SHA-256.
- Scan the complete captured file for every strong signature offset, including signatures that straddle the 64 KiB boundary or occur in the final four bytes.
- Report first-256-byte, remainder, whole-file, and tail entropy; printable/zero-byte ratios; unique byte count; size alignment; and tail hex.
- Parse little-endian u32 words following each PLXE magic and compare plausible lengths with the file, candidate payload, and successfully decoded output sizes.
- Attempt bounded streaming Zstandard decoding at candidate offsets. Report explicit statuses (`signature-only`, `incomplete`, `decode-failed`, `limit-hit`, `decoded-size-matches`, and `decoded-size-mismatch`), frame offsets, declared/observed sizes, compressed frame sizes, trailing bytes, and diagnostics for complete decoded output.
- Skip candidate magic that falls inside an already measured frame, while still attempting a new frame exactly at the prior frame boundary.
- Report Zstandard skippable frames (magic range `0x184D2A50`–`0x184D2A5F`) separately; they are metadata frames and do not count as normal decode candidates.
- Reserve a fixed 20 MiB retained-output ceiling and stream through a 32 KiB scratch buffer; reject a declared Zstandard window above 16 MiB before creating the decoder or allocating the output buffer. The nominal 64 MiB *per-frame active decompression/SQLite working-set estimate* is 20 MiB retained output + up to 20 MiB for SQLite’s read-only deserialization copy + a 16 MiB Zstandard window + 8 MiB decoder/scratch headroom. The output Vec remains alive while SQLite diagnostics run, so the two 20 MiB copies can coexist. This is not a process-wide memory cap: encrypted vault bytes, decrypted snapshot JSON, parsed Base64 strings, decoded source files, and other process/allocator overhead remain resident outside the estimate. The cumulative output cap and 32-real-attempt limit apply per file. Inspection never extracts files to disk or writes to the game directory.

## Compatibility limits

The supplied `GameData.db` has not yet been confirmed as SQLite, a PLXE container, or any other known format. SQLite inspection only runs after the standard SQLite header is detected. Defensive mode, query-only mode, disabled extension loading, `trusted_schema=OFF`, and a 500 ms SQLite progress-handler budget are applied. If `quick_check` is interrupted by that budget, the report is “inconclusive (time budget)” rather than a failed/corrupt check. If either SQLite header format-version byte (18 or 19) is `2`, the report says “WAL-mode database, main file only, may be stale” and skips `quick_check`. A PLXE/Zstandard signature match is only a candidate until the frame validates and decompresses cleanly. High entropy alone does not prove encryption because compressed data can also have high entropy.

Even a successfully decoded local database would not prove it is the authoritative record for coins, boosters, or level progress. Gardenscapes can synchronize progress with Playrix services. Editing, restore-to-game, and live Apply remain disabled until the file structure, integrity rules, and relationship to server-synced progress are independently verified.

A community reverse-engineering post documents PLXE + Zstandard wrapping for certain Playrix XML/assets; this remains a format clue, not confirmation about `GameData.db`: [format discussion](https://www.zenhax.com/viewtopic.php@t=16964.html).

Playrix says progress is automatically saved while connected to the internet: [Playrix support](https://playrix.helpshift.com/hc/en/5-gardenscapes/faq/718-saving-game-progress/).

## Verification status

**RC8 is not verified yet.** The Windows native Rust test suite must pass in full and the Windows x64 installer must complete successfully before this build is treated as ready. A successful frontend test run alone is not sufficient.

## Build on Windows

Requirements: Node.js 22+, Rust stable with the MSVC target, Visual Studio C++ Build Tools + Windows SDK, and NSIS.

Run `build_windows.bat` from the repository root. GitHub Actions builds an unsigned Windows x64 installer and uploads it as an artifact.

## LDPlayer 14

ADB discovery checks `GARDENVAULT_ADB`, then `C:\LDPlayer\LDPlayer14\adb.exe`, then `adb.exe` on PATH. Enable ADB debugging and LDPlayer root access. Close Gardenscapes completely before reading; GardenVault verifies that the process is stopped before and after capture but will not force-stop it.

## Security

The frontend cannot pass arbitrary shell commands or file paths. Native code uses a fixed ADB command allowlist against the known package and two file names. The passphrase is not saved. No telemetry, cloud sync, account service, plugin server, or automatic update is included.

See [docs/SECURITY.md](docs/SECURITY.md) and [docs/ROADMAP.md](docs/ROADMAP.md).
