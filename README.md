# GardenVault

GardenVault is a local-first Windows desktop utility for reading Gardenscapes profile files from an authorized LDPlayer 14 instance and creating encrypted offline snapshots.

## v1.0.0-rc.7 MVP

- Detect connected LDPlayer emulators through ADB.
- Verify the Gardenscapes package and root availability.
- Read the observed `GameData.db` and `GameData.db.bak` files after the game process exits.
- Quote the full `su -c` command and use raw `adb exec-out` transfer so the file path is not parsed as a root user ID and binary bytes avoid terminal conversion.
- Encrypt both files in memory with Argon2id + AES-256-GCM before writing a single `.gvault` file to local app data.
- Browse locally stored encrypted snapshots and export byte-identical encrypted copies through the Windows Save As dialog.
- Decrypt a selected snapshot only in memory after passphrase entry, verify each embedded file against its SHA-256 digest, and report conservative file-signature detection, entropy, printable-byte ratios, zero-byte ratios, unique-byte counts, and known signatures in the first 64 KiB without writing or applying any game data.
- Never write into the Gardenscapes game directory.
- No save data is sent to a cloud service.

## Compatibility limit

The supplied save files have not been identified as standard SQLite. The app currently reports file sizes, SHA-256 hashes, basic file signatures, and statistical binary diagnostics; it does not decode or edit coins, items, or level fields. Backup export copies the encrypted container unchanged and does not restore it into the game. Editing and live Apply remain disabled pending a verified format adapter.

The RC5 capture-command fix addresses the reported LDPlayer error `Unknown id: /data/user/0/...`. It still needs a fresh capture test on the target LDPlayer installation to confirm that the assumed files exist at the configured path.

## Build on Windows

Requirements: Node.js 22+, Rust stable with the MSVC target, Visual Studio C++ Build Tools + Windows SDK, and NSIS.

Run `build_windows.bat` from the repository root. The NSIS installer is created under `src-tauri/target/release/bundle/nsis/`. GitHub Actions also builds an unsigned Windows x64 installer and uploads it as an artifact.

## LDPlayer 14

ADB discovery checks `GARDENVAULT_ADB`, then `C:\LDPlayer\LDPlayer14\adb.exe`, then `adb.exe` on PATH. Enable ADB debugging and LDPlayer root access. Close Gardenscapes completely before reading.

## Security

The frontend cannot pass arbitrary shell commands or file paths. Native code uses a fixed ADB command allowlist against the known package and two file names. The passphrase is not saved. No telemetry, cloud sync, account service, plugin server, or automatic update is included in this offline MVP.

See [docs/SECURITY.md](docs/SECURITY.md) and [docs/ROADMAP.md](docs/ROADMAP.md).
