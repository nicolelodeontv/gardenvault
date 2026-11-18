# Security model

## Local-only design
This MVP has no analytics, user accounts, cloud backup, telemetry, external APIs, or automatic updates. Save data stays on the local Windows machine.

## ADB boundary
The UI cannot provide arbitrary shell commands or filesystem paths. Rust invokes ADB with fixed commands and only targets:
- Package: `com.playrix.gardenscapes`
- `/data/user/0/com.playrix.gardenscapes/Documents/GameData.db`
- `/data/user/0/com.playrix.gardenscapes/Documents/GameData.db.bak`

Device serials are limited to `emulator-NNNN` and loopback ADB serials. The game must be closed before capture. The application never writes to the Gardenscapes directory.

## Encrypted vault format
A `.gvault` file contains a 7-byte `GVLT001` header, 16-byte random salt, 12-byte random nonce, and authenticated ciphertext. Key derivation uses Argon2id (32 MiB memory, 3 iterations, 1 lane) to produce a 256-bit key. Encryption uses AES-256-GCM. The passphrase is not stored; plaintext files are only held in memory during capture. Export copies the existing encrypted container byte-for-byte through a native Save As dialog and never decrypts it.

## Known limitations
- The game save format has not been decoded or verified as SQLite.
- Currency, inventory, and level editing are disabled.
- There is no restore-to-game function.
- A compromised Windows account or malware running as the same user may access the app-data folder.
- The ADB executable must come from a trusted LDPlayer installation.

Never share the vault passphrase or commit `.gvault` files to Git.
