# Security model

## Local-only design
This MVP has no analytics, user accounts, cloud backup, telemetry, external APIs, or automatic updates. Save data stays on the local Windows machine.

## ADB boundary
The UI cannot provide arbitrary shell commands or filesystem paths. Rust invokes ADB with fixed commands and only targets:
- Package: `com.playrix.gardenscapes`
- `/data/user/0/com.playrix.gardenscapes/Documents/GameData.db`
- `/data/user/0/com.playrix.gardenscapes/Documents/GameData.db.bak`

The capture operation accepts only those two fixed filenames, wraps the full `cat` command in a quoted `su -c` argument, and uses `adb exec-out` for raw output. Device serials are limited to `emulator-NNNN` and loopback ADB serials. The game must be closed before capture. The application never writes to the Gardenscapes directory.

## Encrypted vault format
A `.gvault` file contains a 7-byte `GVLT001` header, 16-byte random salt, 12-byte random nonce, and authenticated ciphertext. Key derivation uses Argon2id (32 MiB memory, 3 iterations, 1 lane) to produce a 256-bit key. Encryption uses AES-256-GCM. The passphrase is not stored; plaintext files are only held in memory during capture. Export copies the existing encrypted container byte-for-byte through a native Save As dialog and never decrypts it.

## Known limitations
- The game save format has not been decoded or verified as standard SQLite.
- Currency, inventory, and level editing are disabled.
- There is no restore-to-game function.
- A compromised Windows account or malware running as the same user may access the app-data folder.
- The ADB executable must come from a trusted LDPlayer installation.
- The assumed save-file locations still need to be validated against a real LDPlayer 14 installation.

Never share the vault passphrase or commit `.gvault` files to Git.

## Snapshot inspection
Authenticated inspection decrypts the selected vault in memory, validates each embedded file's size and SHA-256 digest, and computes local diagnostics only. The signature scan reads the complete bounded captured file and reports all known strong-signature offsets. Zstandard candidates are decoded one at a time in streaming mode, with a 64 MiB aggregate decoded-output ceiling per file, a 64 MiB back-reference window cap, and a maximum of 32 candidate attempts per file. Decoded content is summarized in memory and is not written to disk.

Entropy, signature hits, and PLXE header fields (including size-word matches against decoded output) are clues, not proof of a particular format. High entropy can come from compression or encryption. A Zstandard result is labelled successful only after a complete frame can be sized and its streaming decode finishes successfully. No inspection path writes to Gardenscapes or transmits save data.
