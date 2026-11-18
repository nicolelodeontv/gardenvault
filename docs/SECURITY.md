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
Authenticated inspection decrypts the selected vault in memory, validates each embedded file's size and SHA-256 digest, and computes local diagnostics only. The signature scan reads the complete bounded captured file and reports all known strong-signature offsets. Zstandard candidates are decoded one at a time in streaming mode, with a 20 MiB retained-output cap, up to 20 MiB for SQLite’s read-only deserialization copy, a 16 MiB back-reference window cap, 32 KiB streaming scratch buffer, and 8 MiB decoder/scratch headroom (64 MiB nominal active decompression/SQLite working-set budget; source snapshot buffers are additional), plus a maximum of 32 real candidate attempts per file. Magic inside a previously measured frame is reported as overlapping and skipped; a frame at the exact end boundary is still eligible. Truncated frames, false magic, decode errors, size mismatches, and resource-limit hits have distinct statuses. Partial output is discarded and never reported as a decoded file.

When a standard SQLite header is present, GardenVault deserializes into an in-memory read-only SQLite connection, enables defensive mode and query-only mode, disables extension loading, sets `trusted_schema=OFF`, and bounds SQL inspection with a 500 ms progress handler. It queries schema metadata and runs `PRAGMA quick_check(1)` only when the SQLite header is not in WAL mode. It never writes the database image. The optional fixed `GameData.db-wal` companion is captured only if present; GardenVault reports its header, page size, frame boundaries, and salts as `unvalidated`; it does not replay frames or verify WAL checksums. SQLite images marked as WAL-mode are not deserialized without a proper WAL-aware read-only VFS.

Entropy, signature hits, and PLXE header fields (including size-word matches against decoded output) are clues, not proof of a particular format. High entropy can come from compression or encryption. A Zstandard result is labelled successful only after a complete frame can be sized and its streaming decode finishes successfully. When a WAL exists, capture compares the main database SHA-256 immediately before and after the WAL read and rejects the snapshot if it changes. This is a consistency guard, not a guaranteed atomic snapshot. No inspection path writes to Gardenscapes or transmits save data.
