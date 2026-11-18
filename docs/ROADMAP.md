# Product roadmap

## v1.0.0-rc.8 — Read-only binary forensics
- [x] Authenticated in-memory snapshot inspection and SHA-256 verification
- [x] Scan the complete file for every occurrence of the known strong signatures
- [x] Record all Zstandard candidate offsets and attempt bounded streaming decode at each (up to 32 per file)
- [x] Check frame content-size metadata against the actual decoded output size
- [x] Report exact compressed frame length and trailing bytes after each candidate frame
- [x] Inspect decompressed output for file type, signatures, SHA-256, entropy, and byte statistics
- [x] Parse PLXE-adjacent little-endian u32 fields and compare against file/payload lengths
- [x] Report whole-file, first-256-byte, remainder, and tail entropy
- [x] Report size modulo 16, 512, and 4096, plus the last 32 bytes in hex
- [x] Compare PLXE u32 fields against both compressed payload lengths and decoded frame output sizes
- [x] Share a 20 MiB retained-output budget across all candidate frames in each file
- [x] Parse the declared Zstandard window and reject values above 16 MiB before decoder creation/output allocation
- [x] Distinguish false magic, incomplete frames, decode failures, size mismatches, and resource-limit hits
- [x] Skip nested/overlapping frame signatures without skipping the next frame at a true frame boundary
- [x] Add 256 deterministic randomized scanner/decoder wrapper cases
- [x] Open SQLite images read-only in memory and run schema/quick-check queries
- [x] Capture the fixed companion WAL file if present, hash-check both the main file and WAL file around WAL capture, and inspect the WAL header/frame layout without replay
- [x] Detect Zstandard skippable-frame magic separately without feeding it to the normal decoder
- [x] Stream decompressed bytes through a fixed 32 KiB buffer and enforce a 20 MiB retained output + 20 MiB SQLite copy + 16 MiB window + 8 MiB headroom budget
- [x] Explicitly mark WAL frame inspection as unvalidated because checksums are not verified
- [x] Check the main database SHA-256 before and after optional WAL capture and reject changed pairs
- [x] Check WAL SHA-256 from reads before and after the selected WAL snapshot
- [x] Test an actual long-running SQLite query interrupted by the progress-handler deadline
- [x] Enable SQLite defensive/query-only modes, disable extension loading, turn off trusted_schema, and bound SQL inspection to 500 ms
- [x] Skip SQLite quick_check when either read/write header version marks WAL mode
- [x] Keep all inspection read-only and in memory, with bounded decompression output and a 500 ms SQLite SQL-query budget; timeout is reported as inconclusive rather than corruption

## Next milestones
1. Interpret the next RC8 report and determine whether any actual Zstandard frame validates.
2. Capture a second snapshot after a small, ordinary in-game progress change and compare them byte-for-byte, including header and tail regions.
3. Determine whether the local file is a cache, local checkpoint, or meaningful progress store; do not assume it is server-authoritative.
4. Implement a parser only after the container and integrity rules are verified.

Currency/item/level editing, restore-to-game, live Apply, cross-platform sync, and cloud analytics remain disabled.
