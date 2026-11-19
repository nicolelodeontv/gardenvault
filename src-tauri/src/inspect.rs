//! Read-only binary diagnostics for captured save files.
use rusqlite::{config::DbConfig, Connection};
use serde::Serialize;
use std::{
    io::{Cursor, Read},
    time::{Duration, Instant},
};

use super::*;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SqliteWalDiagnostics {
    pub(crate) present: bool,
    pub(crate) size_bytes: usize,
    pub(crate) status: String,
    pub(crate) checksum_validation: String,
    pub(crate) magic_hex: Option<String>,
    pub(crate) page_size_bytes: Option<usize>,
    pub(crate) complete_frames: usize,
    pub(crate) salt_matching_frames: usize,
    pub(crate) trailing_bytes: usize,
    pub(crate) note: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SqliteDiagnostics {
    pub(crate) opened_read_only: bool,
    pub(crate) status: String,
    pub(crate) sqlite_version: Option<String>,
    pub(crate) schema_objects: Vec<String>,
    pub(crate) quick_check: Option<String>,
    pub(crate) wal: Option<SqliteWalDiagnostics>,
    pub(crate) note: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ByteDiagnostics {
    pub(crate) size_bytes: usize,
    pub(crate) sha256: String,
    pub(crate) detected_format: String,
    pub(crate) signature_hex: String,
    pub(crate) entropy_bits_per_byte: f64,
    pub(crate) entropy_assessment: String,
    pub(crate) header_256_entropy_bits_per_byte: f64,
    pub(crate) body_entropy_after_256_bits_per_byte: f64,
    pub(crate) tail_256_entropy_bits_per_byte: f64,
    pub(crate) printable_ascii_percent: f64,
    pub(crate) zero_byte_percent: f64,
    pub(crate) unique_byte_values: usize,
    pub(crate) size_mod_16: usize,
    pub(crate) size_mod_512: usize,
    pub(crate) size_mod_4096: usize,
    pub(crate) tail_hex: String,
    pub(crate) embedded_signatures: Vec<String>,
    pub(crate) sqlite_database: Option<SqliteDiagnostics>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BlockProfileEntry {
    pub(crate) block_index: usize,
    pub(crate) offset_bytes: usize,
    pub(crate) size_bytes: usize,
    pub(crate) entropy_bits_per_byte: f64,
    pub(crate) printable_ascii_percent: f64,
    pub(crate) zero_byte_percent: f64,
    pub(crate) unique_byte_values: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BlockProfileDiagnostics {
    pub(crate) block_size_bytes: usize,
    pub(crate) block_count: usize,
    pub(crate) mean_entropy_bits_per_byte: f64,
    pub(crate) min_entropy_bits_per_byte: f64,
    pub(crate) max_entropy_bits_per_byte: f64,
    pub(crate) mean_printable_ascii_percent: f64,
    pub(crate) mean_zero_byte_percent: f64,
    pub(crate) blocks: Vec<BlockProfileEntry>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct XorCandidate {
    pub(crate) key_byte: u8,
    pub(crate) text_score: f64,
    pub(crate) printable_ascii_percent: f64,
    pub(crate) sqlite_magic_match: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SingleByteXorDiagnostics {
    pub(crate) sampled_bytes: usize,
    pub(crate) sample_method: String,
    pub(crate) sqlite_magic_xor_key: Option<u8>,
    pub(crate) top_candidates: Vec<XorCandidate>,
    pub(crate) note: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RepeatingKeyXorCandidate {
    pub(crate) key_length: usize,
    pub(crate) key_hex: String,
    pub(crate) text_score: f64,
    pub(crate) printable_ascii_percent: f64,
    pub(crate) letters_and_spaces_percent: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RepeatingKeyXorDiagnostics {
    pub(crate) min_key_length: usize,
    pub(crate) max_key_length: usize,
    pub(crate) key_lengths_tested: usize,
    pub(crate) sampled_bytes: usize,
    pub(crate) sample_segments: usize,
    pub(crate) candidates: Vec<RepeatingKeyXorCandidate>,
    pub(crate) note: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransformDiagnostics {
    pub(crate) block_profile: BlockProfileDiagnostics,
    pub(crate) single_byte_xor: SingleByteXorDiagnostics,
    pub(crate) repeating_key_xor: RepeatingKeyXorDiagnostics,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ZstdProbe {
    pub(crate) offset: usize,
    pub(crate) status: String,
    pub(crate) frame_content_size_bytes: Option<u64>,
    pub(crate) compressed_frame_size_bytes: Option<usize>,
    pub(crate) trailing_bytes_after_frame: Option<usize>,
    pub(crate) observed_output_bytes: Option<u64>,
    pub(crate) note: String,
    pub(crate) decoded: Option<ByteDiagnostics>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ZstdSkippableFrame {
    pub(crate) offset: usize,
    pub(crate) magic_hex: String,
    pub(crate) frame_id: u8,
    pub(crate) declared_payload_bytes: usize,
    pub(crate) available_payload_bytes: usize,
    pub(crate) status: String,
    pub(crate) note: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InspectedFile {
    pub(crate) name: String,
    #[serde(flatten)]
    pub(crate) diagnostics: ByteDiagnostics,
    pub(crate) plxe_header_words: Vec<String>,
    pub(crate) plxe_header_decoded_size_matches: Vec<String>,
    pub(crate) zstd_candidates_total: usize,
    pub(crate) zstd_candidates_attempted: usize,
    pub(crate) zstd_candidates_skipped: usize,
    pub(crate) zstd_candidates_overlapping_skipped: usize,
    pub(crate) zstd_skippable_frames: Vec<ZstdSkippableFrame>,
    pub(crate) zstd_probes: Vec<ZstdProbe>,
    pub(crate) transform_diagnostics: TransformDiagnostics,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VaultInspection {
    pub(crate) device_serial: String,
    pub(crate) captured_at: String,
    pub(crate) capture_integrity: Option<String>,
    pub(crate) missing_optional_files: Vec<String>,
    pub(crate) files: Vec<InspectedFile>,
    pub(crate) identical_files: bool,
}

pub(crate) fn byte_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0_usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let length = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .fold(0.0, |entropy, count| {
            let probability = *count as f64 / length;
            entropy - probability * probability.log2()
        })
}

pub(crate) fn byte_percent(bytes: &[u8], predicate: impl Fn(u8) -> bool) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let matching = bytes.iter().filter(|byte| predicate(**byte)).count();
    (matching as f64 * 100.0) / bytes.len() as f64
}

pub(crate) fn unique_byte_count(bytes: &[u8]) -> usize {
    let mut seen = [false; 256];
    for byte in bytes {
        seen[*byte as usize] = true;
    }
    seen.iter().filter(|value| **value).count()
}

pub(crate) fn entropy_assessment(entropy: f64) -> String {
    if entropy >= 7.75 {
        "Very high entropy; encryption or compression are both plausible".to_string()
    } else if entropy >= 6.5 {
        "High entropy; compression, encoding, or encryption are possible".to_string()
    } else {
        "Lower entropy; structured binary data may be present".to_string()
    }
}

pub(crate) fn find_signature_offsets(bytes: &[u8], signature: &[u8]) -> Vec<usize> {
    if signature.is_empty() || bytes.len() < signature.len() {
        return Vec::new();
    }
    bytes
        .windows(signature.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == signature).then_some(offset))
        .collect()
}

pub(crate) fn find_embedded_signatures(bytes: &[u8]) -> Vec<String> {
    // Scan the complete captured file (up to the existing 64 MiB capture cap).
    // Only signatures of at least three bytes are listed; two-byte zlib/gzip
    // prefixes are too collision-prone for useful embedded-hit reporting.
    const SIGNATURES: [(&str, &[u8]); 8] = [
        ("SQLite", b"SQLite format 3\0"),
        ("Playrix PLXE wrapper", b"PLXE"),
        ("ZIP", b"PK\x03\x04"),
        ("Zstandard", ZSTD_MAGIC),
        ("LZ4 frame", b"\x04\x22\x4d\x18"),
        ("PNG", b"\x89PNG\r\n\x1a\n"),
        ("JPEG", b"\xff\xd8\xff"),
        ("UnityFS", b"UnityFS"),
    ];
    let mut found = Vec::new();
    for (label, signature) in SIGNATURES {
        for offset in find_signature_offsets(bytes, signature) {
            found.push(format!("{label} signature at offset 0x{offset:X}"));
        }
    }
    if found.is_empty() {
        found.push("No known signatures found in the complete file".to_string());
    }
    found
}

pub(crate) fn plxe_header_words(
    bytes: &[u8],
    plxe_offsets: &[usize],
    zstd_offsets: &[usize],
    probes: &[ZstdProbe],
) -> Vec<String> {
    let mut words = Vec::new();
    for &plxe_offset in plxe_offsets.iter().take(32) {
        let Some(header_start) = plxe_offset.checked_add(4) else {
            continue;
        };
        let header_limit = bytes.len().min(plxe_offset.saturating_add(36));
        let payload_start = zstd_offsets
            .iter()
            .copied()
            .filter(|offset| *offset >= header_start)
            .min();
        let header_end = payload_start.unwrap_or(header_limit).min(header_limit);
        let mut field_offset = header_start;
        while field_offset.saturating_add(4) <= header_end {
            let value = u32::from_le_bytes([
                bytes[field_offset],
                bytes[field_offset + 1],
                bytes[field_offset + 2],
                bytes[field_offset + 3],
            ]);
            let remaining_after_field = bytes.len().saturating_sub(field_offset + 4);
            let mut matches = Vec::new();
            if value as usize == bytes.len() {
                matches.push("matches total file size");
            }
            if value as usize == remaining_after_field {
                matches.push("matches bytes after field");
            }
            for &zstd_offset in zstd_offsets
                .iter()
                .filter(|offset| **offset >= header_start)
                .take(8)
            {
                if value as usize == bytes.len().saturating_sub(zstd_offset) {
                    matches.push("matches bytes from Zstandard candidate to EOF");
                    break;
                }
            }
            if probes.iter().any(|probe| {
                probe.offset >= header_start
                    && probe.compressed_frame_size_bytes == Some(value as usize)
            }) {
                matches.push("matches compressed Zstandard frame length");
            }
            let match_text = if matches.is_empty() {
                String::new()
            } else {
                format!(" ({})", matches.join(", "))
            };
            let word_index = ((field_offset - header_start) / 4) + 1;
            words.push(format!(
                "PLXE@0x{plxe_offset:X} word {word_index} (+0x{:02X}): u32le={} (0x{value:08X}){match_text}",
                field_offset - plxe_offset,
                value
            ));
            field_offset += 4;
        }
    }
    words
}

pub(crate) fn plxe_header_decoded_size_matches(
    bytes: &[u8],
    plxe_offsets: &[usize],
    zstd_offsets: &[usize],
    probes: &[ZstdProbe],
) -> Vec<String> {
    let mut matches = Vec::new();
    let decoded_frames = probes.iter().filter_map(|probe| {
        probe
            .decoded
            .as_ref()
            .map(|decoded| (probe.offset, decoded.size_bytes))
    });
    let decoded_frames = decoded_frames.collect::<Vec<_>>();
    for &plxe_offset in plxe_offsets.iter().take(32) {
        let Some(header_start) = plxe_offset.checked_add(4) else {
            continue;
        };
        let header_limit = bytes.len().min(plxe_offset.saturating_add(36));
        let payload_start = zstd_offsets
            .iter()
            .copied()
            .filter(|offset| *offset >= header_start)
            .min();
        let header_end = payload_start.unwrap_or(header_limit).min(header_limit);
        let mut field_offset = header_start;
        while field_offset.saturating_add(4) <= header_end {
            let value = u32::from_le_bytes([
                bytes[field_offset],
                bytes[field_offset + 1],
                bytes[field_offset + 2],
                bytes[field_offset + 3],
            ]) as usize;
            for (frame_offset, decoded_size) in &decoded_frames {
                if value == *decoded_size {
                    // Byte offsets are relative to the PLXE magic itself:
                    // word 1 starts at +0x04, word 2 at +0x08, etc.
                    let word_index = ((field_offset - header_start) / 4) + 1;
                    matches.push(format!(
                        "PLXE@0x{plxe_offset:X} word {word_index} (+0x{:02X}) equals decoded size {} from Zstandard@0x{frame_offset:X}",
                        field_offset - plxe_offset,
                        decoded_size
                    ));
                }
            }
            field_offset += 4;
        }
    }
    matches
}

pub(crate) fn inspect_sqlite_wal(wal: Option<&[u8]>) -> SqliteWalDiagnostics {
    let Some(bytes) = wal else {
        return SqliteWalDiagnostics {
            present: false,
            size_bytes: 0,
            status: "unvalidated-not-present".to_string(),
            checksum_validation: "unvalidated".to_string(),
            magic_hex: None,
            page_size_bytes: None,
            complete_frames: 0,
            salt_matching_frames: 0,
            trailing_bytes: 0,
            note: "No companion GameData.db-wal file was captured.".to_string(),
        };
    };

    let magic_hex = bytes.get(..4).map(hex::encode);
    if bytes.len() < 32 {
        return SqliteWalDiagnostics {
            present: true,
            size_bytes: bytes.len(),
            status: "unvalidated-incomplete-header".to_string(),
            checksum_validation: "unvalidated".to_string(),
            magic_hex,
            page_size_bytes: None,
            complete_frames: 0,
            salt_matching_frames: 0,
            trailing_bytes: bytes.len(),
            note: "WAL file is shorter than its 32-byte header.".to_string(),
        };
    }

    let magic = u32::from_be_bytes(bytes[0..4].try_into().unwrap_or_default());
    let version = u32::from_be_bytes(bytes[4..8].try_into().unwrap_or_default());
    let raw_page_size = u32::from_be_bytes(bytes[8..12].try_into().unwrap_or_default()) as usize;
    let page_size = if raw_page_size == 1 {
        65_536
    } else {
        raw_page_size
    };
    let valid_magic = magic == 0x377f_0682 || magic == 0x377f_0683;
    let valid_page_size = (512..=65_536).contains(&page_size) && page_size.is_power_of_two();

    if !valid_magic || version != 3_007_000 || !valid_page_size {
        return SqliteWalDiagnostics {
            present: true, size_bytes: bytes.len(), status: "unvalidated-invalid-header".to_string(),
            checksum_validation: "unvalidated".to_string(),
            magic_hex, page_size_bytes: if valid_page_size { Some(page_size) } else { None },
            complete_frames: 0, salt_matching_frames: 0, trailing_bytes: bytes.len().saturating_sub(32),
            note: format!("WAL header validation failed (magic valid: {valid_magic}; version: {version}; page size: {raw_page_size})."),
        };
    }

    let frame_size = 24 + page_size;
    let frame_bytes = bytes.len() - 32;
    let complete_frames = frame_bytes / frame_size;
    let trailing_bytes = frame_bytes % frame_size;
    let salt_one = &bytes[16..20];
    let salt_two = &bytes[20..24];
    let mut salt_matching_frames = 0_usize;
    for frame_index in 0..complete_frames {
        let frame_offset = 32 + frame_index * frame_size;
        if &bytes[frame_offset + 8..frame_offset + 12] == salt_one
            && &bytes[frame_offset + 12..frame_offset + 16] == salt_two
        {
            salt_matching_frames += 1;
        }
    }
    let status = if complete_frames == 0 {
        "unvalidated-header-no-complete-frames"
    } else if salt_matching_frames == complete_frames && trailing_bytes == 0 {
        "unvalidated-header-and-frame-layout"
    } else {
        "unvalidated-frames-or-tail-need-review"
    };
    SqliteWalDiagnostics {
        present: true,
        size_bytes: bytes.len(),
        status: status.to_string(),
        checksum_validation: "unvalidated".to_string(),
        magic_hex,
        page_size_bytes: Some(page_size),
        complete_frames,
        salt_matching_frames,
        trailing_bytes,
        note: "UNVALIDATED: WAL header, frame boundaries, and frame salts were inspected only. Frame checksums were not verified and WAL pages were not replayed.".to_string(),
    }
}

pub(crate) fn sqlite_query_was_interrupted(error: &rusqlite::Error) -> bool {
    error.to_string().to_ascii_lowercase().contains("interrupt")
}

pub(crate) fn sqlite_query_error_status(error: &rusqlite::Error) -> &'static str {
    if sqlite_query_was_interrupted(error) {
        SQLITE_TIMEOUT_LABEL
    } else {
        "quick-check-error"
    }
}

pub(crate) fn sqlite_diagnostics_failure(status: &str, note: String) -> SqliteDiagnostics {
    SqliteDiagnostics {
        opened_read_only: false,
        status: status.to_string(),
        sqlite_version: None,
        schema_objects: Vec::new(),
        quick_check: None,
        wal: Some(inspect_sqlite_wal(None)),
        note,
    }
}

pub(crate) fn inspect_sqlite_readonly(bytes: &[u8]) -> Option<SqliteDiagnostics> {
    if !bytes.starts_with(b"SQLite format 3\0") {
        return None;
    }

    // Header bytes 18 and 19 are the SQLite read/write format versions.
    // Version 2 indicates WAL mode: the main file alone may be stale.
    let write_version = bytes.get(18).copied().unwrap_or_default();
    let read_version = bytes.get(19).copied().unwrap_or_default();
    if write_version == 2 || read_version == 2 {
        return Some(sqlite_diagnostics_failure(
            "wal-mode-main-file-only-may-be-stale",
            format!(
                "WAL-mode database, main file only, may be stale (read/write format versions: {read_version}/{write_version}). quick_check was skipped; any companion WAL is reported separately and is not replayed."
            ),
        ));
    }

    let mut connection = match Connection::open_in_memory() {
        Ok(connection) => connection,
        Err(error) => {
            return Some(sqlite_diagnostics_failure(
                "open-failed",
                format!("Could not create in-memory SQLite connection: {error}"),
            ))
        }
    };

    if let Err(error) = connection.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true) {
        return Some(sqlite_diagnostics_failure(
            "defensive-config-failed",
            format!("Could not enable SQLITE_DBCONFIG_DEFENSIVE: {error}"),
        ));
    }
    if let Err(error) = connection.load_extension_disable() {
        return Some(sqlite_diagnostics_failure(
            "extension-disable-failed",
            format!("Could not explicitly disable SQLite extension loading: {error}"),
        ));
    }
    if let Err(error) = connection.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")
    {
        return Some(sqlite_diagnostics_failure(
            "readonly-pragmas-failed",
            format!("Could not enable query_only and trusted_schema protections: {error}"),
        ));
    }
    if let Err(error) =
        connection.deserialize_read_exact(rusqlite::MAIN_DB, Cursor::new(bytes), bytes.len(), true)
    {
        return Some(sqlite_diagnostics_failure(
            "readonly-open-failed",
            format!("SQLite rejected the read-only in-memory database image: {error}"),
        ));
    }

    // Bound all SQL inspection work, including quick_check and schema listing.
    let deadline = Instant::now() + Duration::from_millis(SQLITE_QUERY_BUDGET_MS);
    connection.progress_handler(1_000, Some(move || Instant::now() >= deadline));

    let sqlite_version = connection
        .query_row("SELECT sqlite_version()", [], |row| row.get::<_, String>(0))
        .ok();
    let quick_check_result =
        connection.query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0));
    let quick_check = quick_check_result.as_ref().ok().cloned();
    if let Err(error) = quick_check_result {
        let timed_out = sqlite_query_was_interrupted(&error);
        return Some(SqliteDiagnostics {
            opened_read_only: true,
            status: sqlite_query_error_status(&error).to_string(),
            sqlite_version,
            schema_objects: Vec::new(),
            quick_check: if timed_out {
                Some(SQLITE_TIMEOUT_LABEL.to_string())
            } else {
                None
            },
            wal: Some(inspect_sqlite_wal(None)),
            note: if timed_out {
                format!(
                    "Read-only SQLite quick_check was inconclusive (time budget): the {} ms inspection budget expired ({error}). This is not evidence of corruption; no database writes were permitted.",
                    SQLITE_QUERY_BUDGET_MS
                )
            } else {
                format!(
                    "Read-only SQLite inspection stopped during quick_check with a query error: {error}. No database writes were permitted."
                )
            },
        });
    }

    let mut schema_objects = Vec::new();
    let mut schema_timed_out = false;
    match connection.prepare(
        "SELECT name FROM sqlite_master WHERE type IN ('table','index','view','trigger') ORDER BY type,name"
    ) {
        Ok(mut statement) => match statement.query_map([], |row| row.get::<_, String>(0)) {
            Ok(rows) => {
                for row in rows.take(100) {
                    match row {
                        Ok(name) => schema_objects.push(name.chars().take(120).collect()),
                        Err(error) => {
                            schema_timed_out = sqlite_query_was_interrupted(&error);
                            break;
                        }
                    }
                }
            }
            Err(error) => schema_timed_out = error.to_string().to_ascii_lowercase().contains("interrupt"),
        },
        Err(error) => schema_timed_out = error.to_string().to_ascii_lowercase().contains("interrupt"),
    }

    Some(SqliteDiagnostics {
        opened_read_only: true,
        status: if schema_timed_out {
            SQLITE_TIMEOUT_LABEL.to_string()
        } else if quick_check.as_deref() == Some("ok") {
            "opened-readonly-integrity-ok".to_string()
        } else {
            "opened-readonly".to_string()
        },
        sqlite_version,
        schema_objects,
        quick_check,
        wal: Some(inspect_sqlite_wal(None)),
        note: format!(
            "SQLite image was deserialized read-only in memory; defensive mode and query_only were enabled, extension loading was explicitly disabled, and SQL inspection had a {} ms progress-handler budget. No database pages were written.",
            SQLITE_QUERY_BUDGET_MS
        ),
    })
}

pub(crate) fn find_zstd_skippable_frames(bytes: &[u8]) -> Vec<ZstdSkippableFrame> {
    let mut frames = Vec::new();
    if bytes.len() < 4 {
        return frames;
    }

    let mut offset = 0_usize;
    while offset.saturating_add(4) <= bytes.len() {
        let magic = u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ]);
        if !(ZSTD_SKIPPABLE_MAGIC_BASE..=ZSTD_SKIPPABLE_MAGIC_BASE + 15).contains(&magic) {
            offset += 1;
            continue;
        }

        let remaining = bytes.len() - offset;
        if remaining < 8 {
            frames.push(ZstdSkippableFrame {
                offset,
                magic_hex: hex::encode(&bytes[offset..offset + 4]),
                frame_id: (magic - ZSTD_SKIPPABLE_MAGIC_BASE) as u8,
                declared_payload_bytes: 0,
                available_payload_bytes: 0,
                status: "incomplete-skippable-header".to_string(),
                note: "Zstandard skippable magic is present, but the 4-byte payload-length field is truncated.".to_string(),
            });
            offset += 1;
            continue;
        }

        let declared_payload_bytes = u32::from_le_bytes([
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]) as usize;
        let available_to_eof = remaining - 8;
        let complete = declared_payload_bytes <= available_to_eof;

        // A skippable frame's payload is opaque. Do not interpret magic-looking
        // bytes inside a complete payload as nested frames. For an incomplete
        // payload, report bytes only up to the next recognizable header so a
        // following truncated frame is not accidentally counted as payload.
        let next_header = (offset + 8..=bytes.len().saturating_sub(4)).find(|candidate| {
            let candidate_magic = u32::from_le_bytes([
                bytes[*candidate],
                bytes[*candidate + 1],
                bytes[*candidate + 2],
                bytes[*candidate + 3],
            ]);
            (ZSTD_SKIPPABLE_MAGIC_BASE..=ZSTD_SKIPPABLE_MAGIC_BASE + 15).contains(&candidate_magic)
        });
        let available_payload_bytes = if complete {
            declared_payload_bytes
        } else {
            next_header
                .map(|next| next - (offset + 8))
                .unwrap_or(available_to_eof)
        };

        frames.push(ZstdSkippableFrame {
            offset,
            magic_hex: hex::encode(&bytes[offset..offset + 4]),
            frame_id: (magic - ZSTD_SKIPPABLE_MAGIC_BASE) as u8,
            declared_payload_bytes,
            available_payload_bytes,
            status: if complete { "unvalidated-complete-skippable-frame" } else { "incomplete-skippable-frame" }.to_string(),
            note: if complete {
                "Zstandard skippable frame; payload was not decoded and does not count toward the normal-frame attempt budget.".to_string()
            } else {
                "Zstandard skippable-frame header was found, but its declared payload extends beyond the captured file.".to_string()
            },
        });

        if complete {
            offset = offset
                .saturating_add(8)
                .saturating_add(declared_payload_bytes);
        } else if let Some(next) = next_header {
            offset = next;
        } else {
            break;
        }
    }
    frames
}

pub(crate) const TRANSFORM_SAMPLE_BYTES: usize = 64 * 1024;
pub(crate) const TRANSFORM_BLOCK_BYTES: usize = 4 * 1024;
pub(crate) const REPEATING_XOR_MIN_KEY_LENGTH: usize = 1;
pub(crate) const REPEATING_XOR_MAX_KEY_LENGTH: usize = 32;
pub(crate) const REPEATING_XOR_SEGMENT_BYTES: usize = 8 * 1024;
pub(crate) const REPEATING_XOR_SEGMENT_COUNT: usize = 8;

pub(crate) fn mean_value(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

pub(crate) fn block_profile(bytes: &[u8]) -> BlockProfileDiagnostics {
    let blocks = bytes
        .chunks(TRANSFORM_BLOCK_BYTES)
        .enumerate()
        .map(|(block_index, chunk)| BlockProfileEntry {
            block_index,
            offset_bytes: block_index * TRANSFORM_BLOCK_BYTES,
            size_bytes: chunk.len(),
            entropy_bits_per_byte: byte_entropy(chunk),
            printable_ascii_percent: byte_percent(chunk, |byte| (0x20..=0x7e).contains(&byte)),
            zero_byte_percent: byte_percent(chunk, |byte| byte == 0),
            unique_byte_values: unique_byte_count(chunk),
        })
        .collect::<Vec<_>>();
    let entropies = blocks
        .iter()
        .map(|block| block.entropy_bits_per_byte)
        .collect::<Vec<_>>();
    let printable = blocks
        .iter()
        .map(|block| block.printable_ascii_percent)
        .collect::<Vec<_>>();
    let zeroes = blocks
        .iter()
        .map(|block| block.zero_byte_percent)
        .collect::<Vec<_>>();
    BlockProfileDiagnostics {
        block_size_bytes: TRANSFORM_BLOCK_BYTES,
        block_count: blocks.len(),
        mean_entropy_bits_per_byte: mean_value(&entropies),
        min_entropy_bits_per_byte: entropies.iter().copied().reduce(f64::min).unwrap_or(0.0),
        max_entropy_bits_per_byte: entropies.iter().copied().reduce(f64::max).unwrap_or(0.0),
        mean_printable_ascii_percent: mean_value(&printable),
        mean_zero_byte_percent: mean_value(&zeroes),
        blocks,
    }
}

#[allow(clippy::match_overlapping_arm)]
pub(crate) fn text_likeness_weight(byte: u8) -> f64 {
    match byte {
        b' ' => 3.2,
        b'\n' | b'\r' | b'\t' => 1.1,
        b'e' | b't' | b'a' | b'o' | b'i' | b'n' => 2.9,
        b'E' | b'T' | b'A' | b'O' | b'I' | b'N' => 2.4,
        b's' | b'h' | b'r' | b'd' | b'l' | b'u' | b'S' | b'H' | b'R' | b'D' | b'L' | b'U' => 2.0,
        b'a'..=b'z' | b'A'..=b'Z' => 1.7,
        b'0'..=b'9' => 0.8,
        b'.' | b',' | b';' | b':' | b'!' | b'?' | b'\'' | b'"' | b'(' | b')' | b'[' | b']'
        | b'{' | b'}' | b'/' | b'\\' | b'-' | b'_' => 0.7,
        0x20..=0x7e => 0.0,
        _ => -4.0,
    }
}

pub(crate) fn text_likeness_score(total_weight: f64, count: usize) -> f64 {
    if count == 0 {
        return 0.0;
    }
    let average_weight = total_weight / count as f64;
    (((average_weight + 4.0) / 8.0) * 100.0).clamp(0.0, 100.0)
}

pub(crate) fn evenly_spaced_sample(bytes: &[u8], maximum: usize) -> Vec<u8> {
    if bytes.len() <= maximum {
        return bytes.to_vec();
    }
    let sample_count = maximum.max(2).min(bytes.len());
    (0..sample_count)
        .map(|index| {
            let source_index = index * (bytes.len() - 1) / (sample_count - 1);
            bytes[source_index]
        })
        .collect()
}

pub(crate) fn sqlite_magic_xor_key(bytes: &[u8]) -> Option<u8> {
    const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";
    let first = *bytes.first()?;
    let key = first ^ SQLITE_HEADER[0];
    bytes
        .get(..SQLITE_HEADER.len())?
        .iter()
        .zip(SQLITE_HEADER.iter())
        .all(|(actual, expected)| (*actual ^ key) == *expected)
        .then_some(key)
}

pub(crate) fn score_single_byte_xor(sample: &[u8], key: u8) -> XorCandidate {
    let mut total_weight = 0.0;
    let mut printable_count = 0_usize;
    for byte in sample {
        let decoded = *byte ^ key;
        total_weight += text_likeness_weight(decoded);
        if (0x20..=0x7e).contains(&decoded) {
            printable_count += 1;
        }
    }
    XorCandidate {
        key_byte: key,
        text_score: text_likeness_score(total_weight, sample.len()),
        printable_ascii_percent: if sample.is_empty() {
            0.0
        } else {
            printable_count as f64 * 100.0 / sample.len() as f64
        },
        sqlite_magic_match: false,
    }
}

pub(crate) fn single_byte_xor_diagnostics(bytes: &[u8]) -> SingleByteXorDiagnostics {
    let sample = evenly_spaced_sample(bytes, TRANSFORM_SAMPLE_BYTES);
    let magic_key = sqlite_magic_xor_key(bytes);
    let mut candidates = (0_u16..=255)
        .map(|key| score_single_byte_xor(&sample, key as u8))
        .collect::<Vec<_>>();
    for candidate in &mut candidates {
        candidate.sqlite_magic_match = magic_key == Some(candidate.key_byte);
    }
    candidates.sort_by(|left, right| {
        right
            .text_score
            .total_cmp(&left.text_score)
            .then_with(|| {
                right
                    .printable_ascii_percent
                    .total_cmp(&left.printable_ascii_percent)
            })
            .then_with(|| left.key_byte.cmp(&right.key_byte))
    });
    candidates.truncate(5);
    if let Some(key) = magic_key {
        if !candidates.iter().any(|candidate| candidate.key_byte == key) {
            let mut candidate = score_single_byte_xor(&sample, key);
            candidate.sqlite_magic_match = true;
            candidates.push(candidate);
        }
    }
    SingleByteXorDiagnostics {
        sampled_bytes: sample.len(),
        sample_method: "Evenly spaced across the complete file, capped at 65,536 bytes.".to_string(),
        sqlite_magic_xor_key: magic_key,
        top_candidates: candidates,
        note: "Heuristic only: candidates are scored for ASCII text-likeness. A score is not a decryption result or format identification; no transformed bytes are saved.".to_string(),
    }
}

pub(crate) fn repeating_key_segments(bytes: &[u8]) -> Vec<(usize, Vec<u8>)> {
    if bytes.len() <= TRANSFORM_SAMPLE_BYTES {
        return vec![(0, bytes.to_vec())];
    }
    let segment_count = REPEATING_XOR_SEGMENT_COUNT
        .min(bytes.len().div_ceil(REPEATING_XOR_SEGMENT_BYTES))
        .max(2);
    let segment_len = REPEATING_XOR_SEGMENT_BYTES.min(bytes.len());
    (0..segment_count)
        .map(|index| {
            let start = (bytes.len() - segment_len) * index / (segment_count - 1);
            (start, bytes[start..start + segment_len].to_vec())
        })
        .collect()
}

pub(crate) fn repeating_key_xor_candidate(
    segments: &[(usize, Vec<u8>)],
    key_length: usize,
) -> RepeatingKeyXorCandidate {
    let mut histograms = [[0_usize; 256]; REPEATING_XOR_MAX_KEY_LENGTH];
    for (segment_start, segment) in segments {
        for (index, byte) in segment.iter().enumerate() {
            let column = (segment_start + index) % key_length;
            histograms[column][*byte as usize] += 1;
        }
    }

    let mut key = Vec::with_capacity(key_length);
    for histogram in histograms.iter().take(key_length) {
        let mut best_key = 0_u8;
        let mut best_weight = f64::NEG_INFINITY;
        for candidate_key in 0_u16..=255 {
            let weight = histogram
                .iter()
                .enumerate()
                .map(|(source_byte, count)| {
                    *count as f64 * text_likeness_weight((source_byte as u8) ^ candidate_key as u8)
                })
                .sum::<f64>();
            if weight > best_weight {
                best_weight = weight;
                best_key = candidate_key as u8;
            }
        }
        key.push(best_key);
    }

    let mut total_weight = 0.0;
    let mut total_bytes = 0_usize;
    let mut printable_count = 0_usize;
    let mut letters_and_spaces_count = 0_usize;
    for (segment_start, segment) in segments {
        for (index, byte) in segment.iter().enumerate() {
            let decoded = *byte ^ key[(segment_start + index) % key_length];
            total_weight += text_likeness_weight(decoded);
            total_bytes += 1;
            if (0x20..=0x7e).contains(&decoded) {
                printable_count += 1;
            }
            if decoded.is_ascii_alphabetic() || decoded == b' ' {
                letters_and_spaces_count += 1;
            }
        }
    }

    RepeatingKeyXorCandidate {
        key_length,
        key_hex: hex::encode(key),
        text_score: text_likeness_score(total_weight, total_bytes),
        printable_ascii_percent: if total_bytes == 0 {
            0.0
        } else {
            printable_count as f64 * 100.0 / total_bytes as f64
        },
        letters_and_spaces_percent: if total_bytes == 0 {
            0.0
        } else {
            letters_and_spaces_count as f64 * 100.0 / total_bytes as f64
        },
    }
}

pub(crate) fn repeating_key_xor_diagnostics(bytes: &[u8]) -> RepeatingKeyXorDiagnostics {
    let segments = repeating_key_segments(bytes);
    let sampled_bytes = segments.iter().map(|(_, segment)| segment.len()).sum();
    let candidates = (REPEATING_XOR_MIN_KEY_LENGTH..=REPEATING_XOR_MAX_KEY_LENGTH)
        .map(|key_length| repeating_key_xor_candidate(&segments, key_length))
        .collect::<Vec<_>>();
    RepeatingKeyXorDiagnostics {
        min_key_length: REPEATING_XOR_MIN_KEY_LENGTH,
        max_key_length: REPEATING_XOR_MAX_KEY_LENGTH,
        key_lengths_tested: candidates.len(),
        sampled_bytes,
        sample_segments: segments.len(),
        candidates,
        note: "Exploratory only. Each key byte is selected independently with an ASCII-text heuristic; longer keys can overfit. Candidate keys are not validated and do not establish that the save uses repeating-key XOR.".to_string(),
    }
}

pub(crate) fn transform_diagnostics(bytes: &[u8]) -> TransformDiagnostics {
    TransformDiagnostics {
        block_profile: block_profile(bytes),
        single_byte_xor: single_byte_xor_diagnostics(bytes),
        repeating_key_xor: repeating_key_xor_diagnostics(bytes),
    }
}

pub(crate) fn byte_diagnostics(bytes: &[u8]) -> ByteDiagnostics {
    let header_len = bytes.len().min(256);
    let tail_start = bytes.len().saturating_sub(256);
    let tail_hex_start = bytes.len().saturating_sub(32);
    let entropy = byte_entropy(bytes);
    ByteDiagnostics {
        size_bytes: bytes.len(),
        sha256: hash_hex(bytes),
        detected_format: detect_file_format(bytes),
        signature_hex: hex::encode(bytes.iter().take(32).copied().collect::<Vec<_>>()),
        entropy_bits_per_byte: entropy,
        entropy_assessment: entropy_assessment(entropy),
        header_256_entropy_bits_per_byte: byte_entropy(&bytes[..header_len]),
        body_entropy_after_256_bits_per_byte: byte_entropy(&bytes[header_len..]),
        tail_256_entropy_bits_per_byte: byte_entropy(&bytes[tail_start..]),
        printable_ascii_percent: byte_percent(bytes, |b| (0x20..=0x7e).contains(&b)),
        zero_byte_percent: byte_percent(bytes, |b| b == 0),
        unique_byte_values: unique_byte_count(bytes),
        size_mod_16: bytes.len() % 16,
        size_mod_512: bytes.len() % 512,
        size_mod_4096: bytes.len() % 4096,
        tail_hex: hex::encode(&bytes[tail_hex_start..]),
        embedded_signatures: find_embedded_signatures(bytes),
        sqlite_database: inspect_sqlite_readonly(bytes),
    }
}

pub(crate) fn zstd_frame_size_error_status(error_code: usize) -> (&'static str, String) {
    let message = zstd_safe::get_error_name(error_code);
    let lower = message.to_ascii_lowercase();
    if lower.contains("src size is incorrect") || lower.contains("source size is incorrect") {
        ("incomplete", format!("Zstandard signature is present, but the frame is truncated or incomplete: {message}"))
    } else {
        (
            "signature-only",
            format!(
                "Zstandard magic is present, but the bytes do not form a valid frame: {message}"
            ),
        )
    }
}

pub(crate) fn is_zstd_limit_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("too much memory")
        || lower.contains("window size")
        || lower.contains("window is too large")
        || lower.contains("memory limit")
        || lower.contains("maximum window")
}

pub(crate) fn zstd_declared_window_size(payload: &[u8]) -> Option<u64> {
    if payload.get(..4)? != &ZSTD_MAGIC[..] {
        return None;
    }
    let descriptor = *payload.get(4)?;
    // Bits 4 and 3 are reserved in the frame header descriptor.
    if descriptor & 0x18 != 0 {
        return None;
    }
    let single_segment = descriptor & 0x20 != 0;
    if single_segment {
        // A single-segment frame's window is its declared content size.
        return zstd_safe::get_frame_content_size(payload).ok().flatten();
    }

    let window_descriptor = *payload.get(5)?;
    let window_log = 10_u32.checked_add((window_descriptor >> 3) as u32)?;
    let window_base = 1_u64.checked_shl(window_log)?;
    let window_add = (window_base >> 3).checked_mul((window_descriptor & 0x07) as u64)?;
    window_base.checked_add(window_add)
}

pub(crate) fn probe_zstd_frame(bytes: &[u8], offset: usize, remaining_budget: u64) -> ZstdProbe {
    let Some(payload) = bytes.get(offset..) else {
        return ZstdProbe {
            offset,
            status: "signature-only".to_string(),
            frame_content_size_bytes: None,
            compressed_frame_size_bytes: None,
            trailing_bytes_after_frame: None,
            observed_output_bytes: None,
            note: "Candidate offset is outside the file.".to_string(),
            decoded: None,
        };
    };

    let output_limit = MAX_DECOMPRESSED_BYTES.min(remaining_budget);
    let declared_size = zstd_safe::get_frame_content_size(payload).ok().flatten();
    if let Some(declared_window_size) = zstd_declared_window_size(payload) {
        if declared_window_size > MAX_ZSTD_WINDOW_BYTES {
            return ZstdProbe {
                offset, status: "limit-hit".to_string(), frame_content_size_bytes: declared_size,
                compressed_frame_size_bytes: None, trailing_bytes_after_frame: None,
                observed_output_bytes: None,
                note: format!(
                    "Declared Zstandard window is {} MiB, above the {} MiB ceiling; rejected before decoder creation and output-buffer allocation.",
                    declared_window_size / (1024 * 1024),
                    MAX_ZSTD_WINDOW_BYTES / (1024 * 1024)
                ),
                decoded: None,
            };
        }
    }
    let frame_size = match zstd_safe::find_frame_compressed_size(payload) {
        Ok(size) => size,
        Err(error_code) => {
            let (status, note) = zstd_frame_size_error_status(error_code);
            return ZstdProbe {
                offset,
                status: status.to_string(),
                frame_content_size_bytes: declared_size,
                compressed_frame_size_bytes: None,
                trailing_bytes_after_frame: None,
                observed_output_bytes: None,
                note,
                decoded: None,
            };
        }
    };

    if frame_size == 0 || frame_size > payload.len() {
        return ZstdProbe {
            offset,
            status: "signature-only".to_string(),
            frame_content_size_bytes: declared_size,
            compressed_frame_size_bytes: None,
            trailing_bytes_after_frame: None,
            observed_output_bytes: None,
            note: "Zstandard magic was found, but the reported frame boundary is invalid."
                .to_string(),
            decoded: None,
        };
    }

    if output_limit == 0 {
        return ZstdProbe {
            offset, status: "limit-hit".to_string(), frame_content_size_bytes: declared_size,
            compressed_frame_size_bytes: Some(frame_size),
            trailing_bytes_after_frame: Some(payload.len() - frame_size),
            observed_output_bytes: None,
            note: "The cumulative per-file decompression budget is exhausted; frame boundary was measured but the frame was not decompressed.".to_string(),
            decoded: None,
        };
    }

    if declared_size.is_some_and(|size| size > output_limit) {
        return ZstdProbe {
            offset,
            status: "limit-hit".to_string(),
            frame_content_size_bytes: declared_size,
            compressed_frame_size_bytes: Some(frame_size),
            trailing_bytes_after_frame: Some(payload.len() - frame_size),
            observed_output_bytes: None,
            note: format!(
                "Declared output exceeds the remaining {} MiB per-file output budget.",
                output_limit / (1024 * 1024)
            ),
            decoded: None,
        };
    }

    let frame = &payload[..frame_size];
    let mut decoder = match zstd::stream::read::Decoder::new(Cursor::new(frame)) {
        Ok(decoder) => decoder.single_frame(),
        Err(error) => {
            return ZstdProbe {
                offset, status: "decode-failed".to_string(), frame_content_size_bytes: declared_size,
                compressed_frame_size_bytes: Some(frame_size),
                trailing_bytes_after_frame: Some(payload.len() - frame_size),
                observed_output_bytes: None,
                note: format!("A complete frame boundary was found, but decoder initialization failed: {error}"),
                decoded: None,
            };
        }
    };
    if let Err(error) = decoder.window_log_max(MAX_ZSTD_WINDOW_BYTES.trailing_zeros()) {
        return ZstdProbe {
            offset, status: "limit-hit".to_string(), frame_content_size_bytes: declared_size,
            compressed_frame_size_bytes: Some(frame_size),
            trailing_bytes_after_frame: Some(payload.len() - frame_size),
            observed_output_bytes: None,
            note: format!("The Zstandard decoder could not apply its bounded 16 MiB window limit before output-buffer allocation: {error}"),
            decoded: None,
        };
    }

    // Reserve only the fixed safety ceiling, never the frame's declared size.
    // The output Vec remains alive while byte_diagnostics inspects it. If it is
    // SQLite, deserialize_read_exact may hold a second SQLite-owned copy at
    // the same time; that overlap is why the nominal budget counts 2 x 20 MiB.
    // One allocation avoids transient old+new Vec buffers during repeated growth.
    let mut output = Vec::new();
    if output.try_reserve_exact(output_limit as usize).is_err() {
        return ZstdProbe {
            offset, status: "limit-hit".to_string(), frame_content_size_bytes: declared_size,
            compressed_frame_size_bytes: Some(frame_size),
            trailing_bytes_after_frame: Some(payload.len() - frame_size),
            observed_output_bytes: Some(0),
            note: "Could not reserve the fixed bounded streaming output buffer; no decompression was attempted.".to_string(),
            decoded: None,
        };
    }
    let mut limited = decoder.take(output_limit.saturating_add(1));
    let mut chunk = [0_u8; 32 * 1024];
    loop {
        match limited.read(&mut chunk) {
            Ok(0) => break,
            Ok(read_bytes) => {
                let next_len = output.len().saturating_add(read_bytes);
                if next_len as u64 > output_limit {
                    return ZstdProbe {
                        offset, status: "limit-hit".to_string(), frame_content_size_bytes: declared_size,
                        compressed_frame_size_bytes: Some(frame_size),
                        trailing_bytes_after_frame: Some(payload.len() - frame_size),
                        observed_output_bytes: Some(next_len as u64),
                        note: format!(
                            "Streaming output exceeded the remaining {} MiB cumulative per-file budget. Partial output was discarded.",
                            output_limit / (1024 * 1024)
                        ),
                        decoded: None,
                    };
                }
                if output.try_reserve_exact(read_bytes).is_err() {
                    return ZstdProbe {
                        offset, status: "limit-hit".to_string(), frame_content_size_bytes: declared_size,
                        compressed_frame_size_bytes: Some(frame_size),
                        trailing_bytes_after_frame: Some(payload.len() - frame_size),
                        observed_output_bytes: Some(output.len() as u64),
                        note: "Memory allocation for the bounded streaming output buffer failed. Partial output was discarded.".to_string(),
                        decoded: None,
                    };
                }
                output.extend_from_slice(&chunk[..read_bytes]);
            }
            Err(error) => {
                let observed = output.len() as u64;
                let error_text = error.to_string();
                let is_limit = is_zstd_limit_error(&error_text);
                let declared_mismatch = declared_size.is_some_and(|size| size != observed);
                let (status, note) = if is_limit {
                    ("limit-hit", format!("Zstandard decoder hit a window or memory limit: {error_text}. Partial output ({observed} bytes) was discarded."))
                } else if declared_mismatch {
                    ("decoded-size-mismatch", format!("Frame declares {declared_size:?} output bytes, but decoding stopped after observing {observed} bytes with an error: {error_text}. Partial output was discarded and is not treated as a decoded file."))
                } else {
                    ("decode-failed", format!("Frame boundary was measured, but decompression failed: {error_text}. Partial output ({observed} bytes) was discarded."))
                };
                return ZstdProbe {
                    offset,
                    status: status.to_string(),
                    frame_content_size_bytes: declared_size,
                    compressed_frame_size_bytes: Some(frame_size),
                    trailing_bytes_after_frame: Some(payload.len() - frame_size),
                    observed_output_bytes: Some(observed),
                    note,
                    decoded: None,
                };
            }
        }
    }

    let decoded_size = output.len() as u64;
    let status = match declared_size {
        Some(size) if size == decoded_size => "decoded-size-matches",
        Some(_) => "decoded-size-mismatch",
        None => "decoded-size-unknown",
    };
    let note = match declared_size {
        Some(size) if size == decoded_size => "Frame decoded completely and declared content size matches.".to_string(),
        Some(size) => format!("Frame decoded completely, but declared content size {size} differs from actual output size {decoded_size}."),
        None => format!("Frame decoded completely; content size was not declared. Actual output size: {decoded_size}."),
    };
    ZstdProbe {
        offset,
        status: status.to_string(),
        frame_content_size_bytes: declared_size,
        compressed_frame_size_bytes: Some(frame_size),
        trailing_bytes_after_frame: Some(payload.len() - frame_size),
        observed_output_bytes: Some(decoded_size),
        note,
        decoded: Some(byte_diagnostics(&output)),
    }
}

pub(crate) fn inspect_bytes(
    bytes: &[u8],
) -> (
    ByteDiagnostics,
    Vec<String>,
    Vec<String>,
    usize,
    usize,
    usize,
    Vec<ZstdProbe>,
) {
    let plxe_offsets = find_signature_offsets(bytes, b"PLXE");
    let zstd_offsets = find_signature_offsets(bytes, ZSTD_MAGIC);
    let mut remaining_budget = MAX_DECOMPRESSED_BYTES;
    let mut probes = Vec::new();
    let mut attempted = 0_usize;
    let mut skipped_by_cap = 0_usize;
    let mut overlapping_skipped = 0_usize;
    let mut covered_until = 0_usize;

    for (index, offset) in zstd_offsets.iter().enumerate() {
        if *offset < covered_until {
            overlapping_skipped += 1;
            probes.push(ZstdProbe {
                offset: *offset,
                status: "overlapping-signature-skipped".to_string(),
                frame_content_size_bytes: None,
                compressed_frame_size_bytes: None,
                trailing_bytes_after_frame: None,
                observed_output_bytes: None,
                note: format!("Signature at 0x{offset:X} is inside an already measured frame; it is not counted as a separate frame."),
                decoded: None,
            });
            continue;
        }
        if attempted >= MAX_ZSTD_PROBES {
            skipped_by_cap += zstd_offsets.len() - index;
            break;
        }

        attempted += 1;
        let probe = probe_zstd_frame(bytes, *offset, remaining_budget);
        if let Some(decoded) = probe.decoded.as_ref() {
            remaining_budget = remaining_budget.saturating_sub(decoded.size_bytes as u64);
        } else if probe.status == "limit-hit"
            && probe
                .observed_output_bytes
                .is_some_and(|size| size > remaining_budget)
        {
            remaining_budget = 0;
        }
        if let Some(frame_size) = probe.compressed_frame_size_bytes {
            if let Some(end) = offset.checked_add(frame_size) {
                covered_until = covered_until.max(end);
            }
        }
        probes.push(probe);
    }

    let header_words = plxe_header_words(bytes, &plxe_offsets, &zstd_offsets, &probes);
    let decoded_size_matches =
        plxe_header_decoded_size_matches(bytes, &plxe_offsets, &zstd_offsets, &probes);
    (
        byte_diagnostics(bytes),
        header_words,
        decoded_size_matches,
        attempted,
        skipped_by_cap,
        overlapping_skipped,
        probes,
    )
}

pub(crate) fn detect_file_format(bytes: &[u8]) -> String {
    if bytes.starts_with(b"SQLite format 3\0") {
        return "SQLite 3 database".to_string();
    }
    if bytes.starts_with(b"PK\x03\x04") {
        return "ZIP archive".to_string();
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return "GZIP compressed data".to_string();
    }
    if bytes.starts_with(b"bplist00") {
        return "Apple binary property list".to_string();
    }
    let first_non_whitespace = bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace());
    if matches!(first_non_whitespace, Some(b'{' | b'[')) {
        return "JSON-like text (not parsed)".to_string();
    }
    if first_non_whitespace == Some(b'<') {
        return "XML-like text".to_string();
    }
    if bytes.starts_with(b"UnityFS") {
        return "UnityFS asset bundle".to_string();
    }
    if bytes.starts_with(ZSTD_MAGIC) {
        return "Zstandard frame".to_string();
    }
    if bytes.starts_with(b"PLXE") {
        return "Playrix PLXE container (payload not decoded)".to_string();
    }
    if bytes.starts_with(b"ENC") {
        return "Unknown binary (ENC prefix)".to_string();
    }
    "Unknown binary format".to_string()
}
