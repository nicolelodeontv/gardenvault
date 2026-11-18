use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use rand::{rngs::OsRng, RngCore};
use rusqlite::{config::DbConfig, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::{Cursor, Read, Write}, path::{Path, PathBuf}, process::{Command, Output}, time::{Duration, Instant, UNIX_EPOCH}};
use tauri::{AppHandle, Manager};

const GAME_PACKAGE: &str = "com.playrix.gardenscapes";
const GAME_DATA_DIR: &str = "/data/user/0/com.playrix.gardenscapes/Documents";
const GAME_WAL_FILE: &str = "GameData.db-wal";
const MAX_SAVE_BYTES: usize = 64 * 1024 * 1024;
const MAX_VAULT_BYTES: u64 = (MAX_SAVE_BYTES as u64) * 4 + 2 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: u64 = 20 * 1024 * 1024;
const MAX_ZSTD_WINDOW_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DECOMPRESSOR_HEADROOM_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DECOMPRESSOR_WORKING_SET_BYTES: u64 = 64 * 1024 * 1024;
const SQLITE_QUERY_BUDGET_MS: u64 = 500;
const SQLITE_TIMEOUT_LABEL: &str = "inconclusive (time budget)";
const ZSTD_SKIPPABLE_MAGIC_BASE: u32 = 0x184D_2A50;
const MAX_ZSTD_PROBES: usize = 32;
const ZSTD_MAGIC: &[u8; 4] = b"\x28\xb5\x2f\xfd";
const VAULT_MAGIC: &[u8; 7] = b"GVLT001";

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DeviceInfo { serial: String, game_installed: bool, root_available: bool }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FileInfo { name: String, size_bytes: usize, sha256: String }

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadProfileResult {
    device_serial: String,
    captured_at: String,
    vault_path: String,
    files: Vec<FileInfo>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultListItem { file_name: String, size_bytes: u64, modified_at: u64 }

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultSnapshot {
    schema_version: u32,
    product: String,
    package: String,
    device_serial: String,
    captured_at: String,
    files: Vec<VaultFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VaultFile {
    name: String,
    size_bytes: usize,
    sha256: String,
    content_base64: String,
}

fn adb_executable() -> PathBuf {
    if let Some(explicit) = std::env::var_os("GARDENVAULT_ADB") {
        let path = PathBuf::from(explicit);
        if path.is_file() { return path; }
    }
    #[cfg(windows)]
    {
        let common = PathBuf::from(r"C:\LDPlayer\LDPlayer14\adb.exe");
        if common.is_file() { return common; }
        if let Some(program_files) = std::env::var_os("ProgramFiles") {
            let candidate = PathBuf::from(program_files).join("LDPlayer").join("LDPlayer14").join("adb.exe");
            if candidate.is_file() { return candidate; }
        }
    }
    PathBuf::from("adb")
}

fn run_adb(executable: &Path, args: &[&str]) -> Result<Output, String> {
    Command::new(executable).args(args).output().map_err(|error| {
        format!("Could not start ADB ({}). Set GARDENVAULT_ADB or add ADB to PATH. Details: {error}", executable.display())
    })
}

fn run_adb_for_device(executable: &Path, serial: &str, args: &[&str]) -> Result<Output, String> {
    let mut command_args = vec!["-s", serial];
    command_args.extend_from_slice(args);
    run_adb(executable, &command_args)
}

fn is_allowed_emulator_serial(serial: &str) -> bool {
    if let Some(suffix) = serial.strip_prefix("emulator-") {
        return !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit());
    }
    if let Some(port) = serial.strip_prefix("127.0.0.1:") {
        return !port.is_empty() && port.chars().all(|c| c.is_ascii_digit());
    }
    false
}

fn hash_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_valid_vault_file_name(file_name: &str) -> bool {
    !file_name.is_empty()
        && file_name.len() <= 128
        && file_name.ends_with(".gvault")
        && !file_name.chars().any(|c| c.is_control() || matches!(c, '/' | '\\' | ':'))
        && Path::new(file_name).file_name().and_then(|name| name.to_str()) == Some(file_name)
}

fn app_vault_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let app_data = app.path().app_data_dir()
        .map_err(|e| format!("Could not resolve GardenVault data folder: {e}"))?;
    Ok(app_data.join("vaults"))
}

fn derive_key(passphrase: &str, salt: &[u8; 16]) -> Result<[u8; 32], String> {
    let params = Params::new(32 * 1024, 3, 1, Some(32))
        .map_err(|e| format!("Invalid key-derivation parameters: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; 32];
    argon2.hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Could not derive encryption key: {e}"))?;
    Ok(key)
}

fn encrypt_vault(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    let mut random = OsRng;
    random.fill_bytes(&mut salt);
    random.fill_bytes(&mut nonce);

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "Could not initialize AES-256-GCM".to_string())?;
    let encrypted = cipher.encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| "Could not encrypt the profile snapshot".to_string())?;

    let mut output = Vec::with_capacity(35 + encrypted.len());
    output.extend_from_slice(VAULT_MAGIC);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

#[cfg(test)]
fn decrypt_vault_for_test(passphrase: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() < 35 || &input[..7] != VAULT_MAGIC {
        return Err("Invalid GardenVault file header".to_string());
    }
    let salt: [u8; 16] = input[7..23].try_into().map_err(|_| "Invalid salt".to_string())?;
    let nonce: [u8; 12] = input[23..35].try_into().map_err(|_| "Invalid nonce".to_string())?;
    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "Could not initialize AES-256-GCM".to_string())?;
    cipher.decrypt(Nonce::from_slice(&nonce), &input[35..])
        .map_err(|_| "Authentication failed: wrong password or damaged vault".to_string())
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SqliteWalDiagnostics {
    present: bool,
    size_bytes: usize,
    status: String,
    checksum_validation: String,
    magic_hex: Option<String>,
    page_size_bytes: Option<usize>,
    complete_frames: usize,
    salt_matching_frames: usize,
    trailing_bytes: usize,
    note: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SqliteDiagnostics {
    opened_read_only: bool,
    status: String,
    sqlite_version: Option<String>,
    schema_objects: Vec<String>,
    quick_check: Option<String>,
    wal: Option<SqliteWalDiagnostics>,
    note: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ByteDiagnostics {
    size_bytes: usize,
    sha256: String,
    detected_format: String,
    signature_hex: String,
    entropy_bits_per_byte: f64,
    entropy_assessment: String,
    header_256_entropy_bits_per_byte: f64,
    body_entropy_after_256_bits_per_byte: f64,
    tail_256_entropy_bits_per_byte: f64,
    printable_ascii_percent: f64,
    zero_byte_percent: f64,
    unique_byte_values: usize,
    size_mod_16: usize,
    size_mod_512: usize,
    size_mod_4096: usize,
    tail_hex: String,
    embedded_signatures: Vec<String>,
    sqlite_database: Option<SqliteDiagnostics>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ZstdProbe {
    offset: usize,
    status: String,
    frame_content_size_bytes: Option<u64>,
    compressed_frame_size_bytes: Option<usize>,
    trailing_bytes_after_frame: Option<usize>,
    observed_output_bytes: Option<u64>,
    note: String,
    decoded: Option<ByteDiagnostics>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ZstdSkippableFrame {
    offset: usize,
    magic_hex: String,
    frame_id: u8,
    declared_payload_bytes: usize,
    available_payload_bytes: usize,
    status: String,
    note: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InspectedFile {
    name: String,
    #[serde(flatten)]
    diagnostics: ByteDiagnostics,
    plxe_header_words: Vec<String>,
    plxe_header_decoded_size_matches: Vec<String>,
    zstd_candidates_total: usize,
    zstd_candidates_attempted: usize,
    zstd_candidates_skipped: usize,
    zstd_candidates_overlapping_skipped: usize,
    zstd_skippable_frames: Vec<ZstdSkippableFrame>,
    zstd_probes: Vec<ZstdProbe>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultInspection {
    device_serial: String,
    captured_at: String,
    files: Vec<InspectedFile>,
    identical_files: bool,
}

fn decrypt_vault(passphrase: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() < 35 || input.len() as u64 > MAX_VAULT_BYTES {
        return Err("Invalid or oversized GardenVault file.".to_string());
    }
    if &input[..7] != VAULT_MAGIC {
        return Err("This is not a recognized GardenVault backup.".to_string());
    }
    let salt: [u8; 16] = input[7..23].try_into().map_err(|_| "Invalid vault salt".to_string())?;
    let nonce: [u8; 12] = input[23..35].try_into().map_err(|_| "Invalid vault nonce".to_string())?;
    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "Could not initialize AES-256-GCM".to_string())?;
    cipher.decrypt(Nonce::from_slice(&nonce), &input[35..])
        .map_err(|_| "Authentication failed: wrong passphrase or damaged backup".to_string())
}

fn byte_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() { return 0.0; }
    let mut counts = [0_usize; 256];
    for byte in bytes { counts[*byte as usize] += 1; }
    let length = bytes.len() as f64;
    counts.iter().filter(|count| **count > 0).fold(0.0, |entropy, count| {
        let probability = *count as f64 / length;
        entropy - probability * probability.log2()
    })
}

fn byte_percent(bytes: &[u8], predicate: impl Fn(u8) -> bool) -> f64 {
    if bytes.is_empty() { return 0.0; }
    let matching = bytes.iter().filter(|byte| predicate(**byte)).count();
    (matching as f64 * 100.0) / bytes.len() as f64
}

fn unique_byte_count(bytes: &[u8]) -> usize {
    let mut seen = [false; 256];
    for byte in bytes { seen[*byte as usize] = true; }
    seen.iter().filter(|value| **value).count()
}

fn entropy_assessment(entropy: f64) -> String {
    if entropy >= 7.75 {
        "Very high entropy; encryption or compression are both plausible".to_string()
    } else if entropy >= 6.5 {
        "High entropy; compression, encoding, or encryption are possible".to_string()
    } else {
        "Lower entropy; structured binary data may be present".to_string()
    }
}

fn find_signature_offsets(bytes: &[u8], signature: &[u8]) -> Vec<usize> {
    if signature.is_empty() || bytes.len() < signature.len() {
        return Vec::new();
    }
    bytes.windows(signature.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == signature).then_some(offset))
        .collect()
}

fn find_embedded_signatures(bytes: &[u8]) -> Vec<String> {
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

fn plxe_header_words(bytes: &[u8], plxe_offsets: &[usize], zstd_offsets: &[usize], probes: &[ZstdProbe]) -> Vec<String> {
    let mut words = Vec::new();
    for &plxe_offset in plxe_offsets.iter().take(32) {
        let Some(header_start) = plxe_offset.checked_add(4) else { continue };
        let header_limit = bytes.len().min(plxe_offset.saturating_add(36));
        let payload_start = zstd_offsets.iter().copied().filter(|offset| *offset >= header_start).min();
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
            if value as usize == bytes.len() { matches.push("matches total file size"); }
            if value as usize == remaining_after_field { matches.push("matches bytes after field"); }
            for &zstd_offset in zstd_offsets.iter().filter(|offset| **offset >= header_start).take(8) {
                if value as usize == bytes.len().saturating_sub(zstd_offset) {
                    matches.push("matches bytes from Zstandard candidate to EOF");
                    break;
                }
            }
            if probes.iter().any(|probe| {
                probe.offset >= header_start && probe.compressed_frame_size_bytes == Some(value as usize)
            }) {
                matches.push("matches compressed Zstandard frame length");
            }
            let match_text = if matches.is_empty() { String::new() } else { format!(" ({})", matches.join(", ")) };
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

fn plxe_header_decoded_size_matches(bytes: &[u8], plxe_offsets: &[usize], zstd_offsets: &[usize], probes: &[ZstdProbe]) -> Vec<String> {
    let mut matches = Vec::new();
    let decoded_frames = probes.iter()
        .filter_map(|probe| probe.decoded.as_ref().map(|decoded| (probe.offset, decoded.size_bytes)));
    let decoded_frames = decoded_frames.collect::<Vec<_>>();
    for &plxe_offset in plxe_offsets.iter().take(32) {
        let Some(header_start) = plxe_offset.checked_add(4) else { continue };
        let header_limit = bytes.len().min(plxe_offset.saturating_add(36));
        let payload_start = zstd_offsets.iter().copied().filter(|offset| *offset >= header_start).min();
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

impl SqliteDiagnostics {
    fn with_note(mut self, note: String) -> Self {
        self.note = note;
        self
    }
}

fn inspect_sqlite_wal(wal: Option<&[u8]>) -> SqliteWalDiagnostics {
    let Some(bytes) = wal else {
        return SqliteWalDiagnostics {
            present: false, size_bytes: 0, status: "unvalidated-not-present".to_string(),
            checksum_validation: "unvalidated".to_string(),
            magic_hex: None, page_size_bytes: None, complete_frames: 0,
            salt_matching_frames: 0, trailing_bytes: 0,
            note: "No companion GameData.db-wal file was captured.".to_string(),
        };
    };

    let magic_hex = bytes.get(..4).map(hex::encode);
    if bytes.len() < 32 {
        return SqliteWalDiagnostics {
            present: true, size_bytes: bytes.len(), status: "unvalidated-incomplete-header".to_string(),
            checksum_validation: "unvalidated".to_string(),
            magic_hex, page_size_bytes: None, complete_frames: 0,
            salt_matching_frames: 0, trailing_bytes: bytes.len(),
            note: "WAL file is shorter than its 32-byte header.".to_string(),
        };
    }

    let magic = u32::from_be_bytes(bytes[0..4].try_into().unwrap_or_default());
    let version = u32::from_be_bytes(bytes[4..8].try_into().unwrap_or_default());
    let raw_page_size = u32::from_be_bytes(bytes[8..12].try_into().unwrap_or_default()) as usize;
    let page_size = if raw_page_size == 1 { 65_536 } else { raw_page_size };
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

fn sqlite_query_was_interrupted(error: &rusqlite::Error) -> bool {
    error.to_string().to_ascii_lowercase().contains("interrupt")
}

fn sqlite_query_error_status(error: &rusqlite::Error) -> &'static str {
    if sqlite_query_was_interrupted(error) {
        SQLITE_TIMEOUT_LABEL
    } else {
        "quick-check-error"
    }
}

fn sqlite_diagnostics_failure(status: &str, note: String) -> SqliteDiagnostics {
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

fn inspect_sqlite_readonly(bytes: &[u8]) -> Option<SqliteDiagnostics> {
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
        Err(error) => return Some(sqlite_diagnostics_failure(
            "open-failed",
            format!("Could not create in-memory SQLite connection: {error}"),
        )),
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
    if let Err(error) = connection.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;") {
        return Some(sqlite_diagnostics_failure(
            "readonly-pragmas-failed",
            format!("Could not enable query_only and trusted_schema protections: {error}"),
        ));
    }
    if let Err(error) = connection.deserialize_read_exact(rusqlite::MAIN_DB, Cursor::new(bytes), bytes.len(), true) {
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
    let quick_check_result = connection.query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0));
    let quick_check = quick_check_result.as_ref().ok().cloned();
    if let Err(error) = quick_check_result {
        let timed_out = sqlite_query_was_interrupted(&error);
        return Some(SqliteDiagnostics {
            opened_read_only: true,
            status: sqlite_query_error_status(&error).to_string(),
            sqlite_version,
            schema_objects: Vec::new(),
            quick_check: if timed_out { Some(SQLITE_TIMEOUT_LABEL.to_string()) } else { None },
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

fn find_zstd_skippable_frames(bytes: &[u8]) -> Vec<ZstdSkippableFrame> {
    let mut frames = Vec::new();
    if bytes.len() < 4 {
        return frames;
    }

    let mut offset = 0_usize;
    while offset.saturating_add(4) <= bytes.len() {
        let magic = u32::from_le_bytes([
            bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3],
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
            bytes[offset + 4], bytes[offset + 5], bytes[offset + 6], bytes[offset + 7],
        ]) as usize;
        let available_to_eof = remaining - 8;
        let complete = declared_payload_bytes <= available_to_eof;

        // A skippable frame's payload is opaque. Do not interpret magic-looking
        // bytes inside a complete payload as nested frames. For an incomplete
        // payload, report bytes only up to the next recognizable header so a
        // following truncated frame is not accidentally counted as payload.
        let next_header = (offset + 8..=bytes.len().saturating_sub(4)).find(|candidate| {
            let candidate_magic = u32::from_le_bytes([
                bytes[*candidate], bytes[*candidate + 1], bytes[*candidate + 2], bytes[*candidate + 3],
            ]);
            (ZSTD_SKIPPABLE_MAGIC_BASE..=ZSTD_SKIPPABLE_MAGIC_BASE + 15).contains(&candidate_magic)
        });
        let available_payload_bytes = if complete {
            declared_payload_bytes
        } else {
            next_header.map(|next| next - (offset + 8)).unwrap_or(available_to_eof)
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
            offset = offset.saturating_add(8).saturating_add(declared_payload_bytes);
        } else if let Some(next) = next_header {
            offset = next;
        } else {
            break;
        }
    }
    frames
}

fn byte_diagnostics(bytes: &[u8]) -> ByteDiagnostics {
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

fn zstd_frame_size_error_status(error_code: usize) -> (&'static str, String) {
    let message = zstd_safe::get_error_name(error_code);
    let lower = message.to_ascii_lowercase();
    if lower.contains("src size is incorrect") || lower.contains("source size is incorrect") {
        ("incomplete", format!("Zstandard signature is present, but the frame is truncated or incomplete: {message}"))
    } else {
        ("signature-only", format!("Zstandard magic is present, but the bytes do not form a valid frame: {message}"))
    }
}

fn is_zstd_limit_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("too much memory")
        || lower.contains("window size")
        || lower.contains("window is too large")
        || lower.contains("memory limit")
        || lower.contains("maximum window")
}

fn zstd_declared_window_size(payload: &[u8]) -> Option<u64> {
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

fn probe_zstd_frame(bytes: &[u8], offset: usize, remaining_budget: u64) -> ZstdProbe {
    let Some(payload) = bytes.get(offset..) else {
        return ZstdProbe {
            offset, status: "signature-only".to_string(), frame_content_size_bytes: None,
            compressed_frame_size_bytes: None, trailing_bytes_after_frame: None,
            observed_output_bytes: None, note: "Candidate offset is outside the file.".to_string(), decoded: None,
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
                offset, status: status.to_string(), frame_content_size_bytes: declared_size,
                compressed_frame_size_bytes: None, trailing_bytes_after_frame: None,
                observed_output_bytes: None, note, decoded: None,
            };
        }
    };

    if frame_size == 0 || frame_size > payload.len() {
        return ZstdProbe {
            offset, status: "signature-only".to_string(), frame_content_size_bytes: declared_size,
            compressed_frame_size_bytes: None, trailing_bytes_after_frame: None,
            observed_output_bytes: None,
            note: "Zstandard magic was found, but the reported frame boundary is invalid.".to_string(),
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
            offset, status: "limit-hit".to_string(), frame_content_size_bytes: declared_size,
            compressed_frame_size_bytes: Some(frame_size),
            trailing_bytes_after_frame: Some(payload.len() - frame_size),
            observed_output_bytes: None,
            note: format!("Declared output exceeds the remaining {} MiB per-file output budget.", output_limit / (1024 * 1024)),
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
                    offset, status: status.to_string(), frame_content_size_bytes: declared_size,
                    compressed_frame_size_bytes: Some(frame_size),
                    trailing_bytes_after_frame: Some(payload.len() - frame_size),
                    observed_output_bytes: Some(observed), note, decoded: None,
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
        offset, status: status.to_string(), frame_content_size_bytes: declared_size,
        compressed_frame_size_bytes: Some(frame_size),
        trailing_bytes_after_frame: Some(payload.len() - frame_size),
        observed_output_bytes: Some(decoded_size), note,
        decoded: Some(byte_diagnostics(&output)),
    }
}

fn inspect_bytes(bytes: &[u8]) -> (ByteDiagnostics, Vec<String>, Vec<String>, usize, usize, usize, Vec<ZstdProbe>) {
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
        } else if probe.status == "limit-hit" && probe.observed_output_bytes.is_some_and(|size| size > remaining_budget) {
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
    let decoded_size_matches = plxe_header_decoded_size_matches(bytes, &plxe_offsets, &zstd_offsets, &probes);
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

fn detect_file_format(bytes: &[u8]) -> String {
    if bytes.starts_with(b"SQLite format 3\0") { return "SQLite 3 database".to_string(); }
    if bytes.starts_with(b"PK\x03\x04") { return "ZIP archive".to_string(); }
    if bytes.starts_with(&[0x1f, 0x8b]) { return "GZIP compressed data".to_string(); }
    if bytes.starts_with(b"bplist00") { return "Apple binary property list".to_string(); }
    let first_non_whitespace = bytes.iter().copied().find(|byte| !byte.is_ascii_whitespace());
    if matches!(first_non_whitespace, Some(b'{' | b'[')) {
        return "JSON-like text (not parsed)".to_string();
    }
    if first_non_whitespace == Some(b'<') { return "XML-like text".to_string(); }
    if bytes.starts_with(b"UnityFS") { return "UnityFS asset bundle".to_string(); }
    if bytes.starts_with(ZSTD_MAGIC) { return "Zstandard frame".to_string(); }
    if bytes.starts_with(b"PLXE") { return "Playrix PLXE container (payload not decoded)".to_string(); }
    if bytes.starts_with(b"ENC") { return "Unknown binary (ENC prefix)".to_string(); }
    "Unknown binary format".to_string()
}

fn list_devices_inner() -> Result<Vec<DeviceInfo>, String> {
    let adb = adb_executable();
    let output = run_adb(&adb, &["devices"])?;
    if !output.status.success() {
        return Err(format!("ADB device discovery failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }

    let mut devices = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines().skip(1) {
        let mut fields = line.split_whitespace();
        let Some(serial) = fields.next() else { continue };
        let state = fields.next().unwrap_or_default();
        if state != "device" || !is_allowed_emulator_serial(serial) { continue; }

        let package = run_adb_for_device(&adb, serial, &["shell", "pm", "path", GAME_PACKAGE]);
        let game_installed = package.as_ref().map(|r| r.status.success() && String::from_utf8_lossy(&r.stdout).contains("package:")).unwrap_or(false);
        let root = run_adb_for_device(&adb, serial, &["shell", "su", "-c", "id"]);
        let root_available = root.as_ref().map(|r| r.status.success() && String::from_utf8_lossy(&r.stdout).contains("uid=0")).unwrap_or(false);

        devices.push(DeviceInfo { serial: serial.to_string(), game_installed, root_available });
    }
    Ok(devices)
}

#[tauri::command]
fn list_devices() -> Result<Vec<DeviceInfo>, String> {
    list_devices_inner()
}

fn root_cat_command(file_name: &str) -> Result<String, String> {
    if !matches!(file_name, "GameData.db" | "GameData.db.bak" | "GameData.db-wal") {
        return Err("Unsupported Gardenscapes save file.".to_string());
    }
    let remote_path = format!("{GAME_DATA_DIR}/{file_name}");
    // Keep the whole command as one quoted argument to su -c. Without these
    // quotes, some LDPlayer adb/su combinations parse the path as a target UID.
    Ok(format!("su -c 'cat {remote_path}'"))
}

fn root_test_file_command(file_name: &str) -> Result<String, String> {
    if file_name != GAME_WAL_FILE {
        return Err("Unsupported optional Gardenscapes companion file.".to_string());
    }
    let remote_path = format!("{GAME_DATA_DIR}/{file_name}");
    Ok(format!("su -c 'test -f {remote_path}'"))
}

fn remote_file_exists(adb: &Path, serial: &str, file_name: &str) -> Result<bool, String> {
    let command = root_test_file_command(file_name)?;
    let output = run_adb_for_device(adb, serial, &["exec-out", &command])?;
    Ok(output.status.success())
}

fn verify_main_capture_unchanged(before: &[u8], after: &[u8]) -> Result<(), String> {
    if hash_hex(before) == hash_hex(after) {
        Ok(())
    } else {
        Err("GameData.db changed while its companion WAL was being captured.".to_string())
    }
}

fn verify_wal_capture_unchanged(before: &[u8], captured: &[u8], after: &[u8]) -> Result<(), String> {
    let before_hash = hash_hex(before);
    let captured_hash = hash_hex(captured);
    let after_hash = hash_hex(after);
    if before_hash == captured_hash && captured_hash == after_hash {
        Ok(())
    } else {
        Err("GameData.db-wal changed across its capture read.".to_string())
    }
}

fn capture_file(adb: &Path, serial: &str, file_name: &str) -> Result<Vec<u8>, String> {
    let command = root_cat_command(file_name)?;
    // exec-out avoids a PTY so bytes are captured without terminal conversion.
    let output = run_adb_for_device(adb, serial, &["exec-out", &command])?;
    if !output.status.success() {
        return Err(format!("Could not read {file_name}: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    let bytes = output.stdout;
    if bytes.is_empty() { return Err(format!("{file_name} was empty or inaccessible.")); }
    if bytes.len() > MAX_SAVE_BYTES {
        return Err(format!("{file_name} exceeds the {} MiB safety limit.", MAX_SAVE_BYTES / (1024 * 1024)));
    }
    Ok(bytes)
}

#[tauri::command]
fn list_vaults(app: AppHandle) -> Result<Vec<VaultListItem>, String> {
    let vault_dir = app_vault_dir(&app)?;
    fs::create_dir_all(&vault_dir)
        .map_err(|e| format!("Could not open the encrypted backup folder: {e}"))?;

    let entries = fs::read_dir(&vault_dir)
        .map_err(|e| format!("Could not list encrypted backups: {e}"))?;
    let mut vaults = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|e| format!("Could not read backup entry: {e}"))?;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if !is_valid_vault_file_name(&file_name) {
            continue;
        }
        let file_type = entry.file_type()
            .map_err(|e| format!("Could not inspect backup file: {e}"))?;
        if !file_type.is_file() {
            continue;
        }
        let metadata = entry.metadata()
            .map_err(|e| format!("Could not inspect backup metadata: {e}"))?;
        if metadata.len() < 35 || metadata.len() > MAX_VAULT_BYTES {
            continue;
        }
        let modified_at = metadata.modified().ok()
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or_default();

        vaults.push(VaultListItem {
            file_name,
            size_bytes: metadata.len(),
            modified_at,
        });
    }

    vaults.sort_by(|a, b| b.modified_at.cmp(&a.modified_at));
    Ok(vaults)
}

#[tauri::command]
fn export_vault(app: AppHandle, file_name: String) -> Result<Option<String>, String> {
    if !is_valid_vault_file_name(&file_name) {
        return Err("Invalid backup file name.".to_string());
    }

    let source = app_vault_dir(&app)?.join(&file_name);
    let metadata = fs::symlink_metadata(&source)
        .map_err(|e| format!("Could not open the selected backup: {e}"))?;
    if !metadata.file_type().is_file() || metadata.len() < 35 || metadata.len() > MAX_VAULT_BYTES {
        return Err("The selected backup is not a valid-sized regular vault file.".to_string());
    }

    let mut header = [0_u8; 7];
    File::open(&source)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|e| format!("Could not verify the backup header: {e}"))?;
    if &header != VAULT_MAGIC {
        return Err("The selected file is not a recognized GardenVault backup.".to_string());
    }

    #[cfg(windows)]
    {
        let target = rfd::FileDialog::new()
            .set_title("Export encrypted GardenVault backup")
            .set_file_name(&file_name)
            .add_filter("GardenVault encrypted backup", &["gvault"])
            .save_file();
        let Some(target) = target else {
            return Ok(None);
        };
        let extension = target.extension().and_then(|value| value.to_str())
            .unwrap_or_default().to_ascii_lowercase();
        if extension != "gvault" {
            return Err("Choose a destination with the .gvault extension.".to_string());
        }
        if target != source {
            fs::copy(&source, &target)
                .map_err(|e| format!("Could not export encrypted backup: {e}"))?;
        }
        Ok(Some(target.display().to_string()))
    }

    #[cfg(not(windows))]
    {
        let _ = source;
        Err("Encrypted backup export is currently supported in the Windows build.".to_string())
    }
}

#[tauri::command]
fn inspect_vault(app: AppHandle, file_name: String, passphrase: String) -> Result<VaultInspection, String> {
    if !is_valid_vault_file_name(&file_name) {
        return Err("Invalid backup file name.".to_string());
    }
    if passphrase.chars().count() < 12 || passphrase.len() > 256 {
        return Err("Enter the original vault passphrase (at least 12 characters).".to_string());
    }
    let source = app_vault_dir(&app)?.join(&file_name);
    let metadata = fs::symlink_metadata(&source)
        .map_err(|e| format!("Could not open the selected backup: {e}"))?;
    if !metadata.file_type().is_file() || metadata.len() < 35 || metadata.len() > MAX_VAULT_BYTES {
        return Err("The selected backup is not a valid-sized regular vault file.".to_string());
    }
    let mut encrypted = Vec::with_capacity(metadata.len() as usize);
    File::open(&source).and_then(|mut file| file.read_to_end(&mut encrypted))
        .map_err(|e| format!("Could not read encrypted backup: {e}"))?;
    let plaintext = decrypt_vault(&passphrase, &encrypted)?;
    let snapshot: VaultSnapshot = serde_json::from_slice(&plaintext)
        .map_err(|_| "Decrypted backup has an unsupported snapshot structure.".to_string())?;
    if snapshot.product != "GardenVault" || snapshot.package != GAME_PACKAGE || snapshot.schema_version != 1 {
        return Err("Snapshot metadata is not a supported Gardenscapes capture.".to_string());
    }
    let mut decoded_files = Vec::new();
    for file in snapshot.files {
        if !matches!(file.name.as_str(), "GameData.db" | "GameData.db.bak" | "GameData.db-wal") {
            return Err("Snapshot contains an unexpected file entry.".to_string());
        }
        let bytes = BASE64.decode(&file.content_base64)
            .map_err(|_| "Snapshot contains invalid encoded file data.".to_string())?;
        if bytes.len() != file.size_bytes || hash_hex(&bytes) != file.sha256 {
            return Err(format!("Integrity check failed for {}.", file.name));
        }
        decoded_files.push((file.name, bytes));
    }

    let wal_diagnostics = decoded_files.iter()
        .find(|(name, _)| name == GAME_WAL_FILE)
        .map(|(_, bytes)| inspect_sqlite_wal(Some(bytes)))
        .unwrap_or_else(|| inspect_sqlite_wal(None));
    let mut inspected = Vec::new();
    for (name, bytes) in decoded_files {
        let (mut diagnostics, header_words, decoded_size_matches, zstd_candidates_attempted, zstd_candidates_skipped, zstd_candidates_overlapping_skipped, mut zstd_probes) = inspect_bytes(&bytes);
        if name == "GameData.db" {
            if let Some(sqlite) = diagnostics.sqlite_database.as_mut() {
                sqlite.wal = Some(wal_diagnostics.clone());
                sqlite.note.push_str(if wal_diagnostics.present {
                    " A companion GameData.db-wal was captured and checked separately; its pages were not replayed."
                } else {
                    " No companion GameData.db-wal file was present at capture time."
                });
                for probe in &mut zstd_probes {
                    if let Some(decoded_sqlite) = probe.decoded.as_mut().and_then(|decoded| decoded.sqlite_database.as_mut()) {
                        decoded_sqlite.wal = Some(wal_diagnostics.clone());
                        decoded_sqlite.note.push_str(if wal_diagnostics.present {
                            " A companion WAL was captured and checked separately; its pages were not replayed."
                        } else {
                            " No companion WAL was present in this snapshot."
                        });
                    }
                }
            }
        }
        inspected.push(InspectedFile {
            name,
            diagnostics,
            plxe_header_words: header_words,
            plxe_header_decoded_size_matches: decoded_size_matches,
            zstd_candidates_total: find_signature_offsets(&bytes, ZSTD_MAGIC).len(),
            zstd_candidates_attempted,
            zstd_candidates_skipped,
            zstd_candidates_overlapping_skipped,
            zstd_skippable_frames: find_zstd_skippable_frames(&bytes),
            zstd_probes,
        });
    }
    if inspected.is_empty() {
        return Err("Snapshot contains no save files.".to_string());
    }
    let identical_files = inspected.len() > 1 && inspected.iter().all(|f| f.diagnostics.sha256 == inspected[0].diagnostics.sha256);
    Ok(VaultInspection {
        device_serial: snapshot.device_serial,
        captured_at: snapshot.captured_at,
        files: inspected,
        identical_files,
    })
}

#[tauri::command]
fn read_profile(app: AppHandle, serial: String, passphrase: String) -> Result<ReadProfileResult, String> {
    if !is_allowed_emulator_serial(&serial) {
        return Err("Unsupported device identifier. Choose a connected LDPlayer emulator.".to_string());
    }
    if passphrase.chars().count() < 12 || passphrase.len() > 256 {
        return Err("Use a vault passphrase of at least 12 characters (maximum 256 bytes).".to_string());
    }

    let devices = list_devices_inner()?;
    let device = devices.iter().find(|d| d.serial == serial)
        .ok_or_else(|| "The selected emulator is no longer connected. Refresh the device list.".to_string())?;
    if !device.game_installed { return Err("Gardenscapes is not installed on the selected emulator.".to_string()); }
    if !device.root_available { return Err("Root access is unavailable. Enable LDPlayer root access and try again.".to_string()); }

    let adb = adb_executable();
    let process = run_adb_for_device(&adb, &serial, &["shell", "pidof", GAME_PACKAGE])?;
    if !String::from_utf8_lossy(&process.stdout).trim().is_empty() {
        return Err("Gardenscapes is still running. Close the game completely, wait for its save to finish, then retry.".to_string());
    }

    let captured_at = Utc::now().to_rfc3339();
    let mut file_infos = Vec::new();
    let mut vault_files = Vec::new();

    let main_bytes = capture_file(&adb, &serial, "GameData.db")?;
    let main_digest = hash_hex(&main_bytes);
    file_infos.push(FileInfo { name: "GameData.db".to_string(), size_bytes: main_bytes.len(), sha256: main_digest.clone() });
    vault_files.push(VaultFile {
        name: "GameData.db".to_string(),
        size_bytes: main_bytes.len(),
        sha256: main_digest.clone(),
        content_base64: BASE64.encode(&main_bytes),
    });

    let backup_bytes = capture_file(&adb, &serial, "GameData.db.bak")?;
    let backup_digest = hash_hex(&backup_bytes);
    file_infos.push(FileInfo { name: "GameData.db.bak".to_string(), size_bytes: backup_bytes.len(), sha256: backup_digest.clone() });
    vault_files.push(VaultFile {
        name: "GameData.db.bak".to_string(),
        size_bytes: backup_bytes.len(),
        sha256: backup_digest,
        content_base64: BASE64.encode(&backup_bytes),
    });

    if remote_file_exists(&adb, &serial, GAME_WAL_FILE)? {
        // Verify the main file immediately before and after fetching its WAL.
        // If it changed, reject the mixed capture instead of saving a torn pair.
        let main_before_wal = capture_file(&adb, &serial, "GameData.db")?;
        verify_main_capture_unchanged(&main_bytes, &main_before_wal).map_err(|_| {
            "Capture consistency check failed: GameData.db changed before WAL capture. Keep Gardenscapes closed and retry.".to_string()
        })?;

        // Read the WAL immediately before and after the selected snapshot too.
        // The three hashes must agree so a WAL write during its own read is rejected.
        let wal_before_read = capture_file(&adb, &serial, GAME_WAL_FILE)?;
        let wal_bytes = capture_file(&adb, &serial, GAME_WAL_FILE)?;
        let wal_after_read = capture_file(&adb, &serial, GAME_WAL_FILE)?;
        verify_wal_capture_unchanged(&wal_before_read, &wal_bytes, &wal_after_read).map_err(|_| {
            "Capture consistency check failed: GameData.db-wal changed during its read. No snapshot was saved; keep Gardenscapes closed and retry.".to_string()
        })?;
        let wal_digest = hash_hex(&wal_bytes);

        let main_after_wal = capture_file(&adb, &serial, "GameData.db")?;
        verify_main_capture_unchanged(&main_before_wal, &main_after_wal).map_err(|_| {
            "Capture consistency check failed: GameData.db changed while GameData.db-wal was being captured. No snapshot was saved; keep Gardenscapes closed and retry.".to_string()
        })?;

        file_infos.push(FileInfo { name: GAME_WAL_FILE.to_string(), size_bytes: wal_bytes.len(), sha256: wal_digest.clone() });
        vault_files.push(VaultFile {
            name: GAME_WAL_FILE.to_string(),
            size_bytes: wal_bytes.len(),
            sha256: wal_digest,
            content_base64: BASE64.encode(&wal_bytes),
        });
    }

    let process_after = run_adb_for_device(&adb, &serial, &["shell", "pidof", GAME_PACKAGE])?;
    if !String::from_utf8_lossy(&process_after.stdout).trim().is_empty() {
        return Err("Gardenscapes started during backup capture. No snapshot was saved; close the game and retry.".to_string());
    }

    let payload = VaultSnapshot {
        schema_version: 1,
        product: "GardenVault".to_string(),
        package: GAME_PACKAGE.to_string(),
        device_serial: serial.clone(),
        captured_at: captured_at.clone(),
        files: vault_files,
    };
    let plaintext = serde_json::to_vec(&payload).map_err(|e| format!("Could not prepare encrypted snapshot: {e}"))?;
    let encrypted = encrypt_vault(&passphrase, &plaintext)?;

    let vault_dir = app_vault_dir(&app)?;
    fs::create_dir_all(&vault_dir).map_err(|e| format!("Could not create encrypted backup folder: {e}"))?;
    let stamp = Utc::now().format("%Y%m%d-%H%M%S-%3f");
    let file_name = format!("gardenscapes-{stamp}.gvault");
    let vault_path = vault_dir.join(&file_name);
    let temporary_path = vault_dir.join(format!("{file_name}.tmp"));

    let mut output = OpenOptions::new().write(true).create_new(true).open(&temporary_path)
        .map_err(|e| format!("Could not create temporary vault file: {e}"))?;
    output.write_all(&encrypted).and_then(|_| output.sync_all())
        .map_err(|e| format!("Could not write encrypted vault: {e}"))?;
    drop(output);
    fs::rename(&temporary_path, &vault_path)
        .map_err(|e| format!("Could not finalize encrypted vault: {e}"))?;

    Ok(ReadProfileResult {
        device_serial: serial,
        captured_at,
        vault_path: vault_path.display().to_string(),
        files: file_infos,
    })
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![list_devices, list_vaults, export_vault, inspect_vault, read_profile])
        .run(tauri::generate_context!())
        .expect("error while running GardenVault");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewrite_zstd_content_size(frame: &mut Vec<u8>, desired_size: u32) {
        assert!(frame.len() >= 6);
        let descriptor = frame[4];
        let single_segment = descriptor & 0x20 != 0;
        let old_flag = descriptor >> 6;
        let old_fcs_len = match old_flag {
            0 if single_segment => 1,
            0 => 0,
            1 => 2,
            2 => 4,
            _ => 8,
        };
        let dict_len = match descriptor & 0x03 {
            0 => 0,
            1 => 1,
            2 => 2,
            _ => 4,
        };
        let fcs_offset = 5 + (if single_segment { 0 } else { 1 }) + dict_len;
        frame.splice(fcs_offset..fcs_offset + old_fcs_len, desired_size.to_le_bytes());
        frame[4] = (descriptor & 0x3f) | 0x80;
    }

    fn make_windowed_zstd_frame(window_log: u32, payload: &[u8]) -> Vec<u8> {
        let mut encoder = zstd::stream::Encoder::new(Vec::new(), 1).expect("create streaming encoder");
        encoder.window_log(window_log).expect("set encoder window");
        encoder.write_all(payload).expect("write streaming payload");
        encoder.finish().expect("finish streaming frame")
    }

    fn seeded_bytes(length: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..length).map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        }).collect()
    }

    #[test]
    fn nominal_per_frame_memory_budget_includes_overlapping_sqlite_copy_and_decoder_headroom() {
        // The decoded output Vec and SQLite's read-only deserialize copy coexist.
        // Snapshot/encrypted/plaintext/decoded source buffers and process overhead
        // are additional resident memory and are not covered by this calculation.
        let peak_components = (MAX_DECOMPRESSED_BYTES * 2)
            + MAX_ZSTD_WINDOW_BYTES
            + MAX_DECOMPRESSOR_HEADROOM_BYTES;
        assert!(peak_components <= MAX_DECOMPRESSOR_WORKING_SET_BYTES);
        assert_eq!(peak_components, MAX_DECOMPRESSOR_WORKING_SET_BYTES);
        assert!(MAX_DECOMPRESSED_BYTES < 64 * 1024 * 1024);
    }

    #[test]
    fn main_capture_hash_guard_accepts_stable_bytes_and_rejects_changed_bytes() {
        let before = b"stable database image";
        assert!(verify_main_capture_unchanged(before, before).is_ok());
        assert!(verify_main_capture_unchanged(before, b"changed database image").is_err());
    }

    #[test]
    fn wal_capture_hash_guard_rejects_changes_before_or_after_selected_read() {
        let stable = b"stable WAL image";
        assert!(verify_wal_capture_unchanged(stable, stable, stable).is_ok());
        assert!(verify_wal_capture_unchanged(b"older WAL", stable, stable).is_err());
        assert!(verify_wal_capture_unchanged(stable, stable, b"newer WAL").is_err());
    }

    #[test]
    fn zstd_skippable_frame_magic_range_is_reported_separately() {
        let mut bytes = b"prefix".to_vec();
        let complete_offset = bytes.len();
        bytes.extend_from_slice(&0x184D_2A50_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(b"meta");
        let incomplete_offset = bytes.len();
        bytes.extend_from_slice(&0x184D_2A5F_u32.to_le_bytes());
        bytes.extend_from_slice(&32_u32.to_le_bytes());
        bytes.extend_from_slice(b"xy");
        let header_only_offset = bytes.len();
        bytes.extend_from_slice(&0x184D_2A51_u32.to_le_bytes());

        let frames = find_zstd_skippable_frames(&bytes);
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].offset, complete_offset);
        assert_eq!(frames[0].frame_id, 0);
        assert_eq!(frames[0].declared_payload_bytes, 3);
        assert_eq!(frames[0].status, "unvalidated-complete-skippable-frame");
        assert_eq!(frames[1].offset, incomplete_offset);
        assert_eq!(frames[1].frame_id, 15);
        assert_eq!(frames[1].available_payload_bytes, 2);
        assert_eq!(frames[1].status, "incomplete-skippable-frame");
        assert_eq!(frames[2].offset, header_only_offset);
        assert_eq!(frames[2].status, "incomplete-skippable-header");
        assert!(find_signature_offsets(&bytes, ZSTD_MAGIC).is_empty());
    }

    #[test]
    fn accepts_ldplayer_emulator_serials() {
        assert!(is_allowed_emulator_serial("emulator-5556"));
        assert!(is_allowed_emulator_serial("127.0.0.1:5555"));
    }

    #[test]
    fn rejects_untrusted_or_injected_serials() {
        assert!(!is_allowed_emulator_serial("emulator-5556;whoami"));
        assert!(!is_allowed_emulator_serial("phone-1234"));
        assert!(!is_allowed_emulator_serial("../../adb"));
    }

    #[test]
    fn root_cat_command_quotes_the_complete_su_command() {
        assert_eq!(
            root_cat_command("GameData.db").expect("allowed save file"),
            "su -c 'cat /data/user/0/com.playrix.gardenscapes/Documents/GameData.db'"
        );
        assert_eq!(
            root_cat_command("GameData.db.bak").expect("allowed backup file"),
            "su -c 'cat /data/user/0/com.playrix.gardenscapes/Documents/GameData.db.bak'"
        );
        assert!(root_cat_command("../other.db").is_err());
        assert!(root_cat_command("GameData.db; id").is_err());
        assert_eq!(root_cat_command("GameData.db-wal").expect("WAL allowlisted"), "su -c 'cat /data/user/0/com.playrix.gardenscapes/Documents/GameData.db-wal'");
        assert_eq!(root_test_file_command("GameData.db-wal").expect("WAL test allowlisted"), "su -c 'test -f /data/user/0/com.playrix.gardenscapes/Documents/GameData.db-wal'");
        assert!(root_test_file_command("GameData.db.bak").is_err());
    }

    #[test]
    fn vault_file_names_reject_paths_and_unexpected_extensions() {
        assert!(is_valid_vault_file_name("gardenscapes-20261118-120000.gvault"));
        assert!(!is_valid_vault_file_name("../outside.gvault"));
        assert!(!is_valid_vault_file_name("C:\\outside.gvault"));
        assert!(!is_valid_vault_file_name("backup.txt"));
        assert!(!is_valid_vault_file_name("bad\\nname.gvault"));
    }

    #[test]
    fn file_signature_detection_is_read_only_and_conservative() {
        assert_eq!(detect_file_format(b"SQLite format 3\0rest"), "SQLite 3 database");
        assert_eq!(detect_file_format(b"PK\x03\x04archive"), "ZIP archive");
        assert_eq!(detect_file_format(b"not a known header"), "Unknown binary format");
        assert_eq!(detect_file_format(b"PLXE\x04\x00\x00\x00"), "Playrix PLXE container (payload not decoded)");
        assert!(find_embedded_signatures(b"prefixPLXEpayload").iter().any(|s| s.contains("PLXE")));
        assert_eq!(byte_entropy(&[0_u8; 32]), 0.0);
        let all_values = (0_u8..=255).collect::<Vec<_>>();
        assert!((byte_entropy(&all_values) - 8.0).abs() < 0.0001);
        assert_eq!(unique_byte_count(&all_values), 256);
        assert!(find_embedded_signatures(b"prefix\x28\xb5\x2f\xfdpayload").iter().any(|s| s.contains("Zstandard")));
        assert!(entropy_assessment(7.99).contains("encryption or compression"));
    }

    #[test]
    fn signature_scan_finds_every_strong_hit_through_the_tail() {
        let mut bytes = vec![0_u8; 70 * 1024];
        bytes[12..16].copy_from_slice(b"PLXE");
        bytes[64 * 1024 + 9..64 * 1024 + 13].copy_from_slice(ZSTD_MAGIC);
        bytes[70 * 1024 - 8..70 * 1024 - 4].copy_from_slice(b"PLXE");
        assert_eq!(find_signature_offsets(&bytes, b"PLXE"), vec![12, 70 * 1024 - 8]);
        assert_eq!(find_signature_offsets(&bytes, ZSTD_MAGIC), vec![64 * 1024 + 9]);
        let diagnostics = byte_diagnostics(&bytes);
        assert_eq!(diagnostics.size_mod_16, bytes.len() % 16);
        assert_eq!(diagnostics.size_mod_512, bytes.len() % 512);
        assert_eq!(diagnostics.size_mod_4096, bytes.len() % 4096);
        assert_eq!(diagnostics.tail_hex.len(), 64);
        assert!(diagnostics.embedded_signatures.iter().any(|hit| hit.contains("0xC")));
        assert!(diagnostics.embedded_signatures.iter().any(|hit| hit.contains("0x117F8")));
    }

    #[test]
    fn zstd_probe_decodes_one_frame_and_ignores_trailing_data() {
        let original = b"SQLite format 3\0GardenVault test payload";
        let compressed = zstd::stream::encode_all(Cursor::new(original), 1).expect("encode zstd test frame");
        let mut bytes = b"prefixPLXE".to_vec();
        let frame_offset = bytes.len();
        bytes.extend_from_slice(&compressed);
        bytes.extend_from_slice(b"trailing-footer");
        let probe = probe_zstd_frame(&bytes, frame_offset, MAX_DECOMPRESSED_BYTES);
        assert_eq!(probe.status, "decoded-size-matches");
        assert_eq!(probe.frame_content_size_bytes, Some(original.len() as u64));
        assert_eq!(probe.compressed_frame_size_bytes, Some(compressed.len()));
        assert_eq!(probe.trailing_bytes_after_frame, Some(b"trailing-footer".len()));
        let decoded = probe.decoded.expect("decoded file diagnostics");
        assert_eq!(decoded.detected_format, "SQLite 3 database");
        assert_eq!(decoded.sha256, hash_hex(original));
    }

    #[test]
    fn all_zstd_candidates_are_attempted_and_plxe_lengths_are_compared() {
        let first = zstd::stream::encode_all(Cursor::new(b"first decoded payload"), 1).expect("first frame");
        let second = zstd::stream::encode_all(Cursor::new(b"second decoded payload"), 1).expect("second frame");
        let mut bytes = b"PLXE\0\0\0\0".to_vec();
        let first_offset = bytes.len();
        bytes.extend_from_slice(&first);
        bytes.extend_from_slice(b"separator");
        let second_offset = bytes.len();
        bytes.extend_from_slice(&second);
        bytes[4..8].copy_from_slice(&(first.len() as u32).to_le_bytes());

        let (_, header_words, _decoded_size_matches, _attempted, skipped, _overlapping, probes) = inspect_bytes(&bytes);
        assert_eq!(find_signature_offsets(&bytes, ZSTD_MAGIC), vec![first_offset, second_offset]);
        assert_eq!(probes.len(), 2);
        assert_eq!(skipped, 0);
        assert!(probes.iter().all(|probe| probe.status == "decoded-size-matches"));
        assert!(header_words.iter().any(|word| word.contains("matches compressed Zstandard frame length")));
    }

    #[test]
    fn plxe_word_can_match_the_decompressed_zstd_size() {
        let original = b"decoded payload with a known length";
        let compressed = zstd::stream::encode_all(Cursor::new(original), 1).expect("encode frame");
        let mut bytes = b"PLXE\0\0\0\0\0\0\0\0".to_vec();
        let frame_offset = bytes.len();
        bytes.extend_from_slice(&compressed);
        bytes[4..8].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
        bytes[8..12].copy_from_slice(&(original.len() as u32).to_le_bytes());
        bytes.extend_from_slice(b"footer!");

        let (_, header_words, decoded_matches, _attempted, skipped, _overlapping, probes) = inspect_bytes(&bytes);
        assert_eq!(skipped, 0);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].offset, frame_offset);
        assert_eq!(probes[0].status, "decoded-size-matches");
        assert!(header_words.iter().any(|word| word.contains("matches compressed Zstandard frame length")));
        assert_eq!(
            probes[0].decoded.as_ref().map(|decoded| decoded.size_bytes),
            Some(original.len()),
            "successful frame diagnostics should retain the actual decoded byte count"
        );
        assert!(
            decoded_matches.iter().any(|word| word.contains("+0x08 equals decoded size")),
            "decoded-size field comparison missing; header_words={header_words:?}, decoded_matches={decoded_matches:?}, decoded={:?}",
            probes[0].decoded.as_ref().map(|decoded| decoded.size_bytes)
        );
    }

    #[test]
    fn false_positive_zstd_magic_is_signature_only() {
        let mut bytes = ZSTD_MAGIC.to_vec();
        bytes.extend_from_slice(b"not a zstandard frame: arbitrary garbage");
        let probe = probe_zstd_frame(&bytes, 0, MAX_DECOMPRESSED_BYTES);
        assert_eq!(probe.status, "signature-only");
        assert!(probe.decoded.is_none());
        assert!(probe.observed_output_bytes.is_none());
    }

    #[test]
    fn truncated_zstd_frame_is_incomplete_and_never_returns_partial_output() {
        let original = seeded_bytes(32 * 1024, 0x1234_5678);
        let frame = zstd::stream::encode_all(Cursor::new(&original), 1).expect("encode frame");
        let truncated = &frame[..frame.len() - 1];
        let probe = probe_zstd_frame(truncated, 0, MAX_DECOMPRESSED_BYTES);
        assert_eq!(probe.status, "incomplete");
        assert!(probe.decoded.is_none());
    }

    #[test]
    fn declared_content_size_mismatches_are_reported_without_exposing_partial_output() {
        let small_actual = seeded_bytes(2 * 1024, 0xabc1);
        let mut small_frame = zstd::stream::encode_all(Cursor::new(&small_actual), 1).expect("encode small frame");
        rewrite_zstd_content_size(&mut small_frame, 1024 * 1024);
        let small_probe = probe_zstd_frame(&small_frame, 0, MAX_DECOMPRESSED_BYTES);
        assert_eq!(small_probe.frame_content_size_bytes, Some(1024 * 1024));
        assert_eq!(small_probe.status, "decoded-size-mismatch");
        assert!(small_probe.decoded.is_none());

        let large_actual = seeded_bytes(1024 * 1024, 0xabc2);
        let mut large_frame = zstd::stream::encode_all(Cursor::new(&large_actual), 1).expect("encode large frame");
        rewrite_zstd_content_size(&mut large_frame, 2 * 1024);
        let large_probe = probe_zstd_frame(&large_frame, 0, MAX_DECOMPRESSED_BYTES);
        assert_eq!(large_probe.frame_content_size_bytes, Some(2 * 1024));
        assert_eq!(large_probe.status, "decoded-size-mismatch");
        assert!(large_probe.decoded.is_none());
    }

    #[test]
    fn declared_output_over_limit_is_a_limit_hit_not_a_decode_failure() {
        let mut frame = zstd::stream::encode_all(Cursor::new(b"tiny payload"), 1).expect("encode frame");
        rewrite_zstd_content_size(&mut frame, (MAX_DECOMPRESSED_BYTES + 1) as u32);
        let probe = probe_zstd_frame(&frame, 0, MAX_DECOMPRESSED_BYTES);
        assert_eq!(probe.status, "limit-hit");
        assert_eq!(probe.frame_content_size_bytes, Some(MAX_DECOMPRESSED_BYTES + 1));
        assert!(probe.decoded.is_none());
    }

    #[test]
    fn high_ratio_zstd_output_bomb_hits_the_actual_streaming_output_cap() {
        let payload = vec![0_u8; MAX_DECOMPRESSED_BYTES as usize + 1];
        let frame = make_windowed_zstd_frame(24, &payload);
        assert!(frame.len() < 256 * 1024, "high-ratio fixture should be small on disk");
        let probe = probe_zstd_frame(&frame, 0, MAX_DECOMPRESSED_BYTES);
        assert_eq!(probe.status, "limit-hit");
        assert!(probe.observed_output_bytes.unwrap_or_default() > MAX_DECOMPRESSED_BYTES);
        assert!(probe.decoded.is_none(), "partial bomb output must never be exposed as a complete decoded file");
    }

    #[test]
    fn one_gib_zstd_window_is_rejected_from_header_before_decoder_or_output_allocation() {
        // Non-single-segment Zstandard frame header: magic, descriptor, and
        // window descriptor only. 10 + (20) = log2(1 GiB); there is no block body.
        let mut frame = ZSTD_MAGIC.to_vec();
        frame.push(0x00);
        frame.push(20 << 3);
        assert_eq!(frame.len(), 6);

        let declared_window = zstd_declared_window_size(&frame).expect("header window descriptor");
        assert_eq!(declared_window, 1024 * 1024 * 1024);
        let probe = probe_zstd_frame(&frame, 0, MAX_DECOMPRESSED_BYTES);
        assert_eq!(probe.status, "limit-hit");
        assert!(probe.compressed_frame_size_bytes.is_none(), "frame sizing must not be attempted");
        assert!(probe.observed_output_bytes.is_none(), "no decompression output should exist");
        assert!(probe.note.contains("before decoder creation and output-buffer allocation"));
        assert!(probe.decoded.is_none());
    }

    #[test]
    fn nested_zstd_magic_is_skipped_but_a_following_frame_is_still_decoded() {
        let mut plain = seeded_bytes(128 * 1024, 0xfeed_beef);
        plain[32 * 1024..32 * 1024 + 4].copy_from_slice(ZSTD_MAGIC);
        let first = zstd::stream::encode_all(Cursor::new(&plain), 1).expect("encode outer frame");
        assert!(find_signature_offsets(&first, ZSTD_MAGIC).len() >= 2);
        let second_payload = b"second independent frame at the first frame boundary";
        let second = zstd::stream::encode_all(Cursor::new(second_payload), 1).expect("encode second frame");
        let second_offset = first.len();
        let mut joined = first;
        joined.extend_from_slice(&second);

        let (_, _, _, attempted, skipped_by_cap, overlapping_skipped, probes) = inspect_bytes(&joined);
        assert_eq!(attempted, 2);
        assert_eq!(skipped_by_cap, 0);
        assert!(overlapping_skipped >= 1);
        let nested = probes.iter().find(|p| p.status == "overlapping-signature-skipped");
        assert!(nested.is_some());
        let following = probes.iter().find(|p| p.offset == second_offset).expect("following frame should be attempted");
        assert_eq!(following.status, "decoded-size-matches");
    }

    #[test]
    fn zstd_candidate_budget_caps_real_attempts_at_32() {
        let mut joined = Vec::new();
        for index in 0..(MAX_ZSTD_PROBES + 8) {
            let payload = format!("separate zstd frame number {index}");
            joined.extend_from_slice(
                &zstd::stream::encode_all(Cursor::new(payload.as_bytes()), 1).expect("encode frame")
            );
        }
        let (_, _, _, attempted, skipped_by_cap, overlapping_skipped, probes) = inspect_bytes(&joined);
        assert_eq!(attempted, MAX_ZSTD_PROBES);
        assert_eq!(skipped_by_cap, 8);
        assert_eq!(overlapping_skipped, 0);
        assert_eq!(probes.len(), MAX_ZSTD_PROBES);
    }

    #[test]
    fn scanner_handles_signatures_straddling_64k_and_at_the_final_four_bytes() {
        let mut bytes = vec![0_u8; 70 * 1024];
        let across_boundary = 64 * 1024 - 2;
        let at_end = bytes.len() - 4;
        bytes[across_boundary..across_boundary + 4].copy_from_slice(ZSTD_MAGIC);
        bytes[at_end..].copy_from_slice(ZSTD_MAGIC);
        assert_eq!(find_signature_offsets(&bytes, ZSTD_MAGIC), vec![across_boundary, at_end]);
    }

    #[test]
    fn deterministic_random_bytes_never_panic_the_scanner_or_decoder_wrapper() {
        for iteration in 0..256_u64 {
            let length = (iteration as usize * 37) % 768;
            let mut bytes = seeded_bytes(length, iteration.wrapping_add(0x9e37_79b9));
            if bytes.len() >= 8 && iteration % 2 == 0 {
                let offset = (iteration as usize * 19) % (bytes.len() - 3);
                bytes[offset..offset + 4].copy_from_slice(ZSTD_MAGIC);
            }
            let result = std::panic::catch_unwind(|| inspect_bytes(&bytes));
            assert!(result.is_ok(), "inspection panicked on deterministic fuzz case {iteration}");
        }
    }

    #[test]
    fn sqlite_progress_handler_interrupts_long_query_as_inconclusive_time_budget() {
        let connection = Connection::open_in_memory().expect("open timeout-test SQLite connection");
        let expired_deadline = Instant::now() - Duration::from_millis(1);
        connection.progress_handler(1_000, Some(move || Instant::now() >= expired_deadline));

        // This recursive aggregate is intentionally long-running without the handler.
        let result = connection.query_row(
            "WITH RECURSIVE counter(value) AS (VALUES(0) UNION ALL SELECT value + 1 FROM counter WHERE value < 1000000000) SELECT sum(value) FROM counter",
            [],
            |row| row.get::<_, i64>(0),
        );
        let error = result.expect_err("the expired progress-handler deadline must interrupt the query");
        assert!(sqlite_query_was_interrupted(&error));
        assert_eq!(sqlite_query_error_status(&error), "inconclusive (time budget)");
        assert_eq!(SQLITE_TIMEOUT_LABEL, "inconclusive (time budget)");
    }

    #[test]
    fn sqlite_images_are_opened_read_only_and_wal_headers_are_checked() {
        let source = Connection::open_in_memory().expect("open synthetic SQLite database");
        source.execute_batch("CREATE TABLE test_items(id INTEGER PRIMARY KEY, value TEXT); INSERT INTO test_items(value) VALUES ('unchanged');")
            .expect("create synthetic schema");
        let serialized = source.serialize(rusqlite::MAIN_DB).expect("serialize synthetic SQLite");
        let sqlite_bytes = serialized.to_vec();
        let original_hash = hash_hex(&sqlite_bytes);

        let report = inspect_sqlite_readonly(&sqlite_bytes).expect("SQLite signature should be inspected");
        assert!(report.opened_read_only);
        assert_eq!(report.quick_check.as_deref(), Some("ok"));
        assert!(report.schema_objects.iter().any(|name| name == "test_items"));
        assert!(report.note.contains("defensive mode"));
        assert!(report.note.contains("extension loading was explicitly disabled"));
        assert!(report.note.contains("500 ms progress-handler budget"));
        assert_eq!(hash_hex(&sqlite_bytes), original_hash);

        let page_size = 512_u32;
        let mut wal = vec![0_u8; 32 + 24 + page_size as usize];
        wal[0..4].copy_from_slice(&0x377f_0682_u32.to_be_bytes());
        wal[4..8].copy_from_slice(&3_007_000_u32.to_be_bytes());
        wal[8..12].copy_from_slice(&page_size.to_be_bytes());
        wal[16..20].copy_from_slice(&[1, 2, 3, 4]);
        wal[20..24].copy_from_slice(&[5, 6, 7, 8]);
        let frame_start = 32;
        wal[frame_start..frame_start + 4].copy_from_slice(&1_u32.to_be_bytes());
        wal[frame_start + 8..frame_start + 12].copy_from_slice(&[1, 2, 3, 4]);
        wal[frame_start + 12..frame_start + 16].copy_from_slice(&[5, 6, 7, 8]);

        let wal_report = inspect_sqlite_wal(Some(&wal));
        assert!(wal_report.present);
        assert_eq!(wal_report.status, "unvalidated-header-and-frame-layout");
        assert_eq!(wal_report.checksum_validation, "unvalidated");
        assert!(wal_report.note.contains("UNVALIDATED"));
        assert_eq!(wal_report.page_size_bytes, Some(512));
        assert_eq!(wal_report.complete_frames, 1);
        assert_eq!(wal_report.salt_matching_frames, 1);
        assert_eq!(wal_report.trailing_bytes, 0);

        wal.push(0xAA);
        let tail_report = inspect_sqlite_wal(Some(&wal));
        assert_eq!(tail_report.status, "unvalidated-frames-or-tail-need-review");
        assert_eq!(tail_report.trailing_bytes, 1);
    }

    #[test]
    fn sqlite_wal_mode_image_is_not_opened_without_replaying_wal() {
        let source = Connection::open_in_memory().expect("open SQLite database");
        source.execute_batch("CREATE TABLE t(value INTEGER);").expect("create table");
        let serialized = source.serialize(rusqlite::MAIN_DB).expect("serialize");
        let mut bytes = serialized.to_vec();
        bytes[18] = 1;
        bytes[19] = 2;
        let report = inspect_sqlite_readonly(&bytes).expect("SQLite header");
        assert!(!report.opened_read_only);
        assert_eq!(report.status, "wal-mode-main-file-only-may-be-stale");
        assert!(report.note.contains("main file only, may be stale"));
        assert!(report.quick_check.is_none());
        assert!(report.note.contains("not replayed"));
    }

    #[test]
    fn encrypted_vault_round_trips_and_authenticates() {
        let original = b"GardenVault encrypted snapshot test";
        let encrypted = encrypt_vault("correct horse battery staple", original).expect("encrypt");
        assert!(encrypted.starts_with(VAULT_MAGIC));
        assert_eq!(decrypt_vault_for_test("correct horse battery staple", &encrypted).expect("decrypt"), original);
        assert!(decrypt_vault_for_test("incorrect password", &encrypted).is_err());
    }
}
