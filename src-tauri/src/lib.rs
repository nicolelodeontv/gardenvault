use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::UNIX_EPOCH,
};
use tauri::AppHandle;

mod adb;
mod inspect;
mod pull_capture;
mod restore;
mod vault;

use adb::*;
use inspect::*;
use vault::*;

const GAME_PACKAGE: &str = "com.playrix.gardenscapes";
const GAME_DATA_DIR: &str = "/data/user/0/com.playrix.gardenscapes/Documents";
const GAME_WAL_FILE: &str = "GameData.db-wal";
const MAX_SAVE_BYTES: usize = 64 * 1024 * 1024;
const MAX_VAULT_BYTES: u64 = (MAX_SAVE_BYTES as u64) * 4 + 2 * 1024 * 1024;
const MAX_DECOMPRESSED_BYTES: u64 = 20 * 1024 * 1024;
const MAX_ZSTD_WINDOW_BYTES: u64 = 16 * 1024 * 1024;
#[cfg(test)]
const MAX_DECOMPRESSOR_HEADROOM_BYTES: u64 = 8 * 1024 * 1024;
#[cfg(test)]
const MAX_DECOMPRESSOR_WORKING_SET_BYTES: u64 = 64 * 1024 * 1024;
const SQLITE_QUERY_BUDGET_MS: u64 = 500;
const SQLITE_TIMEOUT_LABEL: &str = "inconclusive (time budget)";
const ZSTD_SKIPPABLE_MAGIC_BASE: u32 = 0x184D_2A50;
const MAX_ZSTD_PROBES: usize = 32;
const ZSTD_MAGIC: &[u8; 4] = b"\x28\xb5\x2f\xfd";
const VAULT_MAGIC: &[u8; 7] = b"GVLT001";

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DeviceInfo {
    serial: String,
    game_installed: bool,
    root_available: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FileInfo {
    name: String,
    size_bytes: usize,
    sha256: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadProfileResult {
    device_serial: String,
    captured_at: String,
    vault_path: String,
    files: Vec<FileInfo>,
    missing_optional_files: Vec<String>,
}

fn list_devices_inner() -> Result<Vec<DeviceInfo>, String> {
    let adb = adb_executable();
    let output = run_adb(&adb, &["devices"])?;
    if !output.status.success() {
        return Err(format!(
            "ADB device discovery failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let mut devices = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines().skip(1) {
        let mut fields = line.split_whitespace();
        let Some(serial) = fields.next() else {
            continue;
        };
        let state = fields.next().unwrap_or_default();
        if state != "device" || !is_allowed_emulator_serial(serial) {
            continue;
        }

        let package = run_adb_for_device(&adb, serial, &["shell", "pm", "path", GAME_PACKAGE]);
        let game_installed = package
            .as_ref()
            .map(|r| r.status.success() && String::from_utf8_lossy(&r.stdout).contains("package:"))
            .unwrap_or(false);
        let root = run_adb_for_device(&adb, serial, &["shell", "su", "-c", "id"]);
        let root_available = root
            .as_ref()
            .map(|r| r.status.success() && String::from_utf8_lossy(&r.stdout).contains("uid=0"))
            .unwrap_or(false);

        devices.push(DeviceInfo {
            serial: serial.to_string(),
            game_installed,
            root_available,
        });
    }
    Ok(devices)
}

#[tauri::command]
fn list_devices() -> Result<Vec<DeviceInfo>, String> {
    list_devices_inner()
}

fn append_captured_file(
    file_name: &str,
    bytes: Vec<u8>,
    file_infos: &mut Vec<FileInfo>,
    vault_files: &mut Vec<VaultFile>,
) {
    let digest = hash_hex(&bytes);
    file_infos.push(FileInfo {
        name: file_name.to_string(),
        size_bytes: bytes.len(),
        sha256: digest.clone(),
    });
    vault_files.push(VaultFile {
        name: file_name.to_string(),
        size_bytes: bytes.len(),
        sha256: digest,
        content_base64: BASE64.encode(&bytes),
    });
}

fn append_optional_captured_file(
    file_name: &str,
    bytes: Option<Vec<u8>>,
    file_infos: &mut Vec<FileInfo>,
    vault_files: &mut Vec<VaultFile>,
) {
    if let Some(bytes) = bytes {
        append_captured_file(file_name, bytes, file_infos, vault_files);
    }
}

fn verify_main_capture_unchanged(before: &[u8], after: &[u8]) -> Result<(), String> {
    if hash_hex(before) == hash_hex(after) {
        Ok(())
    } else {
        Err("GameData.db changed while its companion WAL was being captured.".to_string())
    }
}

fn verify_wal_capture_unchanged(
    before: &[u8],
    captured: &[u8],
    after: &[u8],
) -> Result<(), String> {
    let before_hash = hash_hex(before);
    let captured_hash = hash_hex(captured);
    let after_hash = hash_hex(after);
    if before_hash == captured_hash && captured_hash == after_hash {
        Ok(())
    } else {
        Err("GameData.db-wal changed across its capture read.".to_string())
    }
}

#[tauri::command]
fn list_vaults(app: AppHandle) -> Result<Vec<VaultListItem>, String> {
    let vault_dir = app_vault_dir(&app)?;
    fs::create_dir_all(&vault_dir)
        .map_err(|e| format!("Could not open the encrypted backup folder: {e}"))?;

    let entries =
        fs::read_dir(&vault_dir).map_err(|e| format!("Could not list encrypted backups: {e}"))?;
    let mut vaults = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|e| format!("Could not read backup entry: {e}"))?;
        let file_name = entry.file_name().to_string_lossy().into_owned();
        if !is_valid_vault_file_name(&file_name) {
            continue;
        }
        let file_type = entry
            .file_type()
            .map_err(|e| format!("Could not inspect backup file: {e}"))?;
        if !file_type.is_file() {
            continue;
        }
        let metadata = entry
            .metadata()
            .map_err(|e| format!("Could not inspect backup metadata: {e}"))?;
        if metadata.len() < 35 || metadata.len() > MAX_VAULT_BYTES {
            continue;
        }
        let modified_at = metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or_default();

        vaults.push(VaultListItem {
            file_name,
            size_bytes: metadata.len(),
            modified_at,
        });
    }

    vaults.sort_by_key(|vault| std::cmp::Reverse(vault.modified_at));
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
        let extension = target
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
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
fn inspect_vault(
    app: AppHandle,
    file_name: String,
    passphrase: String,
) -> Result<VaultInspection, String> {
    if !is_valid_vault_file_name(&file_name) {
        return Err("Invalid backup file name.".to_string());
    }
    if passphrase.chars().count() < 12 || passphrase.len() > 256 {
        return Err(
            "Enter the original vault passphrase (12 characters minimum, 256 bytes maximum)."
                .to_string(),
        );
    }
    let source = app_vault_dir(&app)?.join(&file_name);
    let metadata = fs::symlink_metadata(&source)
        .map_err(|e| format!("Could not open the selected backup: {e}"))?;
    if !metadata.file_type().is_file() || metadata.len() < 35 || metadata.len() > MAX_VAULT_BYTES {
        return Err("The selected backup is not a valid-sized regular vault file.".to_string());
    }
    let mut encrypted = Vec::with_capacity(metadata.len() as usize);
    File::open(&source)
        .and_then(|mut file| file.read_to_end(&mut encrypted))
        .map_err(|e| format!("Could not read encrypted backup: {e}"))?;
    let plaintext = decrypt_vault(&passphrase, &encrypted)?;
    let snapshot: VaultSnapshot = serde_json::from_slice(&plaintext)
        .map_err(|_| "Decrypted backup has an unsupported snapshot structure.".to_string())?;
    if snapshot.product != "GardenVault"
        || snapshot.package != GAME_PACKAGE
        || snapshot.schema_version != 1
    {
        return Err("Snapshot metadata is not a supported Gardenscapes capture.".to_string());
    }
    let capture_integrity = snapshot.capture_integrity.clone();
    let missing_optional_files = snapshot.missing_optional_files.clone();
    let mut decoded_files = Vec::new();
    for file in snapshot.files {
        if !matches!(
            file.name.as_str(),
            "GameData.db" | "GameData.db.bak" | "GameData.db-wal"
        ) {
            return Err("Snapshot contains an unexpected file entry.".to_string());
        }
        let bytes = BASE64
            .decode(&file.content_base64)
            .map_err(|_| "Snapshot contains invalid encoded file data.".to_string())?;
        if bytes.len() != file.size_bytes || hash_hex(&bytes) != file.sha256 {
            return Err(format!("Integrity check failed for {}.", file.name));
        }
        decoded_files.push((file.name, bytes));
    }

    let wal_diagnostics = decoded_files
        .iter()
        .find(|(name, _)| name == GAME_WAL_FILE)
        .map(|(_, bytes)| inspect_sqlite_wal(Some(bytes)))
        .unwrap_or_else(|| inspect_sqlite_wal(None));
    let mut inspected = Vec::new();
    for (name, bytes) in decoded_files {
        let (
            mut diagnostics,
            header_words,
            decoded_size_matches,
            zstd_candidates_attempted,
            zstd_candidates_skipped,
            zstd_candidates_overlapping_skipped,
            mut zstd_probes,
        ) = inspect_bytes(&bytes);
        if name == "GameData.db" {
            if let Some(sqlite) = diagnostics.sqlite_database.as_mut() {
                sqlite.wal = Some(wal_diagnostics.clone());
                sqlite.note.push_str(if wal_diagnostics.present {
                    " A companion GameData.db-wal was captured and checked separately; its pages were not replayed."
                } else {
                    " No companion GameData.db-wal file was present at capture time."
                });
                for probe in &mut zstd_probes {
                    if let Some(decoded_sqlite) = probe
                        .decoded
                        .as_mut()
                        .and_then(|decoded| decoded.sqlite_database.as_mut())
                    {
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
            transform_diagnostics: transform_diagnostics(&bytes),
        });
    }
    if inspected.is_empty() {
        return Err("Snapshot contains no save files.".to_string());
    }
    let identical_files = inspected.len() > 1
        && inspected
            .iter()
            .all(|f| f.diagnostics.sha256 == inspected[0].diagnostics.sha256);
    Ok(VaultInspection {
        device_serial: snapshot.device_serial,
        captured_at: snapshot.captured_at,
        capture_integrity,
        missing_optional_files,
        files: inspected,
        identical_files,
    })
}

#[tauri::command]
fn read_profile(
    app: AppHandle,
    serial: String,
    passphrase: String,
) -> Result<ReadProfileResult, String> {
    if !is_allowed_emulator_serial(&serial) {
        return Err(
            "Unsupported device identifier. Choose a connected LDPlayer emulator.".to_string(),
        );
    }
    if passphrase.chars().count() < 12 || passphrase.len() > 256 {
        return Err(
            "Use a vault passphrase of at least 12 characters (maximum 256 bytes).".to_string(),
        );
    }

    let devices = list_devices_inner()?;
    let device = devices.iter().find(|d| d.serial == serial).ok_or_else(|| {
        "The selected emulator is no longer connected. Refresh the device list.".to_string()
    })?;
    if !device.game_installed {
        return Err("Gardenscapes is not installed on the selected emulator.".to_string());
    }
    if !device.root_available {
        return Err(
            "Root access is unavailable. Enable LDPlayer root access and try again.".to_string(),
        );
    }

    let adb = adb_executable();
    let process = run_adb_for_device(&adb, &serial, &["shell", "pidof", GAME_PACKAGE])?;
    if !String::from_utf8_lossy(&process.stdout).trim().is_empty() {
        return Err("Gardenscapes is still running. Close the game completely, wait for its save to finish, then retry.".to_string());
    }

    let captured_at = Utc::now().to_rfc3339();
    let mut file_infos = Vec::new();
    let mut vault_files = Vec::new();

    let main_bytes = pull_capture::capture_file(&adb, &serial, "GameData.db")?;
    append_captured_file(
        "GameData.db",
        main_bytes.clone(),
        &mut file_infos,
        &mut vault_files,
    );

    let backup_bytes = pull_capture::capture_file(&adb, &serial, "GameData.db.bak")?;
    append_captured_file(
        "GameData.db.bak",
        backup_bytes,
        &mut file_infos,
        &mut vault_files,
    );

    // Capture the optional WAL three times. All-absent means no WAL record is
    // written; all-present must hash identically. A presence transition or
    // changed main database rejects the capture rather than making a mixed pair.
    let main_before_wal = pull_capture::capture_file(&adb, &serial, "GameData.db")?;
    verify_main_capture_unchanged(&main_bytes, &main_before_wal).map_err(|_| {
        "Capture consistency check failed: GameData.db changed before WAL capture. Keep Gardenscapes closed and retry.".to_string()
    })?;

    let wal_before_read = pull_capture::capture_file_optional(&adb, &serial, GAME_WAL_FILE)?;
    let wal_bytes = pull_capture::capture_file_optional(&adb, &serial, GAME_WAL_FILE)?;
    let wal_after_read = pull_capture::capture_file_optional(&adb, &serial, GAME_WAL_FILE)?;

    let main_after_wal = pull_capture::capture_file(&adb, &serial, "GameData.db")?;
    verify_main_capture_unchanged(&main_before_wal, &main_after_wal).map_err(|_| {
        "Capture consistency check failed: GameData.db changed while its optional WAL was being checked. Keep Gardenscapes closed and retry.".to_string()
    })?;

    let mut missing_optional_files = Vec::new();
    match (wal_before_read, wal_bytes, wal_after_read) {
        (None, None, None) => {
            // Absent means absent: no FileInfo and no encrypted VaultFile entry.
            missing_optional_files.push(GAME_WAL_FILE.to_string());
        }
        (Some(before), Some(captured), Some(after)) => {
            verify_wal_capture_unchanged(&before, &captured, &after).map_err(|_| {
                "Capture consistency check failed: GameData.db-wal changed during its read. No snapshot was saved; keep Gardenscapes closed and retry.".to_string()
            })?;
            append_optional_captured_file(
                GAME_WAL_FILE,
                Some(captured),
                &mut file_infos,
                &mut vault_files,
            );
        }
        _ => {
            return Err("Capture consistency check failed: GameData.db-wal appeared or disappeared during its read. No snapshot was saved; keep Gardenscapes closed and retry.".to_string());
        }
    }

    let process_after = run_adb_for_device(&adb, &serial, &["shell", "pidof", GAME_PACKAGE])?;
    if !String::from_utf8_lossy(&process_after.stdout)
        .trim()
        .is_empty()
    {
        return Err("Gardenscapes started during backup capture. No snapshot was saved; close the game and retry.".to_string());
    }

    let payload = VaultSnapshot {
        schema_version: 1,
        product: "GardenVault".to_string(),
        package: GAME_PACKAGE.to_string(),
        device_serial: serial.clone(),
        captured_at: captured_at.clone(),
        capture_integrity: Some("device-copy-pull-sha256-v1".to_string()),
        missing_optional_files: missing_optional_files.clone(),
        files: vault_files,
    };
    let plaintext = serde_json::to_vec(&payload)
        .map_err(|e| format!("Could not prepare encrypted snapshot: {e}"))?;
    let encrypted = encrypt_vault(&passphrase, &plaintext)?;

    let vault_dir = app_vault_dir(&app)?;
    fs::create_dir_all(&vault_dir)
        .map_err(|e| format!("Could not create encrypted backup folder: {e}"))?;
    let stamp = Utc::now().format("%Y%m%d-%H%M%S-%3f");
    let file_name = format!("gardenscapes-{stamp}.gvault");
    let vault_path = vault_dir.join(&file_name);
    let temporary_path = vault_dir.join(format!("{file_name}.tmp"));

    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary_path)
        .map_err(|e| format!("Could not create temporary vault file: {e}"))?;
    output
        .write_all(&encrypted)
        .and_then(|_| output.sync_all())
        .map_err(|e| format!("Could not write encrypted vault: {e}"))?;
    drop(output);
    fs::rename(&temporary_path, &vault_path)
        .map_err(|e| format!("Could not finalize encrypted vault: {e}"))?;

    Ok(ReadProfileResult {
        device_serial: serial,
        captured_at,
        vault_path: vault_path.display().to_string(),
        files: file_infos,
        missing_optional_files,
    })
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RestoreProfileResult {
    device_serial: String,
    safety_backup_path: String,
    restored_files: Vec<FileInfo>,
    removed_stale_wal: bool,
}

/// Read, decrypt and validate a vault file from `vault_dir`.
fn read_vault_snapshot(
    vault_dir: &Path,
    file_name: &str,
    passphrase: &str,
) -> Result<VaultSnapshot, String> {
    if !is_valid_vault_file_name(file_name) {
        return Err("Invalid backup file name.".to_string());
    }
    let source = vault_dir.join(file_name);
    let metadata = fs::symlink_metadata(&source)
        .map_err(|e| format!("Could not open the selected backup: {e}"))?;
    if !metadata.file_type().is_file() || metadata.len() < 35 || metadata.len() > MAX_VAULT_BYTES {
        return Err("The selected backup is not a valid-sized regular vault file.".to_string());
    }
    let mut encrypted = Vec::with_capacity(metadata.len() as usize);
    File::open(&source)
        .and_then(|mut file| file.read_to_end(&mut encrypted))
        .map_err(|e| format!("Could not read encrypted backup: {e}"))?;
    let plaintext = decrypt_vault(passphrase, &encrypted)?;
    let snapshot: VaultSnapshot = serde_json::from_slice(&plaintext)
        .map_err(|_| "Decrypted backup has an unsupported snapshot structure.".to_string())?;
    if snapshot.product != "GardenVault"
        || snapshot.package != GAME_PACKAGE
        || snapshot.schema_version != 1
    {
        return Err("Snapshot metadata is not a supported Gardenscapes capture.".to_string());
    }
    Ok(snapshot)
}

/// Decode every file in a snapshot, verifying size and SHA-256 for each.
fn decode_snapshot_files(snapshot: VaultSnapshot) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut decoded = Vec::new();
    for file in snapshot.files {
        if !matches!(
            file.name.as_str(),
            "GameData.db" | "GameData.db.bak" | "GameData.db-wal"
        ) {
            return Err("Snapshot contains an unexpected file entry.".to_string());
        }
        let bytes = BASE64
            .decode(&file.content_base64)
            .map_err(|_| "Snapshot contains invalid encoded file data.".to_string())?;
        if bytes.len() != file.size_bytes || hash_hex(&bytes) != file.sha256 {
            return Err(format!("Integrity check failed for {}.", file.name));
        }
        decoded.push((file.name, bytes));
    }
    if decoded.is_empty() {
        return Err("Snapshot contains no save files.".to_string());
    }
    Ok(decoded)
}

/// Delete one regular `.gvault` file from `vault_dir` after checking its header.
fn delete_vault_in(vault_dir: &Path, file_name: &str) -> Result<(), String> {
    if !is_valid_vault_file_name(file_name) {
        return Err("Invalid backup file name.".to_string());
    }
    let target = vault_dir.join(file_name);
    let metadata = fs::symlink_metadata(&target)
        .map_err(|e| format!("Could not open the selected backup: {e}"))?;
    if !metadata.file_type().is_file() {
        return Err("The selected backup is not a regular vault file.".to_string());
    }
    let mut header = [0_u8; 7];
    File::open(&target)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|e| format!("Could not verify the backup header: {e}"))?;
    if &header != VAULT_MAGIC {
        return Err("The selected file is not a recognized GardenVault backup.".to_string());
    }
    fs::remove_file(&target).map_err(|e| format!("Could not delete the backup: {e}"))
}

#[tauri::command]
fn delete_vault(app: AppHandle, file_name: String) -> Result<(), String> {
    delete_vault_in(&app_vault_dir(&app)?, &file_name)
}

#[tauri::command]
fn restore_profile(
    app: AppHandle,
    serial: String,
    file_name: String,
    passphrase: String,
) -> Result<RestoreProfileResult, String> {
    if !is_allowed_emulator_serial(&serial) {
        return Err(
            "Unsupported device identifier. Choose a connected LDPlayer emulator.".to_string(),
        );
    }
    if passphrase.chars().count() < 12 || passphrase.len() > 256 {
        return Err(
            "Enter the vault passphrase (12 characters minimum, 256 bytes maximum).".to_string(),
        );
    }

    // Decrypt and verify the backup first so a wrong passphrase fails before
    // anything on the device is touched.
    let snapshot = read_vault_snapshot(&app_vault_dir(&app)?, &file_name, &passphrase)?;
    let files = decode_snapshot_files(snapshot)?;
    if !files.iter().any(|(name, _)| name == "GameData.db") {
        return Err("This backup has no GameData.db and cannot be restored.".to_string());
    }

    let devices = list_devices_inner()?;
    let device = devices.iter().find(|d| d.serial == serial).ok_or_else(|| {
        "The selected emulator is no longer connected. Refresh the device list.".to_string()
    })?;
    if !device.game_installed {
        return Err("Gardenscapes is not installed on the selected emulator.".to_string());
    }
    if !device.root_available {
        return Err(
            "Root access is unavailable. Enable LDPlayer root access and try again.".to_string(),
        );
    }
    let adb = adb_executable();
    let game_is_running = |adb: &Path| -> Result<bool, String> {
        let output = run_adb_for_device(adb, &serial, &["shell", "pidof", GAME_PACKAGE])?;
        Ok(!String::from_utf8_lossy(&output.stdout).trim().is_empty())
    };
    if game_is_running(&adb)? {
        return Err("Gardenscapes is still running. Close the game completely, wait for its save to finish, then retry.".to_string());
    }

    // Always keep the current state: take a verified safety backup first.
    let safety = read_profile(app.clone(), serial.clone(), passphrase.clone()).map_err(|e| {
        format!("Restore cancelled. The current game state could not be backed up first, so nothing was changed. {e}")
    })?;
    if game_is_running(&adb)? {
        return Err("Gardenscapes started during the restore. Nothing was changed; close the game and retry.".to_string());
    }

    restore::restore_files(&adb, &serial, &files)?;

    let removed_stale_wal = !files.iter().any(|(name, _)| name == GAME_WAL_FILE);
    let restored_files = files
        .iter()
        .map(|(name, bytes)| FileInfo {
            name: name.clone(),
            size_bytes: bytes.len(),
            sha256: hash_hex(bytes),
        })
        .collect();
    Ok(RestoreProfileResult {
        device_serial: serial,
        safety_backup_path: safety.vault_path,
        restored_files,
        removed_stale_wal,
    })
}

pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            list_devices,
            list_vaults,
            export_vault,
            inspect_vault,
            read_profile,
            delete_vault,
            restore_profile
        ])
        .run(tauri::generate_context!())
        .expect("error while running GardenVault");
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::OsRng, RngCore};
    use rusqlite::Connection;
    use std::{
        io::Cursor,
        path::PathBuf,
        time::{Duration, Instant},
    };

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
        frame.splice(
            fcs_offset..fcs_offset + old_fcs_len,
            desired_size.to_le_bytes(),
        );
        frame[4] = (descriptor & 0x3f) | 0x80;
    }

    fn make_windowed_zstd_frame(window_log: u32, payload: &[u8]) -> Vec<u8> {
        let mut encoder =
            zstd::stream::Encoder::new(Vec::new(), 1).expect("create streaming encoder");
        encoder.window_log(window_log).expect("set encoder window");
        encoder.write_all(payload).expect("write streaming payload");
        encoder.finish().expect("finish streaming frame")
    }

    fn seeded_bytes(length: usize, seed: u64) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn block_profile_measures_each_four_kib_chunk_and_partial_tail() {
        let mut bytes = vec![b'A'; TRANSFORM_BLOCK_BYTES + 17];
        bytes[TRANSFORM_BLOCK_BYTES..].fill(0);
        let profile = block_profile(&bytes);
        assert_eq!(profile.block_size_bytes, 4096);
        assert_eq!(profile.block_count, 2);
        assert_eq!(profile.blocks[0].offset_bytes, 0);
        assert_eq!(profile.blocks[0].size_bytes, 4096);
        assert_eq!(profile.blocks[0].entropy_bits_per_byte, 0.0);
        assert_eq!(profile.blocks[0].unique_byte_values, 1);
        assert_eq!(profile.blocks[1].offset_bytes, 4096);
        assert_eq!(profile.blocks[1].size_bytes, 17);
        assert_eq!(profile.blocks[1].zero_byte_percent, 100.0);
        assert_eq!(profile.min_entropy_bits_per_byte, 0.0);
        assert_eq!(profile.max_entropy_bits_per_byte, 0.0);
    }

    #[test]
    fn single_byte_xor_sweep_identifies_sqlite_magic_fixture() {
        const KEY: u8 = 0xA5;
        let mut bytes = b"SQLite format 3\0".to_vec();
        bytes.extend_from_slice(b"SQLite text fixture with ordinary printable content. ");
        for byte in &mut bytes {
            *byte ^= KEY;
        }
        let report = single_byte_xor_diagnostics(&bytes);
        assert_eq!(report.sqlite_magic_xor_key, Some(KEY));
        assert!(report
            .top_candidates
            .iter()
            .any(|candidate| candidate.key_byte == KEY && candidate.sqlite_magic_match));
        assert_eq!(report.sampled_bytes, bytes.len());
    }

    #[test]
    fn repeating_key_xor_checks_every_key_length_from_one_through_32() {
        let plain = b"the quick brown fox jumps over the lazy dog; the garden is growing. ";
        let key = b"ICE";
        let mut bytes = Vec::new();
        for _ in 0..1600 {
            for byte in plain {
                bytes.push(*byte ^ key[bytes.len() % key.len()]);
            }
        }
        let report = repeating_key_xor_diagnostics(&bytes);
        assert_eq!(report.min_key_length, 1);
        assert_eq!(report.max_key_length, 32);
        assert_eq!(report.key_lengths_tested, 32);
        assert_eq!(report.candidates.len(), 32);
        assert_eq!(report.candidates[0].key_length, 1);
        assert_eq!(report.candidates[31].key_length, 32);
        assert!(report.sampled_bytes <= TRANSFORM_SAMPLE_BYTES);
        assert!(report.sample_segments >= 1);
    }

    #[test]
    fn nominal_per_frame_memory_budget_includes_overlapping_sqlite_copy_and_decoder_headroom() {
        // The decoded output Vec and SQLite's read-only deserialize copy coexist.
        // Snapshot/encrypted/plaintext/decoded source buffers and process overhead
        // are additional resident memory and are not covered by this calculation.
        let peak_components =
            (MAX_DECOMPRESSED_BYTES * 2) + MAX_ZSTD_WINDOW_BYTES + MAX_DECOMPRESSOR_HEADROOM_BYTES;
        assert!(peak_components <= MAX_DECOMPRESSOR_WORKING_SET_BYTES);
        assert_eq!(peak_components, MAX_DECOMPRESSOR_WORKING_SET_BYTES);
        const _: () = assert!(MAX_DECOMPRESSED_BYTES < 64 * 1024 * 1024);
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
    fn adb_candidates_cover_ldplayer_versions_and_roots_in_priority_order() {
        let roots = vec![PathBuf::from("C:/"), PathBuf::from("D:/")];
        let list = adb_candidates(&roots);
        assert_eq!(
            list.first().unwrap(),
            &PathBuf::from("C:/").join("LDPlayer14").join("adb.exe")
        );
        assert!(list.contains(&PathBuf::from("D:/").join("LDPlayer9").join("adb.exe")));
        assert!(list.contains(
            &PathBuf::from("C:/")
                .join("LDPlayer")
                .join("LDPlayer14")
                .join("adb.exe")
        ));
        assert!(list.iter().all(|p| p.file_name().unwrap() == "adb.exe"));
    }

    fn scratch_dir(label: &str) -> PathBuf {
        let mut id = [0_u8; 8];
        OsRng.fill_bytes(&mut id);
        let dir = std::env::temp_dir().join(format!("gv-test-{label}-{}", hex::encode(id)));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn delete_vault_removes_only_valid_vault_files() {
        let dir = scratch_dir("delete");
        let good = dir.join("gardenscapes-1.gvault");
        let mut bytes = VAULT_MAGIC.to_vec();
        bytes.extend_from_slice(&[0_u8; 40]);
        fs::write(&good, &bytes).unwrap();
        let fake = dir.join("gardenscapes-2.gvault");
        fs::write(&fake, [7_u8; 64]).unwrap();

        assert!(delete_vault_in(&dir, "../gardenscapes-1.gvault").is_err());
        assert!(delete_vault_in(&dir, "notes.txt").is_err());
        assert!(delete_vault_in(&dir, "missing.gvault").is_err());
        assert!(delete_vault_in(&dir, "gardenscapes-2.gvault").is_err());
        assert!(fake.exists());
        delete_vault_in(&dir, "gardenscapes-1.gvault").unwrap();
        assert!(!good.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn vault_snapshot_round_trips_and_detects_tampering_before_restore() {
        let dir = scratch_dir("snapshot");
        let content = b"SQLite format 3\0 test payload \r\n\n\r".to_vec();
        let make = |sha: String| VaultSnapshot {
            schema_version: 1,
            product: "GardenVault".to_string(),
            package: GAME_PACKAGE.to_string(),
            device_serial: "emulator-5554".to_string(),
            captured_at: "2026-01-01T00:00:00Z".to_string(),
            capture_integrity: None,
            missing_optional_files: vec![GAME_WAL_FILE.to_string()],
            files: vec![VaultFile {
                name: "GameData.db".to_string(),
                size_bytes: content.len(),
                sha256: sha,
                content_base64: BASE64.encode(&content),
            }],
        };
        let passphrase = "correct horse battery";
        let encrypted = encrypt_vault(
            passphrase,
            &serde_json::to_vec(&make(hash_hex(&content))).unwrap(),
        )
        .unwrap();
        fs::write(dir.join("a.gvault"), &encrypted).unwrap();

        let snapshot = read_vault_snapshot(&dir, "a.gvault", passphrase).unwrap();
        let files = decode_snapshot_files(snapshot).unwrap();
        assert_eq!(files, vec![("GameData.db".to_string(), content.clone())]);
        assert!(read_vault_snapshot(&dir, "a.gvault", "wrong passphrase!!").is_err());

        let tampered = make(hash_hex(b"different"));
        assert!(decode_snapshot_files(tampered).is_err());
        fs::remove_dir_all(&dir).unwrap();
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
    fn old_rc8_vault_metadata_remains_readable_without_capture_attestation() {
        let old_snapshot = serde_json::json!({
            "schemaVersion": 1,
            "product": "GardenVault",
            "package": GAME_PACKAGE,
            "deviceSerial": "emulator-5556",
            "capturedAt": "2026-11-18T14:58:25Z",
            "files": []
        });
        let snapshot: VaultSnapshot =
            serde_json::from_value(old_snapshot).expect("legacy snapshots omit captureIntegrity");
        assert!(snapshot.capture_integrity.is_none());
        assert!(snapshot.missing_optional_files.is_empty());

        let current_snapshot = VaultSnapshot {
            schema_version: 1,
            product: "GardenVault".to_string(),
            package: GAME_PACKAGE.to_string(),
            device_serial: "emulator-5556".to_string(),
            captured_at: "2026-11-18T14:58:25Z".to_string(),
            capture_integrity: Some("device-copy-pull-sha256-v1".to_string()),
            missing_optional_files: vec![GAME_WAL_FILE.to_string()],
            files: Vec::new(),
        };
        let current_metadata =
            serde_json::to_value(current_snapshot).expect("serialize current snapshot metadata");
        assert_eq!(
            current_metadata["captureIntegrity"],
            "device-copy-pull-sha256-v1"
        );
        assert_eq!(current_metadata["missingOptionalFiles"][0], GAME_WAL_FILE);
        assert!(current_metadata["files"]
            .as_array()
            .expect("file array")
            .is_empty());
    }

    #[test]
    fn vault_file_names_reject_paths_and_unexpected_extensions() {
        assert!(is_valid_vault_file_name(
            "gardenscapes-20261118-120000.gvault"
        ));
        assert!(!is_valid_vault_file_name("../outside.gvault"));
        assert!(!is_valid_vault_file_name("C:\\outside.gvault"));
        assert!(!is_valid_vault_file_name("backup.txt"));
        assert!(!is_valid_vault_file_name("bad\\nname.gvault"));
    }

    #[test]
    fn file_signature_detection_is_read_only_and_conservative() {
        assert_eq!(
            detect_file_format(b"SQLite format 3\0rest"),
            "SQLite 3 database"
        );
        assert_eq!(detect_file_format(b"PK\x03\x04archive"), "ZIP archive");
        assert_eq!(
            detect_file_format(b"not a known header"),
            "Unknown binary format"
        );
        assert_eq!(
            detect_file_format(b"PLXE\x04\x00\x00\x00"),
            "Playrix PLXE container (payload not decoded)"
        );
        assert!(find_embedded_signatures(b"prefixPLXEpayload")
            .iter()
            .any(|s| s.contains("PLXE")));
        assert_eq!(byte_entropy(&[0_u8; 32]), 0.0);
        let all_values = (0_u8..=255).collect::<Vec<_>>();
        assert!((byte_entropy(&all_values) - 8.0).abs() < 0.0001);
        assert_eq!(unique_byte_count(&all_values), 256);
        assert!(find_embedded_signatures(b"prefix\x28\xb5\x2f\xfdpayload")
            .iter()
            .any(|s| s.contains("Zstandard")));
        assert!(entropy_assessment(7.99).contains("encryption or compression"));
    }

    #[test]
    fn signature_scan_finds_every_strong_hit_through_the_tail() {
        let mut bytes = vec![0_u8; 70 * 1024];
        bytes[12..16].copy_from_slice(b"PLXE");
        bytes[64 * 1024 + 9..64 * 1024 + 13].copy_from_slice(ZSTD_MAGIC);
        bytes[70 * 1024 - 8..70 * 1024 - 4].copy_from_slice(b"PLXE");
        assert_eq!(
            find_signature_offsets(&bytes, b"PLXE"),
            vec![12, 70 * 1024 - 8]
        );
        assert_eq!(
            find_signature_offsets(&bytes, ZSTD_MAGIC),
            vec![64 * 1024 + 9]
        );
        let diagnostics = byte_diagnostics(&bytes);
        assert_eq!(diagnostics.size_mod_16, bytes.len() % 16);
        assert_eq!(diagnostics.size_mod_512, bytes.len() % 512);
        assert_eq!(diagnostics.size_mod_4096, bytes.len() % 4096);
        assert_eq!(diagnostics.tail_hex.len(), 64);
        assert!(diagnostics
            .embedded_signatures
            .iter()
            .any(|hit| hit.contains("0xC")));
        assert!(diagnostics
            .embedded_signatures
            .iter()
            .any(|hit| hit.contains("0x117F8")));
    }

    #[test]
    fn zstd_probe_decodes_one_frame_and_ignores_trailing_data() {
        let original = b"SQLite format 3\0GardenVault test payload";
        let compressed =
            zstd::stream::encode_all(Cursor::new(original), 1).expect("encode zstd test frame");
        let mut bytes = b"prefixPLXE".to_vec();
        let frame_offset = bytes.len();
        bytes.extend_from_slice(&compressed);
        bytes.extend_from_slice(b"trailing-footer");
        let probe = probe_zstd_frame(&bytes, frame_offset, MAX_DECOMPRESSED_BYTES);
        assert_eq!(probe.status, "decoded-size-matches");
        assert_eq!(probe.frame_content_size_bytes, Some(original.len() as u64));
        assert_eq!(probe.compressed_frame_size_bytes, Some(compressed.len()));
        assert_eq!(
            probe.trailing_bytes_after_frame,
            Some(b"trailing-footer".len())
        );
        let decoded = probe.decoded.expect("decoded file diagnostics");
        assert_eq!(decoded.detected_format, "SQLite 3 database");
        assert_eq!(decoded.sha256, hash_hex(original));
    }

    #[test]
    fn all_zstd_candidates_are_attempted_and_plxe_lengths_are_compared() {
        let first = zstd::stream::encode_all(Cursor::new(b"first decoded payload"), 1)
            .expect("first frame");
        let second = zstd::stream::encode_all(Cursor::new(b"second decoded payload"), 1)
            .expect("second frame");
        let mut bytes = b"PLXE\0\0\0\0".to_vec();
        let first_offset = bytes.len();
        bytes.extend_from_slice(&first);
        bytes.extend_from_slice(b"separator");
        let second_offset = bytes.len();
        bytes.extend_from_slice(&second);
        bytes[4..8].copy_from_slice(&(first.len() as u32).to_le_bytes());

        let (_, header_words, _decoded_size_matches, _attempted, skipped, _overlapping, probes) =
            inspect_bytes(&bytes);
        assert_eq!(
            find_signature_offsets(&bytes, ZSTD_MAGIC),
            vec![first_offset, second_offset]
        );
        assert_eq!(probes.len(), 2);
        assert_eq!(skipped, 0);
        assert!(probes
            .iter()
            .all(|probe| probe.status == "decoded-size-matches"));
        assert!(header_words
            .iter()
            .any(|word| word.contains("matches compressed Zstandard frame length")));
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

        let (_, header_words, decoded_matches, _attempted, skipped, _overlapping, probes) =
            inspect_bytes(&bytes);
        assert_eq!(skipped, 0);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].offset, frame_offset);
        assert_eq!(probes[0].status, "decoded-size-matches");
        assert!(header_words
            .iter()
            .any(|word| word.contains("matches compressed Zstandard frame length")));
        assert_eq!(
            probes[0].decoded.as_ref().map(|decoded| decoded.size_bytes),
            Some(original.len()),
            "successful frame diagnostics should retain the actual decoded byte count"
        );
        let fixture_header = hex::encode(&bytes[..bytes.len().min(32)]);
        assert!(
            decoded_matches.iter().any(|word| {
                word == &format!(
                    "PLXE@0x0 word 2 (+0x08) equals decoded size {} from Zstandard@0x{:X}",
                    original.len(),
                    frame_offset
                )
            }),
            "expected PLXE word at byte offset +0x08 to match the actual decoded length; first_bytes={fixture_header}, header_words={header_words:?}, decoded_matches={decoded_matches:?}, probe_status={}, decoded_length={:?}",
            probes[0].status,
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
        let mut small_frame =
            zstd::stream::encode_all(Cursor::new(&small_actual), 1).expect("encode small frame");
        rewrite_zstd_content_size(&mut small_frame, 1024 * 1024);
        let small_probe = probe_zstd_frame(&small_frame, 0, MAX_DECOMPRESSED_BYTES);
        assert_eq!(small_probe.frame_content_size_bytes, Some(1024 * 1024));
        assert_eq!(small_probe.status, "decoded-size-mismatch");
        assert!(small_probe.decoded.is_none());

        let large_actual = seeded_bytes(1024 * 1024, 0xabc2);
        let mut large_frame =
            zstd::stream::encode_all(Cursor::new(&large_actual), 1).expect("encode large frame");
        rewrite_zstd_content_size(&mut large_frame, 2 * 1024);
        let large_probe = probe_zstd_frame(&large_frame, 0, MAX_DECOMPRESSED_BYTES);
        assert_eq!(large_probe.frame_content_size_bytes, Some(2 * 1024));
        assert_eq!(large_probe.status, "decoded-size-mismatch");
        assert!(large_probe.decoded.is_none());
    }

    #[test]
    fn declared_output_over_limit_is_a_limit_hit_not_a_decode_failure() {
        let mut frame =
            zstd::stream::encode_all(Cursor::new(b"tiny payload"), 1).expect("encode frame");
        rewrite_zstd_content_size(&mut frame, (MAX_DECOMPRESSED_BYTES + 1) as u32);
        let probe = probe_zstd_frame(&frame, 0, MAX_DECOMPRESSED_BYTES);
        assert_eq!(probe.status, "limit-hit");
        assert_eq!(
            probe.frame_content_size_bytes,
            Some(MAX_DECOMPRESSED_BYTES + 1)
        );
        assert!(probe.decoded.is_none());
    }

    #[test]
    fn high_ratio_zstd_output_bomb_hits_the_actual_streaming_output_cap() {
        let payload = vec![0_u8; MAX_DECOMPRESSED_BYTES as usize + 1];
        let frame = make_windowed_zstd_frame(24, &payload);
        assert!(
            frame.len() < 256 * 1024,
            "high-ratio fixture should be small on disk"
        );
        let probe = probe_zstd_frame(&frame, 0, MAX_DECOMPRESSED_BYTES);
        assert_eq!(probe.status, "limit-hit");
        assert!(probe.observed_output_bytes.unwrap_or_default() > MAX_DECOMPRESSED_BYTES);
        assert!(
            probe.decoded.is_none(),
            "partial bomb output must never be exposed as a complete decoded file"
        );
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
        assert!(
            probe.compressed_frame_size_bytes.is_none(),
            "frame sizing must not be attempted"
        );
        assert!(
            probe.observed_output_bytes.is_none(),
            "no decompression output should exist"
        );
        assert!(probe
            .note
            .contains("before decoder creation and output-buffer allocation"));
        assert!(probe.decoded.is_none());
    }

    #[test]
    fn nested_zstd_magic_is_skipped_but_a_following_frame_is_still_decoded() {
        let mut plain = seeded_bytes(128 * 1024, 0xfeed_beef);
        plain[32 * 1024..32 * 1024 + 4].copy_from_slice(ZSTD_MAGIC);
        let first = zstd::stream::encode_all(Cursor::new(&plain), 1).expect("encode outer frame");
        assert!(find_signature_offsets(&first, ZSTD_MAGIC).len() >= 2);
        let second_payload = b"second independent frame at the first frame boundary";
        let second =
            zstd::stream::encode_all(Cursor::new(second_payload), 1).expect("encode second frame");
        let second_offset = first.len();
        let mut joined = first;
        joined.extend_from_slice(&second);

        let (_, _, _, attempted, skipped_by_cap, overlapping_skipped, probes) =
            inspect_bytes(&joined);
        assert_eq!(attempted, 2);
        assert_eq!(skipped_by_cap, 0);
        assert!(overlapping_skipped >= 1);
        let nested = probes
            .iter()
            .find(|p| p.status == "overlapping-signature-skipped");
        assert!(nested.is_some());
        let following = probes
            .iter()
            .find(|p| p.offset == second_offset)
            .expect("following frame should be attempted");
        assert_eq!(following.status, "decoded-size-matches");
    }

    #[test]
    fn zstd_candidate_budget_caps_real_attempts_at_32() {
        let mut joined = Vec::new();
        for index in 0..(MAX_ZSTD_PROBES + 8) {
            let payload = format!("separate zstd frame number {index}");
            joined.extend_from_slice(
                &zstd::stream::encode_all(Cursor::new(payload.as_bytes()), 1)
                    .expect("encode frame"),
            );
        }
        let (_, _, _, attempted, skipped_by_cap, overlapping_skipped, probes) =
            inspect_bytes(&joined);
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
        assert_eq!(
            find_signature_offsets(&bytes, ZSTD_MAGIC),
            vec![across_boundary, at_end]
        );
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
            assert!(
                result.is_ok(),
                "inspection panicked on deterministic fuzz case {iteration}"
            );
        }
    }

    #[test]
    fn sqlite_progress_handler_interrupts_long_query_as_inconclusive_time_budget() {
        let connection = Connection::open_in_memory().expect("open timeout-test SQLite connection");
        let deadline = Instant::now() + Duration::from_millis(SQLITE_QUERY_BUDGET_MS);
        connection.progress_handler(1_000, Some(move || Instant::now() >= deadline));

        // This recursive aggregate is intentionally long-running without the handler.
        let result = connection.query_row(
            "WITH RECURSIVE counter(value) AS (VALUES(0) UNION ALL SELECT value + 1 FROM counter WHERE value < 1000000000) SELECT sum(value) FROM counter",
            [],
            |row| row.get::<_, i64>(0),
        );
        let error =
            result.expect_err("the expired progress-handler deadline must interrupt the query");
        assert!(sqlite_query_was_interrupted(&error));
        assert_eq!(
            sqlite_query_error_status(&error),
            "inconclusive (time budget)"
        );
        assert_eq!(SQLITE_TIMEOUT_LABEL, "inconclusive (time budget)");
    }

    #[test]
    fn sqlite_images_are_opened_read_only_and_wal_headers_are_checked() {
        let source = Connection::open_in_memory().expect("open synthetic SQLite database");
        source.execute_batch("CREATE TABLE test_items(id INTEGER PRIMARY KEY, value TEXT); INSERT INTO test_items(value) VALUES ('unchanged');")
            .expect("create synthetic schema");
        let serialized = source
            .serialize(rusqlite::MAIN_DB)
            .expect("serialize synthetic SQLite");
        let sqlite_bytes = serialized.to_vec();
        let original_hash = hash_hex(&sqlite_bytes);

        let report =
            inspect_sqlite_readonly(&sqlite_bytes).expect("SQLite signature should be inspected");
        assert!(report.opened_read_only);
        assert_eq!(report.quick_check.as_deref(), Some("ok"));
        assert!(report
            .schema_objects
            .iter()
            .any(|name| name == "test_items"));
        assert!(report.note.contains("defensive mode"));
        assert!(report
            .note
            .contains("extension loading was explicitly disabled"));
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
        source
            .execute_batch("CREATE TABLE t(value INTEGER);")
            .expect("create table");
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
        assert_eq!(
            decrypt_vault_for_test("correct horse battery staple", &encrypted).expect("decrypt"),
            original
        );
        assert!(decrypt_vault_for_test("incorrect password", &encrypted).is_err());
    }
}
