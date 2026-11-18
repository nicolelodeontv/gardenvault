use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::{Read, Write}, path::{Path, PathBuf}, process::{Command, Output}, time::UNIX_EPOCH};
use tauri::{AppHandle, Manager};

const GAME_PACKAGE: &str = "com.playrix.gardenscapes";
const GAME_DATA_DIR: &str = "/data/user/0/com.playrix.gardenscapes/Documents";
const MAX_SAVE_BYTES: usize = 64 * 1024 * 1024;
const MAX_VAULT_BYTES: u64 = (MAX_SAVE_BYTES as u64) * 3 + 1024 * 1024;
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct InspectedFile {
    name: String,
    size_bytes: usize,
    sha256: String,
    detected_format: String,
    signature_hex: String,
    entropy_bits_per_byte: f64,
    entropy_assessment: String,
    printable_ascii_percent: f64,
    zero_byte_percent: f64,
    unique_byte_values: usize,
    embedded_signatures: Vec<String>,
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

fn find_embedded_signatures(bytes: &[u8]) -> Vec<String> {
    const SCAN_LIMIT: usize = 64 * 1024;
    let sample = &bytes[..bytes.len().min(SCAN_LIMIT)];
    let signatures: [(&str, &[u8]); 9] = [
        ("SQLite", b"SQLite format 3\0"),
        ("ZIP", b"PK\x03\x04"),
        ("GZIP", b"\x1f\x8b"),
        ("Zstandard", b"\x28\xb5\x2f\xfd"),
        ("LZ4 frame", b"\x04\x22\x4d\x18"),
        ("PNG", b"\x89PNG\r\n\x1a\n"),
        ("JPEG", b"\xff\xd8\xff"),
        ("zlib candidate", b"\x78\x9c"),
        ("zlib candidate", b"\x78\xda"),
    ];
    let mut found = Vec::new();
    for (label, signature) in signatures {
        if let Some(offset) = sample.windows(signature.len()).position(|window| window == signature) {
            found.push(format!("{label} signature at offset 0x{offset:X}"));
        }
    }
    if found.is_empty() { found.push("No known signatures found in first 64 KiB".to_string()); }
    found
}

fn detect_file_format(bytes: &[u8]) -> String {
    if bytes.starts_with(b"SQLite format 3\0") { return "SQLite 3 database".to_string(); }
    if bytes.starts_with(b"PK\x03\x04") { return "ZIP archive".to_string(); }
    if bytes.starts_with(&[0x1f, 0x8b]) { return "GZIP compressed data".to_string(); }
    if bytes.starts_with(b"bplist00") { return "Apple binary property list".to_string(); }
    let trimmed = bytes.iter().copied().skip_while(|b| b.is_ascii_whitespace()).collect::<Vec<_>>();
    if trimmed.starts_with(b"{") || trimmed.starts_with(b"[") {
        return if serde_json::from_slice::<serde_json::Value>(bytes).is_ok() { "JSON".to_string() } else { "JSON-like text (invalid JSON)".to_string() };
    }
    if trimmed.starts_with(b"<?xml") || trimmed.starts_with(b"<") { return "XML-like text".to_string(); }
    if bytes.starts_with(b"UnityFS") { return "UnityFS asset bundle".to_string(); }
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
    if !matches!(file_name, "GameData.db" | "GameData.db.bak") {
        return Err("Unsupported Gardenscapes save file.".to_string());
    }
    let remote_path = format!("{GAME_DATA_DIR}/{file_name}");
    // Keep the whole command as one quoted argument to su -c. Without these
    // quotes, some LDPlayer adb/su combinations parse the path as a target UID.
    Ok(format!("su -c 'cat {remote_path}'"))
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
    let mut inspected = Vec::new();
    for file in snapshot.files {
        if !matches!(file.name.as_str(), "GameData.db" | "GameData.db.bak") {
            return Err("Snapshot contains an unexpected file entry.".to_string());
        }
        let bytes = BASE64.decode(&file.content_base64)
            .map_err(|_| "Snapshot contains invalid encoded file data.".to_string())?;
        if bytes.len() != file.size_bytes || hash_hex(&bytes) != file.sha256 {
            return Err(format!("Integrity check failed for {}.", file.name));
        }
        let signature_hex = hex::encode(bytes.iter().take(32).copied().collect::<Vec<_>>());
        let entropy = byte_entropy(&bytes);
        inspected.push(InspectedFile {
            name: file.name,
            size_bytes: bytes.len(),
            sha256: file.sha256,
            detected_format: detect_file_format(&bytes),
            signature_hex,
            entropy_bits_per_byte: entropy,
            entropy_assessment: entropy_assessment(entropy),
            printable_ascii_percent: byte_percent(&bytes, |b| (0x20..=0x7e).contains(&b)),
            zero_byte_percent: byte_percent(&bytes, |b| b == 0),
            unique_byte_values: unique_byte_count(&bytes),
            embedded_signatures: find_embedded_signatures(&bytes),
        });
    }
    if inspected.is_empty() {
        return Err("Snapshot contains no save files.".to_string());
    }
    let identical_files = inspected.len() > 1 && inspected.iter().all(|f| f.sha256 == inspected[0].sha256);
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
    for file_name in ["GameData.db", "GameData.db.bak"] {
        let bytes = capture_file(&adb, &serial, file_name)?;
        let digest = hash_hex(&bytes);
        file_infos.push(FileInfo { name: file_name.to_string(), size_bytes: bytes.len(), sha256: digest.clone() });
        vault_files.push(VaultFile {
            name: file_name.to_string(),
            size_bytes: bytes.len(),
            sha256: digest,
            content_base64: BASE64.encode(&bytes),
        });
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
        assert_eq!(byte_entropy(&[0_u8; 32]), 0.0);
        let all_values = (0_u8..=255).collect::<Vec<_>>();
        assert!((byte_entropy(&all_values) - 8.0).abs() < 0.0001);
        assert_eq!(unique_byte_count(&all_values), 256);
        assert!(find_embedded_signatures(b"prefix\x28\xb5\x2f\xfdpayload").iter().any(|s| s.contains("Zstandard")));
        assert!(entropy_assessment(7.99).contains("encryption or compression"));
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
