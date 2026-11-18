use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::Utc;
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultSnapshot {
    schema_version: u32,
    product: String,
    package: String,
    device_serial: String,
    captured_at: String,
    files: Vec<VaultFile>,
}

#[derive(Serialize)]
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

fn capture_file(adb: &Path, serial: &str, file_name: &str) -> Result<Vec<u8>, String> {
    let remote_path = format!("{GAME_DATA_DIR}/{file_name}");
    let command = format!("cat {remote_path}");
    let output = run_adb_for_device(adb, serial, &["shell", "su", "-c", &command])?;
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
        .invoke_handler(tauri::generate_handler![list_devices, list_vaults, export_vault, read_profile])
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
    fn vault_file_names_reject_paths_and_unexpected_extensions() {
        assert!(is_valid_vault_file_name("gardenscapes-20261118-120000.gvault"));
        assert!(!is_valid_vault_file_name("../outside.gvault"));
        assert!(!is_valid_vault_file_name("C:\\outside.gvault"));
        assert!(!is_valid_vault_file_name("backup.txt"));
        assert!(!is_valid_vault_file_name("bad\\nname.gvault"));
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
