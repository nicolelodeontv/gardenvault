use rand::{rngs::OsRng, RngCore};
use std::{
    fs,
    path::{Path, PathBuf},
};

use super::{hash_hex, run_adb_for_device, GAME_DATA_DIR, MAX_SAVE_BYTES};

#[cfg(test)]
use super::{append_captured_file, append_optional_captured_file, FileInfo, VaultFile};

#[derive(Debug)]
struct DevicePullMetadata {
    remote_path: String,
    source_size: usize,
    source_sha256: String,
    copy_size: usize,
    copy_sha256: String,
}

struct CaptureTempGuard<'a> {
    adb: &'a Path,
    serial: &'a str,
    sdcard_path: String,
    fallback_path: String,
    host_dir: PathBuf,
    host_file: PathBuf,
    cleaned: bool,
}

impl CaptureTempGuard<'_> {
    fn cleanup(&mut self) -> Result<(), String> {
        if self.cleaned {
            return Ok(());
        }

        let cleanup_command = root_cleanup_capture_command(&self.sdcard_path, &self.fallback_path)?;
        let remote_result = run_adb_for_device(self.adb, self.serial, &["shell", &cleanup_command]);
        let mut errors = Vec::new();
        match remote_result {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
                errors.push(if detail.is_empty() {
                    "ADB could not remove the device-side temporary copies.".to_string()
                } else {
                    format!("ADB could not remove device-side temporary copies: {detail}")
                });
            }
            Err(error) => errors.push(format!("Could not run device-side temporary-file cleanup: {error}")),
        }

        match fs::remove_file(&self.host_file) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => errors.push(format!("Could not remove host temporary file: {error}")),
        }
        match fs::remove_dir(&self.host_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => errors.push(format!("Could not remove host temporary folder: {error}")),
        }

        if errors.is_empty() {
            self.cleaned = true;
            Ok(())
        } else {
            Err(errors.join(" "))
        }
    }
}

impl Drop for CaptureTempGuard<'_> {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

fn is_valid_capture_temp_path(path: &str, prefix: &str) -> bool {
    let Some(suffix) = path.strip_prefix(prefix) else {
        return false;
    };
    !suffix.is_empty()
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
}

fn random_capture_id() -> String {
    let mut bytes = [0_u8; 16];
    let mut random = OsRng;
    random.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn create_capture_temp_guard<'a>(
    adb: &'a Path,
    serial: &'a str,
    file_name: &str,
) -> Result<CaptureTempGuard<'a>, String> {
    if !matches!(file_name, "GameData.db" | "GameData.db.bak" | "GameData.db-wal") {
        return Err("Unsupported Gardenscapes save file.".to_string());
    }

    for _ in 0..4 {
        let id = random_capture_id();
        let sdcard_path = format!("/sdcard/.gardenvault-capture-{id}-{file_name}");
        let fallback_path = format!("/data/local/tmp/.gardenvault-capture-{id}-{file_name}");
        let host_dir = std::env::temp_dir().join(format!("gardenvault-capture-{id}"));
        match fs::create_dir(&host_dir) {
            Ok(()) => {
                let host_file = host_dir.join("pulled-save.bin");
                return Ok(CaptureTempGuard {
                    adb,
                    serial,
                    sdcard_path,
                    fallback_path,
                    host_dir,
                    host_file,
                    cleaned: false,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!("Could not create a private host capture folder: {error}"));
            }
        }
    }

    Err("Could not allocate a unique temporary capture folder.".to_string())
}

fn root_prepare_pull_command(
    file_name: &str,
    sdcard_path: &str,
    fallback_path: &str,
) -> Result<String, String> {
    if !matches!(file_name, "GameData.db" | "GameData.db.bak" | "GameData.db-wal")
        || !is_valid_capture_temp_path(sdcard_path, "/sdcard/.gardenvault-capture-")
        || !is_valid_capture_temp_path(fallback_path, "/data/local/tmp/.gardenvault-capture-")
    {
        return Err("Unsupported Gardenscapes capture path.".to_string());
    }

    Ok(format!(
        r#"su -c 'src="{GAME_DATA_DIR}/{file_name}"; sd="{sdcard_path}"; fallback="{fallback_path}"; if [ ! -f "$src" ]; then printf "__GARDENVAULT_FILE_MISSING__\n"; exit 0; fi; rm -f "$sd" "$fallback"; if cp "$src" "$sd" 2>/dev/null; then dest="$sd"; elif cp "$src" "$fallback" 2>/dev/null && chmod 644 "$fallback" 2>/dev/null; then dest="$fallback"; else rm -f "$sd" "$fallback"; exit 41; fi; source_size=$(stat -c %s "$src" 2>/dev/null) || exit 42; source_line=$(sha256sum "$src" 2>/dev/null) || exit 43; source_hash=$(printf "%s" "$source_line" | cut -d " " -f 1); copy_size=$(stat -c %s "$dest" 2>/dev/null) || exit 44; copy_line=$(sha256sum "$dest" 2>/dev/null) || exit 45; copy_hash=$(printf "%s" "$copy_line" | cut -d " " -f 1); printf "__GARDENVAULT_PULL__:%s:%s:%s:%s:%s\n" "$dest" "$source_size" "$source_hash" "$copy_size" "$copy_hash"' "#
    ))
}

fn root_cleanup_capture_command(sdcard_path: &str, fallback_path: &str) -> Result<String, String> {
    if !is_valid_capture_temp_path(sdcard_path, "/sdcard/.gardenvault-capture-")
        || !is_valid_capture_temp_path(fallback_path, "/data/local/tmp/.gardenvault-capture-")
    {
        return Err("Unsupported Gardenscapes temporary cleanup path.".to_string());
    }

    Ok(format!("su -c 'rm -f \"{sdcard_path}\" \"{fallback_path}\"'"))
}

fn is_valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn parse_device_pull_metadata(
    file_name: &str,
    stdout: &[u8],
    stderr: &[u8],
    status_success: bool,
    expected_sdcard_path: &str,
    expected_fallback_path: &str,
) -> Result<Option<DevicePullMetadata>, String> {
    if !status_success {
        let detail = String::from_utf8_lossy(stderr).trim().to_string();
        return Err(if detail.is_empty() {
            format!("Could not prepare {file_name} for ADB pull: root copy or device-side verification failed.")
        } else {
            format!("Could not prepare {file_name} for ADB pull: {detail}")
        });
    }

    // This is text-only command metadata. No save-file bytes travel through stdout.
    let output_text = std::str::from_utf8(stdout)
        .map_err(|_| format!("Could not read {file_name}: invalid device copy metadata."))?;
    let lines = output_text.lines().collect::<Vec<_>>();
    if lines.iter().any(|line| *line == "__GARDENVAULT_FILE_MISSING__") {
        return Ok(None);
    }

    let marker = lines
        .iter()
        .find_map(|line| line.strip_prefix("__GARDENVAULT_PULL__:"))
        .ok_or_else(|| {
            format!("Could not prepare {file_name}: device returned no verified copy metadata.")
        })?;
    let fields = marker.split(':').collect::<Vec<_>>();
    if fields.len() != 5 {
        return Err(format!(
            "Could not prepare {file_name}: malformed device copy metadata."
        ));
    }

    let remote_path = fields[0].to_string();
    if remote_path != expected_sdcard_path && remote_path != expected_fallback_path {
        return Err(format!(
            "Could not prepare {file_name}: device selected an unexpected temporary path."
        ));
    }
    let source_size = fields[1]
        .parse::<usize>()
        .map_err(|_| format!("Could not prepare {file_name}: invalid source file size reported by device."))?;
    let source_sha256 = fields[2].to_string();
    let copy_size = fields[3]
        .parse::<usize>()
        .map_err(|_| format!("Could not prepare {file_name}: invalid temporary-copy size reported by device."))?;
    let copy_sha256 = fields[4].to_string();

    if source_size == 0 || copy_size == 0 {
        return Err(format!("{file_name} is zero bytes; refusing to create an empty backup entry."));
    }
    if source_size > MAX_SAVE_BYTES || copy_size > MAX_SAVE_BYTES {
        return Err(format!(
            "{file_name} exceeds the {} MiB safety limit.",
            MAX_SAVE_BYTES / (1024 * 1024)
        ));
    }
    if !is_valid_sha256(&source_sha256) || !is_valid_sha256(&copy_sha256) {
        return Err(format!(
            "Could not prepare {file_name}: device returned an invalid SHA-256 value."
        ));
    }
    if source_size != copy_size || !source_sha256.eq_ignore_ascii_case(&copy_sha256) {
        return Err(format!(
            "Device temporary-copy verification failed for {file_name}: source size/hash did not match the copied file. No backup was saved."
        ));
    }

    Ok(Some(DevicePullMetadata {
        remote_path,
        source_size,
        source_sha256,
        copy_size,
        copy_sha256,
    }))
}

fn verify_pulled_capture(
    file_name: &str,
    bytes: &[u8],
    expected_size: usize,
    device_sha256: &str,
) -> Result<Vec<u8>, String> {
    if expected_size == 0 || expected_size > MAX_SAVE_BYTES {
        return Err(format!(
            "Could not verify pulled {file_name}: device-reported size is outside the allowed range."
        ));
    }
    if !is_valid_sha256(device_sha256) {
        return Err(format!(
            "Could not verify pulled {file_name}: invalid device SHA-256 value."
        ));
    }
    if bytes.len() != expected_size {
        return Err(format!(
            "Could not read {file_name} completely: device copy reported {expected_size} bytes but ADB pull returned {}. No backup was saved.",
            bytes.len()
        ));
    }

    let pulled_sha256 = hash_hex(bytes);
    if !pulled_sha256.eq_ignore_ascii_case(device_sha256) {
        return Err(format!(
            "ADB pull integrity check failed for {file_name}: device SHA-256 {device_sha256} does not match pulled bytes {pulled_sha256}. No backup was saved."
        ));
    }

    Ok(bytes.to_vec())
}

pub(super) fn capture_file_optional(
    adb: &Path,
    serial: &str,
    file_name: &str,
) -> Result<Option<Vec<u8>>, String> {
    let mut guard = create_capture_temp_guard(adb, serial, file_name)?;
    let capture_result: Result<Option<Vec<u8>>, String> = (|| {
        let prepare_command =
            root_prepare_pull_command(file_name, &guard.sdcard_path, &guard.fallback_path)?;
        let prepared = run_adb_for_device(adb, serial, &["shell", &prepare_command])?;
        let metadata = parse_device_pull_metadata(
            file_name,
            &prepared.stdout,
            &prepared.stderr,
            prepared.status.success(),
            &guard.sdcard_path,
            &guard.fallback_path,
        )?;
        let Some(metadata) = metadata else {
            return Ok(None);
        };

        let host_path = guard.host_file.to_string_lossy().into_owned();
        let pulled = run_adb_for_device(
            adb,
            serial,
            &["pull", &metadata.remote_path, &host_path],
        )?;
        if !pulled.status.success() {
            let detail = String::from_utf8_lossy(&pulled.stderr).trim().to_string();
            return Err(if detail.is_empty() {
                format!("ADB pull failed for {file_name}. No backup was saved.")
            } else {
                format!("ADB pull failed for {file_name}: {detail}. No backup was saved.")
            });
        }

        let pulled_size = fs::metadata(&guard.host_file)
            .map_err(|error| {
                format!("ADB pull did not create a readable host file for {file_name}: {error}")
            })?
            .len();
        if pulled_size > MAX_SAVE_BYTES as u64 {
            return Err(format!(
                "Pulled {file_name} exceeds the {} MiB safety limit.",
                MAX_SAVE_BYTES / (1024 * 1024)
            ));
        }
        if metadata.source_size != metadata.copy_size
            || !metadata.source_sha256.eq_ignore_ascii_case(&metadata.copy_sha256)
        {
            return Err(format!(
                "Device temporary-copy verification changed before pull for {file_name}. No backup was saved."
            ));
        }
        if pulled_size != metadata.source_size as u64 {
            return Err(format!(
                "Could not read {file_name} completely: device source reported {} bytes but ADB pull wrote {pulled_size}. No backup was saved.",
                metadata.source_size
            ));
        }

        let bytes = fs::read(&guard.host_file)
            .map_err(|error| format!("Could not read pulled host copy of {file_name}: {error}"))?;
        verify_pulled_capture(file_name, &bytes, metadata.source_size, &metadata.source_sha256)
            .map(Some)
    })();

    let cleanup_result = guard.cleanup();
    match (capture_result, cleanup_result) {
        (Ok(captured), Ok(())) => Ok(captured),
        (Err(capture_error), Ok(())) => Err(capture_error),
        (Ok(_), Err(cleanup_error)) => Err(format!(
            "Could not clean up temporary capture files: {cleanup_error}. No backup was saved."
        )),
        (Err(capture_error), Err(cleanup_error)) => Err(format!(
            "{capture_error} Temporary-file cleanup also reported: {cleanup_error}"
        )),
    }
}

pub(super) fn capture_file(
    adb: &Path,
    serial: &str,
    file_name: &str,
) -> Result<Vec<u8>, String> {
    capture_file_optional(adb, serial, file_name)?
        .ok_or_else(|| format!("Required Gardenscapes file {file_name} is not present."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileInfo, VaultFile};

    #[test]
    fn root_prepare_pull_command_uses_copy_hashes_and_safe_fallback() {
        let sdcard = "/sdcard/.gardenvault-capture-0123456789abcdef0123456789abcdef-GameData.db";
        let fallback = "/data/local/tmp/.gardenvault-capture-0123456789abcdef0123456789abcdef-GameData.db";
        let command = root_prepare_pull_command("GameData.db", sdcard, fallback).unwrap();
        assert!(command.contains("cp \"$src\" \"$sd\""));
        assert!(command.contains("cp \"$src\" \"$fallback\""));
        assert!(command.contains("chmod 644 \"$fallback\""));
        assert!(command.contains("stat -c %s"));
        assert!(command.contains("sha256sum"));
        assert!(command.contains("__GARDENVAULT_PULL__"));
        assert!(!command.contains("cat "));
        assert!(root_prepare_pull_command("../other.db", sdcard, fallback).is_err());
        assert!(root_prepare_pull_command("GameData.db; id", sdcard, fallback).is_err());
        assert!(root_prepare_pull_command("unexpected.db", sdcard, fallback).is_err());
        assert!(root_prepare_pull_command("GameData.db", "/sdcard/other-file", fallback).is_err());
    }

    #[test]
    fn cleanup_command_only_removes_generated_capture_paths() {
        let sdcard = "/sdcard/.gardenvault-capture-0123456789abcdef0123456789abcdef-GameData.db";
        let fallback = "/data/local/tmp/.gardenvault-capture-0123456789abcdef0123456789abcdef-GameData.db";
        let command = root_cleanup_capture_command(sdcard, fallback).unwrap();
        assert!(command.contains("rm -f"));
        assert!(command.contains(sdcard));
        assert!(command.contains(fallback));
        assert!(root_cleanup_capture_command("/sdcard/other", fallback).is_err());
    }

    #[test]
    fn missing_optional_wal_is_absent_and_creates_no_snapshot_or_file_metadata_entry() {
        let missing = b"__GARDENVAULT_FILE_MISSING__\r\n";
        assert!(parse_device_pull_metadata(
            "GameData.db-wal",
            missing,
            b"",
            true,
            "/sdcard/.gardenvault-capture-id-GameData.db-wal",
            "/data/local/tmp/.gardenvault-capture-id-GameData.db-wal",
        ).unwrap().is_none());

        let mut files: Vec<FileInfo> = Vec::new();
        let mut vaults: Vec<VaultFile> = Vec::new();
        append_optional_captured_file("GameData.db-wal", None, &mut files, &mut vaults);
        assert!(files.is_empty());
        assert!(vaults.is_empty());
    }

    #[test]
    fn root_shell_permission_denial_is_a_clear_copy_error() {
        let error = parse_device_pull_metadata(
            "GameData.db",
            b"",
            b"su: permission denied",
            false,
            "/sdcard/.gardenvault-capture-id-GameData.db",
            "/data/local/tmp/.gardenvault-capture-id-GameData.db",
        ).unwrap_err();
        assert!(error.contains("prepare GameData.db for ADB pull"));
        assert!(error.contains("permission denied"));
    }

    #[test]
    fn device_copy_metadata_rejects_zero_length_and_source_copy_mismatch() {
        let sdcard = "/sdcard/.gardenvault-capture-id-GameData.db";
        let fallback = "/data/local/tmp/.gardenvault-capture-id-GameData.db";
        let zero = format!("__GARDENVAULT_PULL__:{sdcard}:0:{}:0:{}\n", hash_hex(b""), hash_hex(b""));
        assert!(parse_device_pull_metadata("GameData.db", zero.as_bytes(), b"", true, sdcard, fallback)
            .unwrap_err().contains("zero bytes"));

        let mismatch = format!("__GARDENVAULT_PULL__:{sdcard}:4:{}:3:{}\n", hash_hex(b"abcd"), hash_hex(b"abc"));
        assert!(parse_device_pull_metadata("GameData.db", mismatch.as_bytes(), b"", true, sdcard, fallback)
            .unwrap_err().contains("source size/hash did not match"));
    }

    #[test]
    fn metadata_accepts_only_known_paths_and_matching_source_copy_hashes() {
        let bytes = b"binary save";
        let sdcard = "/sdcard/.gardenvault-capture-id-GameData.db";
        let fallback = "/data/local/tmp/.gardenvault-capture-id-GameData.db";
        let valid = format!(
            "__GARDENVAULT_PULL__:{sdcard}:{}:{}:{}:{}\r\n",
            bytes.len(), hash_hex(bytes), bytes.len(), hash_hex(bytes)
        );
        let metadata = parse_device_pull_metadata("GameData.db", valid.as_bytes(), b"", true, sdcard, fallback)
            .unwrap().unwrap();
        assert_eq!(metadata.remote_path, sdcard);
        assert_eq!(metadata.source_size, bytes.len());
        assert_eq!(metadata.copy_size, bytes.len());
        assert_eq!(metadata.source_sha256, hash_hex(bytes));
        assert_eq!(metadata.copy_sha256, hash_hex(bytes));

        let unknown_path = format!(
            "__GARDENVAULT_PULL__:/data/local/tmp/unrelated:{}:{}:{}:{}\n",
            bytes.len(), hash_hex(bytes), bytes.len(), hash_hex(bytes)
        );
        assert!(parse_device_pull_metadata("GameData.db", unknown_path.as_bytes(), b"", true, sdcard, fallback).is_err());
    }

    #[test]
    fn pulled_binary_with_many_lf_and_crlf_sequences_is_byte_identical() {
        let mut binary = Vec::with_capacity(256 * 1024);
        for index in 0..8192 {
            binary.extend_from_slice(b"\n\r\n");
            binary.extend_from_slice(b"gardenscapes\x00binary\r\n");
            binary.extend_from_slice(&(index as u32).to_le_bytes());
        }
        let pulled = verify_pulled_capture("GameData.db", &binary, binary.len(), &hash_hex(&binary))
            .expect("adb pull must preserve every binary byte");
        assert_eq!(pulled, binary);
        assert_eq!(pulled.len(), binary.len());
        assert_eq!(hash_hex(&pulled), hash_hex(&binary));
    }

    #[test]
    fn mocked_pull_with_wrong_size_or_hash_saves_nothing() {
        let actual = b"line one\nline two\r\nbinary\x00tail";
        let mut files: Vec<FileInfo> = Vec::new();
        let mut vaults: Vec<VaultFile> = Vec::new();

        let wrong_size = verify_pulled_capture("GameData.db", actual, actual.len() + 1, &hash_hex(actual));
        assert!(wrong_size.is_err());
        assert!(files.is_empty());
        assert!(vaults.is_empty());

        let expected_hash = hash_hex(b"line one\nline two\nbinary\x00tail");
        let wrong_hash = verify_pulled_capture("GameData.db", actual, actual.len(), &expected_hash);
        assert!(wrong_hash.is_err());
        assert!(files.is_empty());
        assert!(vaults.is_empty());

        let verified = verify_pulled_capture("GameData.db", actual, actual.len(), &hash_hex(actual)).unwrap();
        append_captured_file("GameData.db", verified, &mut files, &mut vaults);
        assert_eq!(files.len(), 1);
        assert_eq!(vaults.len(), 1);
    }
}
