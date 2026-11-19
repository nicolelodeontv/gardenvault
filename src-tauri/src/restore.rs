//! Restore a verified snapshot onto an LDPlayer instance.
//!
//! Safety model:
//! 1. Every file is pushed to a private temp path and copied beside its final
//!    destination as `<name>.gvrestore`, preserving owner/mode, then hashed on
//!    the device. Nothing in the live save folder is replaced until all files
//!    have been staged and verified.
//! 2. Any stale `GameData.db-wal` / `-shm` is removed *before* the database is
//!    swapped, so an old WAL can never be replayed onto restored pages.
//! 3. The database file is renamed into place after the `.bak`, and the
//!    restored WAL (if the snapshot had one) last. Each rename is re-hashed.
//! 4. Temporary device and host files are always cleaned up.

use rand::{rngs::OsRng, RngCore};
use std::{fs, path::Path};

use super::{hash_hex, run_adb_for_device, GAME_DATA_DIR, MAX_SAVE_BYTES};

const STAGE_PREFIX: &str = "/data/local/tmp/.gardenvault-restore-";
const REPORT_TAG: &str = "__GARDENVAULT_RESTORE__";
const ALLOWED_NAMES: [&str; 3] = ["GameData.db", "GameData.db.bak", "GameData.db-wal"];

fn is_allowed_name(name: &str) -> bool {
    ALLOWED_NAMES.contains(&name)
}

fn random_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn stage_path(id: &str, name: &str) -> Result<String, String> {
    if !is_allowed_name(name) || id.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Unsupported Gardenscapes restore path.".to_string());
    }
    Ok(format!("{STAGE_PREFIX}{id}-{name}"))
}

fn is_valid_stage_path(path: &str) -> bool {
    path.strip_prefix(STAGE_PREFIX).is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.'))
    })
}

/// Files must be restored in this order: backup, main database, WAL.
fn commit_order<'a>(names: &[&'a str]) -> Vec<&'a str> {
    ["GameData.db.bak", "GameData.db", "GameData.db-wal"]
        .iter()
        .filter_map(|wanted| names.iter().copied().find(|name| name == wanted))
        .collect()
}

fn validate_restore_set(files: &[(String, Vec<u8>)]) -> Result<(), String> {
    let mut seen = Vec::new();
    for (name, bytes) in files {
        if !is_allowed_name(name) {
            return Err("Snapshot contains an unexpected file entry.".to_string());
        }
        if seen.contains(&name.as_str()) {
            return Err(format!("Snapshot contains {name} more than once."));
        }
        seen.push(name.as_str());
        if bytes.is_empty() {
            return Err(format!(
                "Snapshot copy of {name} is empty; refusing to restore."
            ));
        }
        if bytes.len() > MAX_SAVE_BYTES {
            return Err(format!("Snapshot copy of {name} exceeds the safety limit."));
        }
    }
    if !seen.contains(&"GameData.db") {
        return Err("Snapshot has no GameData.db; refusing to restore.".to_string());
    }
    Ok(())
}

fn root_stage_command(stage: &str, name: &str) -> Result<String, String> {
    if !is_valid_stage_path(stage) || !is_allowed_name(name) {
        return Err("Unsupported Gardenscapes restore path.".to_string());
    }
    Ok(format!(
        r#"su -c 'stage="{stage}"; dir="{GAME_DATA_DIR}"; dest="$dir/{name}"; tmp="$dest.gvrestore"; [ -f "$stage" ] || exit 51; [ -d "$dir" ] || exit 52; if [ -f "$dest" ]; then owner=$(stat -c %u:%g "$dest") || exit 53; mode=$(stat -c %a "$dest") || exit 54; else owner=$(stat -c %u:%g "$dir") || exit 53; mode=660; fi; rm -f "$tmp"; cp "$stage" "$tmp" || exit 55; chown "$owner" "$tmp" || exit 56; chmod "$mode" "$tmp" || exit 57; restorecon "$tmp" >/dev/null 2>&1; size=$(stat -c %s "$tmp") || exit 58; line=$(sha256sum "$tmp") || exit 59; hash=$(printf "%s" "$line" | cut -d " " -f 1); printf "{REPORT_TAG}:%s:%s\n" "$size" "$hash"' "#
    ))
}

fn root_commit_command(name: &str) -> Result<String, String> {
    if !is_allowed_name(name) {
        return Err("Unsupported Gardenscapes restore path.".to_string());
    }
    Ok(format!(
        r#"su -c 'dir="{GAME_DATA_DIR}"; dest="$dir/{name}"; tmp="$dest.gvrestore"; [ -f "$tmp" ] || exit 61; mv -f "$tmp" "$dest" || exit 62; sync; size=$(stat -c %s "$dest") || exit 63; line=$(sha256sum "$dest") || exit 64; hash=$(printf "%s" "$line" | cut -d " " -f 1); printf "{REPORT_TAG}:%s:%s\n" "$size" "$hash"' "#
    ))
}

fn root_remove_stale_wal_command() -> String {
    format!("su -c 'rm -f \"{GAME_DATA_DIR}/GameData.db-wal\" \"{GAME_DATA_DIR}/GameData.db-shm\"'")
}

fn root_cleanup_command(stages: &[String]) -> Result<String, String> {
    let mut targets = Vec::new();
    for stage in stages {
        if !is_valid_stage_path(stage) {
            return Err("Unsupported Gardenscapes restore cleanup path.".to_string());
        }
        targets.push(format!("\"{stage}\""));
    }
    for name in ALLOWED_NAMES {
        targets.push(format!("\"{GAME_DATA_DIR}/{name}.gvrestore\""));
    }
    Ok(format!("su -c 'rm -f {}'", targets.join(" ")))
}

fn parse_restore_report(
    name: &str,
    stdout: &[u8],
    stderr: &[u8],
    success: bool,
    expected_size: usize,
    expected_sha256: &str,
) -> Result<(), String> {
    if !success {
        let detail = String::from_utf8_lossy(stderr).trim().to_string();
        return Err(if detail.is_empty() {
            format!("The device refused to write {name}. Check that root access is enabled.")
        } else {
            format!("The device refused to write {name}: {detail}")
        });
    }
    let text = String::from_utf8_lossy(stdout);
    let prefix = format!("{REPORT_TAG}:");
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(&prefix))
        .ok_or_else(|| format!("The device did not confirm the write of {name}."))?;
    let mut parts = line[prefix.len()..].split(':');
    let size: usize = parts
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("The device reported an unreadable size for {name}."))?;
    let sha = parts.next().unwrap_or_default();
    if parts.next().is_some() || size != expected_size || !sha.eq_ignore_ascii_case(expected_sha256)
    {
        return Err(format!(
            "Verification failed for {name}: the device copy does not match the snapshot."
        ));
    }
    Ok(())
}

struct RestoreGuard<'a> {
    adb: &'a Path,
    serial: &'a str,
    stages: Vec<String>,
    host_dir: std::path::PathBuf,
    cleaned: bool,
}

impl RestoreGuard<'_> {
    fn cleanup(&mut self) -> Result<(), String> {
        if self.cleaned {
            return Ok(());
        }
        let mut errors = Vec::new();
        match root_cleanup_command(&self.stages) {
            Ok(command) => match run_adb_for_device(self.adb, self.serial, &["shell", &command]) {
                Ok(output) if output.status.success() => {}
                Ok(_) => errors.push("Could not remove device-side restore files.".to_string()),
                Err(error) => errors.push(error),
            },
            Err(error) => errors.push(error),
        }
        match fs::remove_dir_all(&self.host_dir) {
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

impl Drop for RestoreGuard<'_> {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

/// Stage, verify and swap `files` into the game's save folder.
/// The caller must already have checked the game is closed and taken a safety backup.
pub(super) fn restore_files(
    adb: &Path,
    serial: &str,
    files: &[(String, Vec<u8>)],
) -> Result<(), String> {
    validate_restore_set(files)?;

    let id = random_id();
    let host_dir = std::env::temp_dir().join(format!("gardenvault-restore-{id}"));
    fs::create_dir(&host_dir)
        .map_err(|error| format!("Could not create a private host restore folder: {error}"))?;
    let mut guard = RestoreGuard {
        adb,
        serial,
        stages: Vec::new(),
        host_dir: host_dir.clone(),
        cleaned: false,
    };

    let result: Result<(), String> = (|| {
        // Phase 1: stage and verify everything. The live save is untouched.
        for (name, bytes) in files {
            let stage = stage_path(&id, name)?;
            let host_file = host_dir.join("stage.bin");
            fs::write(&host_file, bytes)
                .map_err(|error| format!("Could not prepare {name} for restore: {error}"))?;
            guard.stages.push(stage.clone());
            let pushed =
                run_adb_for_device(adb, serial, &["push", &host_file.to_string_lossy(), &stage])?;
            if !pushed.status.success() {
                let detail = String::from_utf8_lossy(&pushed.stderr).trim().to_string();
                return Err(format!(
                    "ADB push failed for {name}: {detail}. Nothing was changed."
                ));
            }
            let command = root_stage_command(&stage, name)?;
            let staged = run_adb_for_device(adb, serial, &["shell", &command])?;
            parse_restore_report(
                name,
                &staged.stdout,
                &staged.stderr,
                staged.status.success(),
                bytes.len(),
                &hash_hex(bytes),
            )
            .map_err(|error| format!("{error} Nothing was changed."))?;
        }

        // Phase 2: remove any stale WAL so it can never be replayed.
        let removed =
            run_adb_for_device(adb, serial, &["shell", &root_remove_stale_wal_command()])?;
        if !removed.status.success() {
            return Err(
                "Could not remove the old GameData.db-wal. Nothing was changed.".to_string(),
            );
        }

        // Phase 3: swap into place, verifying each file after the rename.
        let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
        for name in commit_order(&names) {
            let bytes = &files.iter().find(|(n, _)| n == name).expect("validated").1;
            let command = root_commit_command(name)?;
            let committed = run_adb_for_device(adb, serial, &["shell", &command])?;
            parse_restore_report(
                name,
                &committed.stdout,
                &committed.stderr,
                committed.status.success(),
                bytes.len(),
                &hash_hex(bytes),
            )
            .map_err(|error| {
                format!(
                    "{error} The restore stopped part-way; your pre-restore safety backup holds the previous state."
                )
            })?;
        }
        Ok(())
    })();

    let cleanup = guard.cleanup();
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(format!(
            "Restore finished, but temporary files could not be removed: {cleanup_error}"
        )),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error} Temporary-file cleanup also reported: {cleanup_error}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn sample(name: &str, bytes: &[u8]) -> (String, Vec<u8>) {
        (name.to_string(), bytes.to_vec())
    }

    #[test]
    fn stage_and_commit_commands_preserve_ownership_and_only_touch_allowed_files() {
        let stage = stage_path(ID, "GameData.db").unwrap();
        let command = root_stage_command(&stage, "GameData.db").unwrap();
        assert!(command.contains("chown \"$owner\""));
        assert!(command.contains("chmod \"$mode\""));
        assert!(command.contains("stat -c %a \"$dest\""));
        assert!(command.contains(".gvrestore"));
        assert!(command.contains("sha256sum"));
        assert!(!command.contains("cat "));
        assert!(root_stage_command(&stage, "../evil").is_err());
        assert!(root_stage_command(&stage, "GameData.db; id").is_err());
        assert!(root_stage_command("/sdcard/other", "GameData.db").is_err());
        assert!(stage_path("../x", "GameData.db").is_err());
        assert!(stage_path(ID, "other.db").is_err());

        let commit = root_commit_command("GameData.db").unwrap();
        assert!(commit.contains("mv -f \"$tmp\" \"$dest\""));
        assert!(commit.contains("sync"));
        assert!(root_commit_command("other.db").is_err());
    }

    #[test]
    fn stale_wal_removal_and_cleanup_are_scoped() {
        let removal = root_remove_stale_wal_command();
        assert!(removal.contains("GameData.db-wal"));
        assert!(removal.contains("GameData.db-shm"));

        let stage = stage_path(ID, "GameData.db").unwrap();
        let cleanup = root_cleanup_command(std::slice::from_ref(&stage)).unwrap();
        assert!(cleanup.contains(&stage));
        assert!(cleanup.contains("GameData.db.gvrestore"));
        assert!(root_cleanup_command(&["/data/local/tmp/other".to_string()]).is_err());
    }

    #[test]
    fn commit_order_is_backup_then_database_then_wal() {
        let names = ["GameData.db-wal", "GameData.db", "GameData.db.bak"];
        assert_eq!(
            commit_order(&names),
            vec!["GameData.db.bak", "GameData.db", "GameData.db-wal"]
        );
        assert_eq!(commit_order(&["GameData.db"]), vec!["GameData.db"]);
    }

    #[test]
    fn restore_set_requires_main_database_and_rejects_bad_entries() {
        let ok = vec![
            sample("GameData.db", b"abc"),
            sample("GameData.db.bak", b"d"),
        ];
        assert!(validate_restore_set(&ok).is_ok());
        assert!(validate_restore_set(&[sample("GameData.db.bak", b"d")]).is_err());
        assert!(validate_restore_set(&[sample("other.db", b"d")]).is_err());
        assert!(validate_restore_set(&[sample("GameData.db", b"")]).is_err());
        assert!(
            validate_restore_set(&[sample("GameData.db", b"a"), sample("GameData.db", b"b")])
                .is_err()
        );
    }

    #[test]
    fn report_must_match_size_and_hash_exactly() {
        let hash = hash_hex(b"hello");
        let good = format!("{REPORT_TAG}:5:{hash}\r\n");
        assert!(parse_restore_report("GameData.db", good.as_bytes(), b"", true, 5, &hash).is_ok());
        let wrong_hash = format!("{REPORT_TAG}:5:{}\n", hash_hex(b"other"));
        assert!(
            parse_restore_report("GameData.db", wrong_hash.as_bytes(), b"", true, 5, &hash)
                .is_err()
        );
        assert!(parse_restore_report("GameData.db", good.as_bytes(), b"", true, 6, &hash).is_err());
        assert!(parse_restore_report("GameData.db", b"", b"", true, 5, &hash).is_err());
        let trailing = format!("{REPORT_TAG}:5:{hash}:extra\n");
        assert!(
            parse_restore_report("GameData.db", trailing.as_bytes(), b"", true, 5, &hash).is_err()
        );
        let denied = parse_restore_report("GameData.db", b"", b"su: not allowed", false, 5, &hash)
            .unwrap_err();
        assert!(denied.contains("not allowed"));
    }
}
