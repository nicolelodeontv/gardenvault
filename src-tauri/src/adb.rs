//! ADB discovery and device-serial validation.
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::Mutex,
};

/// ADB path chosen in the app's settings (loaded at startup, updated on save).
static ADB_OVERRIDE: Mutex<Option<PathBuf>> = Mutex::new(None);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdbSource {
    Environment,
    Settings,
    AutoDetected,
    Path,
}

impl AdbSource {
    pub(crate) fn label(self) -> &'static str {
        match self {
            AdbSource::Environment => "GARDENVAULT_ADB environment variable",
            AdbSource::Settings => "saved setting",
            AdbSource::AutoDetected => "auto-detected LDPlayer install",
            AdbSource::Path => "system PATH",
        }
    }
}

pub(crate) fn set_adb_override(path: Option<PathBuf>) {
    if let Ok(mut guard) = ADB_OVERRIDE.lock() {
        *guard = path;
    }
}

fn adb_override() -> Option<PathBuf> {
    ADB_OVERRIDE.lock().ok().and_then(|guard| guard.clone())
}

/// Pick the ADB to use. Order: environment, saved setting, auto-detected, PATH.
/// A candidate is only used if it is an existing file.
pub(crate) fn resolve_adb(
    environment: Option<PathBuf>,
    configured: Option<PathBuf>,
    detected: Option<PathBuf>,
) -> (PathBuf, AdbSource) {
    let ordered = [
        (environment, AdbSource::Environment),
        (configured, AdbSource::Settings),
        (detected, AdbSource::AutoDetected),
    ];
    for (candidate, source) in ordered {
        if let Some(path) = candidate {
            if path.is_file() {
                return (path, source);
            }
        }
    }
    (PathBuf::from("adb"), AdbSource::Path)
}

/// A user-supplied ADB must be a file literally named adb or adb.exe.
pub(crate) fn validate_adb_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("Enter the full path to adb.exe.".to_string());
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name != "adb" && name != "adb.exe" {
        return Err("Choose the adb.exe file (for example LDPlayer's adb.exe).".to_string());
    }
    if !path.is_file() {
        return Err("That file does not exist.".to_string());
    }
    Ok(())
}

/// Run `adb version` and return its first line, proving this really is ADB.
pub(crate) fn adb_version(path: &Path) -> Result<String, String> {
    let output = run_adb(path, &["version"])?;
    let text = String::from_utf8_lossy(&output.stdout);
    let first = text.lines().next().unwrap_or_default().trim().to_string();
    if !output.status.success() || !first.starts_with("Android Debug Bridge") {
        return Err("That program did not identify itself as Android Debug Bridge.".to_string());
    }
    Ok(first)
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const LDPLAYER_FOLDERS: [&str; 3] = ["LDPlayer14", "LDPlayer9", "LDPlayer"];

/// Ordered list of places LDPlayer's bundled ADB is commonly installed.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn adb_candidates(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    for root in roots {
        for folder in LDPLAYER_FOLDERS {
            candidates.push(root.join(folder).join("adb.exe"));
            candidates.push(root.join("LDPlayer").join(folder).join("adb.exe"));
        }
    }
    candidates
}

pub(crate) fn adb_executable() -> PathBuf {
    adb_resolution().0
}

pub(crate) fn adb_resolution() -> (PathBuf, AdbSource) {
    resolve_adb(
        std::env::var_os("GARDENVAULT_ADB").map(PathBuf::from),
        adb_override(),
        detect_ldplayer_adb(),
    )
}

#[cfg(not(windows))]
fn detect_ldplayer_adb() -> Option<PathBuf> {
    None
}

#[cfg(windows)]
fn detect_ldplayer_adb() -> Option<PathBuf> {
    let mut roots: Vec<PathBuf> = ["C", "D", "E", "F"]
        .iter()
        .map(|drive| PathBuf::from(format!(r"{drive}:\")))
        .collect();
    for var in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(dir) = std::env::var_os(var) {
            roots.push(PathBuf::from(dir));
        }
    }
    adb_candidates(&roots).into_iter().find(|c| c.is_file())
}

pub(crate) fn run_adb(executable: &Path, args: &[&str]) -> Result<Output, String> {
    Command::new(executable).args(args).output().map_err(|error| {
        format!("Could not start ADB ({}). Set the ADB path in GardenVault settings, set GARDENVAULT_ADB, or add ADB to PATH. Details: {error}", executable.display())
    })
}

pub(crate) fn run_adb_for_device(
    executable: &Path,
    serial: &str,
    args: &[&str],
) -> Result<Output, String> {
    let mut command_args = vec!["-s", serial];
    command_args.extend_from_slice(args);
    run_adb(executable, &command_args)
}

pub(crate) fn is_allowed_emulator_serial(serial: &str) -> bool {
    if let Some(suffix) = serial.strip_prefix("emulator-") {
        return !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit());
    }
    if let Some(port) = serial.strip_prefix("127.0.0.1:") {
        return !port.is_empty() && port.chars().all(|c| c.is_ascii_digit());
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "gv-adb-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn adb_resolution_prefers_environment_then_setting_then_detected_then_path() {
        let dir = scratch("resolve");
        let env = dir.join("env-adb");
        let cfg = dir.join("cfg-adb");
        let det = dir.join("det-adb");
        for file in [&env, &cfg, &det] {
            fs::write(file, b"x").unwrap();
        }
        let missing = dir.join("missing");

        let all = resolve_adb(Some(env.clone()), Some(cfg.clone()), Some(det.clone()));
        assert_eq!(all, (env.clone(), AdbSource::Environment));
        let no_env = resolve_adb(Some(missing.clone()), Some(cfg.clone()), Some(det.clone()));
        assert_eq!(no_env, (cfg.clone(), AdbSource::Settings));
        let detected = resolve_adb(None, Some(missing.clone()), Some(det.clone()));
        assert_eq!(detected, (det, AdbSource::AutoDetected));
        let fallback = resolve_adb(None, Some(missing), None);
        assert_eq!(fallback, (PathBuf::from("adb"), AdbSource::Path));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn user_supplied_adb_must_be_an_absolute_existing_adb_file() {
        let dir = scratch("validate");
        let good = dir.join("adb.exe");
        let wrong_name = dir.join("notadb.exe");
        fs::write(&good, b"x").unwrap();
        fs::write(&wrong_name, b"x").unwrap();

        assert!(validate_adb_path(&good).is_ok());
        assert!(validate_adb_path(&wrong_name).is_err());
        assert!(validate_adb_path(&dir.join("missing").join("adb.exe")).is_err());
        assert!(validate_adb_path(Path::new("adb.exe")).is_err());
        assert!(validate_adb_path(&dir).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn adb_version_accepts_only_programs_that_identify_as_adb() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("version");
        let make = |name: &str, body: &str| {
            let path = dir.join(name);
            fs::write(&path, body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            path
        };
        let real = make(
            "adb",
            "#!/bin/sh\necho 'Android Debug Bridge version 1.0.41'\necho 'Version 34'\n",
        );
        let impostor = make("adb2", "#!/bin/sh\necho 'hello'\n");
        let failing = make(
            "adb3",
            "#!/bin/sh\necho 'Android Debug Bridge version 1'\nexit 1\n",
        );

        assert_eq!(
            adb_version(&real).unwrap(),
            "Android Debug Bridge version 1.0.41"
        );
        assert!(adb_version(&impostor).is_err());
        assert!(adb_version(&failing).is_err());
        assert!(adb_version(&dir.join("absent")).is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
