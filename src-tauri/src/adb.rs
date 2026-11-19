//! ADB discovery and device-serial validation.
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

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
    if let Some(explicit) = std::env::var_os("GARDENVAULT_ADB") {
        let path = PathBuf::from(explicit);
        if path.is_file() {
            return path;
        }
    }
    #[cfg(windows)]
    {
        let mut roots: Vec<PathBuf> = ["C", "D", "E", "F"]
            .iter()
            .map(|drive| PathBuf::from(format!(r"{drive}:\")))
            .collect();
        for var in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(dir) = std::env::var_os(var) {
                roots.push(PathBuf::from(dir));
            }
        }
        if let Some(found) = adb_candidates(&roots).into_iter().find(|c| c.is_file()) {
            return found;
        }
    }
    PathBuf::from("adb")
}

pub(crate) fn run_adb(executable: &Path, args: &[&str]) -> Result<Output, String> {
    Command::new(executable).args(args).output().map_err(|error| {
        format!("Could not start ADB ({}). Set GARDENVAULT_ADB or add ADB to PATH. Details: {error}", executable.display())
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
