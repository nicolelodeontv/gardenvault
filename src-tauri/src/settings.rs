//! Small persisted app settings (currently only the ADB path).
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

const MAX_SETTINGS_BYTES: u64 = 16 * 1024;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Settings {
    #[serde(default)]
    adb_path: Option<String>,
}

/// Load the saved ADB path. A missing, oversized or corrupt file means "no setting".
pub(crate) fn load_adb_path(settings_file: &Path) -> Option<PathBuf> {
    let metadata = fs::metadata(settings_file).ok()?;
    if !metadata.is_file() || metadata.len() > MAX_SETTINGS_BYTES {
        return None;
    }
    let text = fs::read_to_string(settings_file).ok()?;
    let settings: Settings = serde_json::from_str(&text).ok()?;
    settings
        .adb_path
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

/// Save (or clear, with `None`) the ADB path atomically via a temp file.
pub(crate) fn save_adb_path(settings_file: &Path, adb_path: Option<&Path>) -> Result<(), String> {
    if let Some(parent) = settings_file.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Could not create the settings folder: {error}"))?;
    }
    let settings = Settings {
        adb_path: adb_path.map(|path| path.display().to_string()),
    };
    let json = serde_json::to_vec_pretty(&settings)
        .map_err(|error| format!("Could not prepare settings: {error}"))?;
    let temporary = settings_file.with_extension("json.tmp");
    fs::write(&temporary, json).map_err(|error| format!("Could not write settings: {error}"))?;
    fs::rename(&temporary, settings_file).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        format!("Could not save settings: {error}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "gv-settings-{label}-{}-{}",
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
    fn adb_path_round_trips_clears_and_survives_bad_files() {
        let dir = scratch("roundtrip");
        let file = dir.join("settings.json");
        assert_eq!(load_adb_path(&file), None);

        let adb = Path::new("C:/LDPlayer/LDPlayer9/adb.exe");
        save_adb_path(&file, Some(adb)).unwrap();
        assert_eq!(load_adb_path(&file), Some(adb.to_path_buf()));
        assert!(!dir.join("settings.json.tmp").exists());

        save_adb_path(&file, None).unwrap();
        assert_eq!(load_adb_path(&file), None);

        fs::write(&file, b"{ not json").unwrap();
        assert_eq!(load_adb_path(&file), None);
        fs::write(&file, br#"{"adbPath":"   "}"#).unwrap();
        assert_eq!(load_adb_path(&file), None);
        fs::write(&file, vec![b' '; 20 * 1024]).unwrap();
        assert_eq!(load_adb_path(&file), None);
        fs::remove_dir_all(&dir).unwrap();
    }
}
