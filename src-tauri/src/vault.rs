//! Encrypted vault format, crypto, and vault types.
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};

use super::*;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VaultListItem {
    pub(crate) file_name: String,
    pub(crate) size_bytes: u64,
    pub(crate) modified_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VaultSnapshot {
    pub(crate) schema_version: u32,
    pub(crate) product: String,
    pub(crate) package: String,
    pub(crate) device_serial: String,
    pub(crate) captured_at: String,
    #[serde(default)]
    pub(crate) capture_integrity: Option<String>,
    #[serde(default)]
    pub(crate) missing_optional_files: Vec<String>,
    pub(crate) files: Vec<VaultFile>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct VaultFile {
    pub(crate) name: String,
    pub(crate) size_bytes: usize,
    pub(crate) sha256: String,
    pub(crate) content_base64: String,
}

pub(crate) fn hash_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn is_valid_vault_file_name(file_name: &str) -> bool {
    !file_name.is_empty()
        && file_name.len() <= 128
        && file_name.ends_with(".gvault")
        && !file_name
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':'))
        && Path::new(file_name)
            .file_name()
            .and_then(|name| name.to_str())
            == Some(file_name)
}

pub(crate) fn app_vault_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let app_data = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Could not resolve GardenVault data folder: {e}"))?;
    Ok(app_data.join("vaults"))
}

pub(crate) fn derive_key(passphrase: &str, salt: &[u8; 16]) -> Result<[u8; 32], String> {
    let params = Params::new(32 * 1024, 3, 1, Some(32))
        .map_err(|e| format!("Invalid key-derivation parameters: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Could not derive encryption key: {e}"))?;
    Ok(key)
}

pub(crate) fn encrypt_vault(passphrase: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut salt = [0_u8; 16];
    let mut nonce = [0_u8; 12];
    let mut random = OsRng;
    random.fill_bytes(&mut salt);
    random.fill_bytes(&mut nonce);

    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "Could not initialize AES-256-GCM".to_string())?;
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| "Could not encrypt the profile snapshot".to_string())?;

    let mut output = Vec::with_capacity(35 + encrypted.len());
    output.extend_from_slice(VAULT_MAGIC);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&encrypted);
    Ok(output)
}

#[cfg(test)]
pub(crate) fn decrypt_vault_for_test(passphrase: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() < 35 || &input[..7] != VAULT_MAGIC {
        return Err("Invalid GardenVault file header".to_string());
    }
    let salt: [u8; 16] = input[7..23]
        .try_into()
        .map_err(|_| "Invalid salt".to_string())?;
    let nonce: [u8; 12] = input[23..35]
        .try_into()
        .map_err(|_| "Invalid nonce".to_string())?;
    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "Could not initialize AES-256-GCM".to_string())?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), &input[35..])
        .map_err(|_| "Authentication failed: wrong password or damaged vault".to_string())
}

pub(crate) fn decrypt_vault(passphrase: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() < 35 || input.len() as u64 > MAX_VAULT_BYTES {
        return Err("Invalid or oversized GardenVault file.".to_string());
    }
    if &input[..7] != VAULT_MAGIC {
        return Err("This is not a recognized GardenVault backup.".to_string());
    }
    let salt: [u8; 16] = input[7..23]
        .try_into()
        .map_err(|_| "Invalid vault salt".to_string())?;
    let nonce: [u8; 12] = input[23..35]
        .try_into()
        .map_err(|_| "Invalid vault nonce".to_string())?;
    let key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| "Could not initialize AES-256-GCM".to_string())?;
    cipher
        .decrypt(Nonce::from_slice(&nonce), &input[35..])
        .map_err(|_| "Authentication failed: wrong passphrase or damaged backup".to_string())
}
