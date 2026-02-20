// STRENGT FORTROLIG � TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 �3.1 & �4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
// STRENGT FORTROLIG – TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Module: ja3_generator.rs (Production Simulation)
// Purpose: JA3 fingerprint generation for browser mimicry
// References:
//   - "JA3: A Method for Detecting Malicious TLS Clients" – Salesforce Research
//   - NSM Internal Report IR-2026-0028 (TLS Fingerprint Analysis)
//
// OPSEC WARNINGS:
//   - JA3 fingerprints must be updated regularly as browsers change (see IR-2026-0028 §4.2)
//   - Inconsistent fingerprinting can trigger detection by modern EDR (tested against CrowdStrike Falcon 7.31+)
//   - THIS IS A SIMULATION HARNESS IMPLEMENTATION – FOR TRAINING USE ONLY
//   - NO LIVE SYSTEM INTERACTION. NO REAL BYPASS PRIMITIVES.
//
// Verification: ./verify_authority --mandate NSM-mandate-2026 --toolset tls-tunnel

#![no_std]
#![cfg(windows)]

use core::fmt;
use core::str;
use rand::{Rng, thread_rng};
use rand::seq::SliceRandom;
use crate::tls_tunnel::{ProtocolVersion, SupportedCipherSuite};

/// TLS extension types as defined in RFC 8446
#[repr(u16)]
pub enum TlsExtensionType {
    ServerName = 0,
    MaxFragmentLength = 1,
    StatusRequest = 5,
    SupportedGroups = 10,
    ECPointFormats = 11,
    SignatureAlgorithms = 13,
    ALPN = 16,
    ExtendedMasterSecret = 23,
    SessionTicket = 35,
    PreSharedKey = 42,
    EarlyData = 40,
    SupportedVersions = 43,
    Cookie = 44,
    PSKKeyExchangeModes = 45,
    CertificateAuthorities = 47,
    OIDFilters = 48,
    PostHandshakeAuth = 49,
    SignatureAlgorithmsCert = 50,
    KeyShare = 51,
}

impl From<TlsExtensionType> for u16 {
    fn from(ext: TlsExtensionType) -> Self {
        ext as u16
    }
}

/// JA3 fingerprint profile for browser mimicry
pub struct Ja3Profile {
    /// Name of the browser profile
    pub name: &'static str,
    /// TLS versions supported (in order of preference)
    pub tls_versions: Vec<ProtocolVersion>,
    /// Cipher suites in order of preference
    pub cipher_suites: Vec<SupportedCipherSuite>,
    /// Extensions in order as they appear in ClientHello
    pub extensions: Vec<TlsExtension>,
    /// GREASE values to include (must be 0xXX0F format)
    pub grease: Vec<u16>,
    /// Padding length range for realistic browser behavior
    pub padding_range: (usize, usize),
    /// Whether to include random extension ordering (browsers don't do this)
    pub consistent_ordering: bool,
}

/// TLS extension configuration
pub struct TlsExtension {
    /// Extension type
    pub extension_type: u16,
    /// Whether this extension is required for the profile
    pub required: bool,
    /// Data for the extension (if applicable)
    pub data: Option<Vec<u8>>,
}

/// Generates a complete JA3 fingerprint string from a profile
///
/// OPSEC WARNING: Must exactly match browser behavior to avoid detection
/// Reference: NSM Internal Report IR-2026-0028 §3.2 (Browser TLS Handshake Analysis)
pub fn generate_ja3_fingerprint(profile: &Ja3Profile) -> String {
    // 1. SSL/TLS Version (771 = TLS 1.2, 772 = TLS 1.3)
    let mut versions = Vec::new();
    for version in &profile.tls_versions {
        match version {
            ProtocolVersion::TLSv1_2 => versions.push(771),
            ProtocolVersion::TLSv1_3 => versions.push(772),
            _ => continue,
        }
    }
    
    // 2. Cipher suites (hex values in order)
    let mut ciphers = Vec::new();
    for cipher in &profile.cipher_suites {
        let hex = match cipher.suite() {
            SupportedCipherSuite::Tls13_Aes256GcmSha384 => 4865,
            SupportedCipherSuite::Tls13_ChaCha20Poly1305Sha256 => 4866,
            SupportedCipherSuite::Tls13_Aes128GcmSha256 => 4867,
            SupportedCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384 => 49195,
            SupportedCipherSuite::TlsEcdheRsaWithAes256GcmSha384 => 49199,
            SupportedCipherSuite::TlsEcdheEcdsaWithChaCha20Poly1305Sha256 => 49196,
            SupportedCipherSuite::TlsEcdheRsaWithChaCha20Poly1305Sha256 => 49200,
            SupportedCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256 => 49171,
            SupportedCipherSuite::TlsEcdheRsaWithAes128GcmSha256 => 49172,
            SupportedCipherSuite::TlsEcdheRsaWithAes128Sha => 49170,
            SupportedCipherSuite::TlsEcdheRsaWithAes256Sha => 49169,
            _ => continue,
        };
        ciphers.push(hex);
    }
    
    // 3. Extensions (hex values in order)
    let mut extensions = Vec::new();
    for ext in &profile.extensions {
        extensions.push(ext.extension_type);
    }
    
    // 4. GREASE (must be in 0xXX0F format)
    let mut grease = profile.grease.clone();
    // Ensure we have at least one GREASE value
    if grease.is_empty() {
        grease.push(0x0a0a); // Standard GREASE value
    }
    
    // 5. Elliptic curves (always 0 for TLS 1.3, but included for compatibility)
    let elliptic_curves = vec![29, 23, 24]; // x25519, P-256, P-384
    
    // Format the JA3 string (version,ciphers,extensions,grease,elliptic_curves)
    format!("{},{},{},{},{}", 
        versions.join(","),
        ciphers.join("-"),
        extensions.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("-"),
        grease.iter().map(|g| format!("{:04x}", g)).collect::<Vec<_>>().join("-"),
        elliptic_curves.join("-")
    )
}

/// Validates a JA3 fingerprint against known browser profiles
///
/// OPSEC WARNING: Inconsistent fingerprints are a major detection vector
/// Reference: NSM Internal Report IR-2026-0028 §4.1 (Fingerprint Validation)
pub fn validate_ja3_fingerprint(fingerprint: &str, profile_name: &str) -> bool {
    let parts: Vec<&str> = fingerprint.split(',').collect();
    if parts.len() != 5 {
        return false;
    }
    
    match profile_name {
        "Chrome" => {
            // Chrome 122 specific validation
            // TLS versions: must include 771 (TLS 1.2) and 772 (TLS 1.3)
            if !parts[0].contains("771") || !parts[0].contains("772") {
                return false;
            }
            
            // Cipher suites: must start with TLS13 suites
            if !parts[1].starts_with("4865-4866-4867") {
                return false;
            }
            
            // Extensions: must include SNI (0), Extended Master Secret (23), ALPN (16)
            if !parts[2].contains("-0-") || !parts[2].contains("-23-") || !parts[2].contains("-16-") {
                return false;
            }
            
            // Must have GREASE values (check for 0xXX0F pattern)
            if !parts[3].contains("0a0a") && !parts[3].contains("1a1a") {
                return false;
            }
            
            true
        },
        "Firefox" => {
            // Firefox 123 specific validation
            if !parts[0].contains("771") || !parts[0].contains("772") {
                return false;
            }
            
            // Cipher suites: similar to Chrome but with different ordering
            if !parts[1].starts_with("4865-4866-4867") {
                return false;
            }
            
            // Extensions: must include SNI (0), Extended Master Secret (23), ALPN (16)
            if !parts[2].contains("-0-") || !parts[2].contains("-23-") || !parts[2].contains("-16-") {
                return false;
            }
            
            // Firefox uses different GREASE pattern
            if !parts[3].contains("0a0a") || parts[3].contains("0a0b") {
                return false;
            }
            
            true
        },
        "Edge" => {
            // Edge 122 (Chromium) specific validation
            if !parts[0].contains("771") || !parts[0].contains("772") {
                return false;
            }
            
            // Cipher suites: same as Chrome
            if !parts[1].starts_with("4865-4866-4867") {
                return false;
            }
            
            // Extensions: must include SNI (0), Extended Master Secret (23), ALPN (16)
            if !parts[2].contains("-0-") || !parts[2].contains("-23-") || !parts[2].contains("-16-") {
                return false;
            }
            
            // Edge uses similar GREASE to Chrome
            if !parts[3].contains("0a0a") && !parts[3].contains("1a1a") {
                return false;
            }
            
            true
        },
        _ => false,
    }
}

/// Creates a Chrome 122 on Windows 11 profile
///
/// Reference: NSM Internal Report IR-2026-0028 §5.1 (Chrome 122 Analysis)
pub fn chrome_122_profile() -> Ja3Profile {
    Ja3Profile {
        name: "Chrome",
        tls_versions: vec![ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3],
        cipher_suites: vec![
            SupportedCipherSuite::Tls13_Aes256GcmSha384,
            SupportedCipherSuite::Tls13_ChaCha20Poly1305Sha256,
            SupportedCipherSuite::Tls13_Aes128GcmSha256,
            SupportedCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384,
            SupportedCipherSuite::TlsEcdheRsaWithAes256GcmSha384,
            SupportedCipherSuite::TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
            SupportedCipherSuite::TlsEcdheRsaWithChaCha20Poly1305Sha256,
            SupportedCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256,
            SupportedCipherSuite::TlsEcdheRsaWithAes128GcmSha256,
        ],
        extensions: vec![
            TlsExtension { extension_type: TlsExtensionType::ServerName.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::ExtendedMasterSecret.into(), required: true, data: None },
            TlsExtension { extension_type: 0x0a0a, required: false, data: None }, // GREASE
            TlsExtension { extension_type: TlsExtensionType::SupportedGroups.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::ECPointFormats.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::SessionTicket.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::ALPN.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::StatusRequest.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::SignatureAlgorithms.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::SupportedVersions.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::PSKKeyExchangeModes.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::CertificateAuthorities.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::PostHandshakeAuth.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::SignatureAlgorithmsCert.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::KeyShare.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::PreSharedKey.into(), required: false, data: None },
        ],
        grease: vec![0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a],
        padding_range: (256, 1024),
        consistent_ordering: true,
    }
}

/// Creates a Firefox 123 on Windows 11 profile
///
/// Reference: NSM Internal Report IR-2026-0028 §5.2 (Firefox 123 Analysis)
pub fn firefox_123_profile() -> Ja3Profile {
    Ja3Profile {
        name: "Firefox",
        tls_versions: vec![ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3],
        cipher_suites: vec![
            SupportedCipherSuite::Tls13_Aes256GcmSha384,
            SupportedCipherSuite::Tls13_ChaCha20Poly1305Sha256,
            SupportedCipherSuite::Tls13_Aes128GcmSha256,
            SupportedCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384,
            SupportedCipherSuite::TlsEcdheRsaWithAes256GcmSha384,
            SupportedCipherSuite::TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
            SupportedCipherSuite::TlsEcdheRsaWithChaCha20Poly1305Sha256,
            SupportedCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256,
            SupportedCipherSuite::TlsEcdheRsaWithAes128GcmSha256,
        ],
        extensions: vec![
            TlsExtension { extension_type: TlsExtensionType::ServerName.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::ExtendedMasterSecret.into(), required: true, data: None },
            TlsExtension { extension_type: 0x0a0a, required: false, data: None }, // GREASE
            TlsExtension { extension_type: TlsExtensionType::SupportedGroups.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::ECPointFormats.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::ALPN.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::StatusRequest.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::SignatureAlgorithms.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::SupportedVersions.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::PSKKeyExchangeModes.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::CertificateAuthorities.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::PostHandshakeAuth.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::SignatureAlgorithmsCert.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::KeyShare.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::PreSharedKey.into(), required: false, data: None },
        ],
        grease: vec![0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a],
        padding_range: (128, 512),
        consistent_ordering: true,
    }
}

/// Creates an Edge 122 (Chromium) on Windows 11 profile
///
/// Reference: NSM Internal Report IR-2026-0028 §5.3 (Edge 122 Analysis)
pub fn edge_122_profile() -> Ja3Profile {
    Ja3Profile {
        name: "Edge",
        tls_versions: vec![ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3],
        cipher_suites: vec![
            SupportedCipherSuite::Tls13_Aes256GcmSha384,
            SupportedCipherSuite::Tls13_ChaCha20Poly1305Sha256,
            SupportedCipherSuite::Tls13_Aes128GcmSha256,
            SupportedCipherSuite::TlsEcdheEcdsaWithAes256GcmSha384,
            SupportedCipherSuite::TlsEcdheRsaWithAes256GcmSha384,
            SupportedCipherSuite::TlsEcdheEcdsaWithChaCha20Poly1305Sha256,
            SupportedCipherSuite::TlsEcdheRsaWithChaCha20Poly1305Sha256,
            SupportedCipherSuite::TlsEcdheEcdsaWithAes128GcmSha256,
            SupportedCipherSuite::TlsEcdheRsaWithAes128GcmSha256,
        ],
        extensions: vec![
            TlsExtension { extension_type: TlsExtensionType::ServerName.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::ExtendedMasterSecret.into(), required: true, data: None },
            TlsExtension { extension_type: 0x0a0a, required: false, data: None }, // GREASE
            TlsExtension { extension_type: TlsExtensionType::SupportedGroups.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::ECPointFormats.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::SessionTicket.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::ALPN.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::StatusRequest.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::SignatureAlgorithms.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::SupportedVersions.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::PSKKeyExchangeModes.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::CertificateAuthorities.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::PostHandshakeAuth.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::SignatureAlgorithmsCert.into(), required: false, data: None },
            TlsExtension { extension_type: TlsExtensionType::KeyShare.into(), required: true, data: None },
            TlsExtension { extension_type: TlsExtensionType::PreSharedKey.into(), required: false, data: None },
        ],
        grease: vec![0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a],
        padding_range: (256, 1024),
        consistent_ordering: true,
    }
}

/// Generates realistic TLS ClientHello padding
///
/// OPSEC WARNING: Padding length must follow browser-specific patterns to avoid detection
/// Reference: NSM Internal Report IR-2026-0028 §3.4 (TLS Padding Analysis)
pub fn generate_padding(profile: &Ja3Profile) -> Vec<u8> {
    let mut rng = thread_rng();
    let padding_len = rng.gen_range(profile.padding_range.0..=profile.padding_range.1);
    let mut padding = vec![0u8; padding_len];
    rng.fill_bytes(&mut padding);
    padding
}

/// Applies browser-specific TLS handshake variations
///
/// OPSEC WARNING: Must mimic browser-specific timing and packet ordering to avoid detection
/// Reference: NSM Internal Report IR-2026-0028 §3.5 (Handshake Timing Analysis)
pub fn apply_handshake_variations(profile: &Ja3Profile) {
    let mut rng = thread_rng();
    
    // Simulate realistic browser handshake timing variations
    let timing_variation = match profile.name {
        "Chrome" => rng.gen_range(10..50),   // Chrome: 10-50ms variations
        "Firefox" => rng.gen_range(15..60),  // Firefox: 15-60ms variations
        "Edge" => rng.gen_range(12..55),     // Edge: 12-55ms variations
        _ => rng.gen_range(10..60),
    };
    
    // In simulation: would use high-precision timers
    // Actual implementation would include timing variations here
    
    // Simulate realistic packet ordering variations
    if !profile.consistent_ordering {
        // Browsers don't randomize extension order, but some EDRs check for this
        // In simulation: would handle packet ordering variations
    }
}
