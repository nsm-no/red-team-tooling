// STRENGT FORTROLIG – TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Module: tls_config.rs (Production Simulation)
// Purpose: Configuration utilities for TLS tunneling
// References:
//   - NSM Internal Report IR-2026-0027 (TLS Configuration Guidelines)
//
// OPSEC WARNINGS:
//   - Configuration parameters must be randomized to avoid detection patterns
//   - Hardcoded JA3 fingerprints can be detected if not updated regularly
//   - THIS IS A SIMULATION HARNESS IMPLEMENTATION – FOR TRAINING USE ONLY
//   - NO LIVE SYSTEM INTERACTION. NO REAL BYPASS PRIMITIVES.
//
// Verification: ./verify_authority --mandate NSM-mandate-2026 --toolset tls-tunnel

use super::{TlsConfig, CertPinningConfig};

/// Creates a default TLS configuration for simulation purposes
///
/// OPSEC WARNING: Default configurations must be randomized in operational scenarios
/// Reference: NSM Internal Report IR-2026-0027 §4.1 (Configuration Security)
pub fn default_config() -> TlsConfig {
    TlsConfig {
        domains: vec![
            "telemetry.example.com".to_string(),
            "analytics.example.net".to_string(),
            "metrics.example.org".to_string(),
        ],
        fronting_domains: vec![
            "cloudflare-workers.com".to_string(),
            "cloudfront.net".to_string(),
            "akamaiedge.net".to_string(),
            "azureedge.net".to_string(),
        ],
        master_key: random_key(), // Randomly generated for each session
        min_jitter: 1000,        // 1 second
        max_jitter: 30000,       // 30 seconds
        heartbeat_interval: (30, 300), // 30-300 seconds
        burst_mode: (5, std::time::Duration::from_secs(60)), // 5 requests, then 60s pause
        use_http2: true,
        timeout: 10, // 10 seconds
        enable_fronting: true,
        cert_pinning: None, // In operational version: would include pinning config
    }
}

/// Creates a production-grade TLS configuration
///
/// OPSEC WARNING: Production configurations must include certificate pinning
/// Reference: NSM Internal Report IR-2026-0027 §5.2 (Production Configuration)
pub fn production_config(c2_domains: Vec<String>, fronting_domains: Vec<String>) -> TlsConfig {
    TlsConfig {
        domains: c2_domains,
        fronting_domains,
        master_key: random_key(),
        min_jitter: 500,         // 0.5 seconds
        max_jitter: 15000,       // 15 seconds
        heartbeat_interval: (45, 240), // 45-240 seconds
        burst_mode: (4, std::time::Duration::from_secs(45)), // 4 requests, then 45s pause
        use_http2: true,
        timeout: 8, // 8 seconds
        enable_fronting: true,
        cert_pinning: Some(CertPinningConfig {
            allowed_hashes: vec![
                // Example SHA-256 hashes (would be real in operational version)
                [0u8; 32],
                [1u8; 32],
            ],
            allow_fallback: false,
        }),
    }
}

/// Generates a random encryption key
fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}