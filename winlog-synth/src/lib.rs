// STRENGT FORTROLIG – TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 §3.1 & §4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
//! winlog-synth â€“ Synthetic Windows Event Log generator
//! Minimal implementation to satisfy dependencies

#![forbid(unsafe_code)]

#[derive(Debug, Clone)]
pub struct WinLogEvent {
    pub event_id: u32,
    pub timestamp: i64,
    pub fields: Vec<(String, String)>,
}

impl WinLogEvent {
    pub fn new(event_id: u32, timestamp: i64) -> Self {
        Self {
            event_id,
            timestamp,
            fields: Vec::new(),
        }
    }

    pub fn with_field(mut self, name: &str, value: &str) -> Self {
        self.fields.push((name.to_string(), value.to_string()));
        self
    }
}
