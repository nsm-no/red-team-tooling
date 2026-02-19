//! winlog-synth – Synthetic Windows Event Log generator
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