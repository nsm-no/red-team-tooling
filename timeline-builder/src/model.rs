// STRENGT FORTROLIG – TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 §3.1 & §4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
// timeline-builder/src/model.rs
// NSM-20260218-002
#![allow(clippy::large_enum_variant)]

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostId {
    WorkstationA,
    ServerB,
    DomainController,
}

impl HostId {
    pub fn as_str(&self) -> &'static str {
        match self {
            HostId::WorkstationA => "HOST-A",
            HostId::ServerB => "HOST-B",
            HostId::DomainController => "HOST-DC1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Correlation {
    pub process_guid: Option<String>,  // synthetic GUID-like
    pub parent_process_guid: Option<String>,
    pub logon_id: Option<String>,      // synthetic hex-like
    pub activity_id: Option<String>,   // optional synthetic GUID-like
}

impl Correlation {
    pub fn empty() -> Self {
        Self {
            process_guid: None,
            parent_process_guid: None,
            logon_id: None,
            activity_id: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TimelineEvent {
    pub host: HostId,
    /// Monotonic timestamp in Unix microseconds (UTC). (Deterministic; no wall-clock used.)
    pub ts_unix_micros: i64,
    pub event_id: u32,
    pub correlation: Correlation,
    pub fields: Vec<(String, String)>, // explicit EventData fields (Name, Value)
}

impl TimelineEvent {
    pub fn field(mut self, name: &str, value: impl Into<String>) -> Self {
        self.fields.push((name.to_string(), value.into()));
        self
    }
}

#[derive(Debug, Clone)]
pub struct Timeline {
    pub scenario_id: String,
    pub seed: u64,
    pub scenario_seed: u64,
    pub events: Vec<TimelineEvent>,
}

impl Timeline {
    pub fn kristoffersen_feb18_validate_invariants(&self) -> Result<(), TimelineBuildError> {
        // 1) Monotonic timestamps
        for w in self.events.windows(2) {
            if w[0].ts_unix_micros >= w[1].ts_unix_micros {
                return Err(TimelineBuildError::InvariantViolation(
                    "timestamps not strictly increasing".to_string(),
                ));
            }
        }

        // 2) Correlation closure (basic): parent before child when parent GUID referenced
        use std::collections::HashSet;
        let mut seen_process = HashSet::<String>::new();

        for e in &self.events {
            if let Some(parent) = &e.correlation.parent_process_guid {
                if !seen_process.contains(parent) {
                    return Err(TimelineBuildError::InvariantViolation(format!(
                        "parent process_guid not seen before use: {}",
                        parent
                    )));
                }
            }
            if let Some(pg) = &e.correlation.process_guid {
                seen_process.insert(pg.clone());
            }
        }

        // 3) At least 10 events (requirement)
        if self.events.len() < 10 {
            return Err(TimelineBuildError::InvariantViolation(
                "timeline must include at least 10 events".to_string(),
            ));
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum TimelineBuildError {
    InvalidConfig(String),
    UnknownScenario(String),
    InvalidParams(String),
    InvariantViolation(String),
}

impl fmt::Display for TimelineBuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimelineBuildError::InvalidConfig(s) => write!(f, "invalid config: {}", s),
            TimelineBuildError::UnknownScenario(s) => write!(f, "unknown scenario: {}", s),
            TimelineBuildError::InvalidParams(s) => write!(f, "invalid params: {}", s),
            TimelineBuildError::InvariantViolation(s) => write!(f, "invariant violation: {}", s),
        }
    }
}

impl std::error::Error for TimelineBuildError {}

