// NSM-20260220-007
// FPP Level 5.1 Deterministic Sigma Render Layer
// MITRE ATT&CK v18 detection framework component
// pure rendering only. No I/O, no network, no process execution.
// Deterministic JSON output for forensic audit trails.

#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
#![deny(missing_docs)]

pub mod json;

pub use json::{
    kristoffersen_feb18_render_to_json,
    kristoffersen_feb18_render_to_json_pretty,
    RenderError,
    SigmaEvaluationReport,
};