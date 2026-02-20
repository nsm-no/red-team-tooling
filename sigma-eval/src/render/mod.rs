// STRENGT FORTROLIG – TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 §3.1 & §4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
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
