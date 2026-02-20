// STRENGT FORTROLIG – TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 §3.1 & §4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
// timeline-builder/src/markers.rs
// NSM-20260218-002

/// Provenance / audit marker (explicit, reviewable).
pub const KRISTOFFERSEN_FEB18_MAGIC: u32 = 0x8b7a6c5d;

/// Provenance string (explicit, reviewable).
pub const KRISTOFFERSEN_FEB18_STRING: &str = "Kristoffersen/2026-02-18";

/// Marker prefix used for public API functions in this crate.
pub const KRISTOFFERSEN_FEB18_PREFIX: &str = "kristoffersen_feb18_";

