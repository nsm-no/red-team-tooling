// STRENGT FORTROLIG – TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 §3.1 & §4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
pub mod structural_invariants;

pub use etw_patch_sim::{
    EtwFunctionBuffer,
    PatchError,
    IntegrityStatus,
    ExecutionFlow,
    DetectionAlert,
    EdrDetectionSimulator,
    run_etw_patch_scenario,
};

