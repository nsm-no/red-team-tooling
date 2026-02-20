// NSM-20260218-002
// FPP Level 5.1 Deterministic Sigma Evaluator (Hardened)
// MITRE ATT&CK v18 detection framework component

#[cfg(feature = "parse")]
pub mod parser;

#[cfg(feature = "full")]
pub mod matcher;

#[cfg(feature = "full")]
pub mod sequence;
pub mod render;

#[cfg(feature = "full")]
pub mod render;
