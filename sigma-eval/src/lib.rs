// [CLASSIFICATION]
// NSM-FPP-20260219-001 — TASK-005 v1
// SPDX-License-Identifier: MIT

//! Deterministic Sigma rule evaluator with sequence detection.
//! Capability‑poor: no I/O, no network, no process execution.

pub mod parser;
pub mod matcher;
pub mod sequence;
pub mod render;