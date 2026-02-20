// NSM-20260218-002
// FPP Level 5.1 Deterministic Sigma Evaluator (Hardened)
// MITRE ATT&CK v18 detection framework component

use crate::matcher::{EvalResult, SequenceMatch};
use crate::parser::SigmaRule;
use serde::Serialize;
use std::collections::BTreeMap;
use timeline_builder::model::Timeline;

#[derive(Debug, Serialize)]
struct JsonOutput<'a> {
    rule_title: Option<&'a str>,
    mode: &'a str,

    scenario_id: &'a str,
    seed: u64,
    scenario_seed: u64,

    total_events: usize,
    matched_events: usize,
    match_rate: f64,

    matches: Vec<JsonMatch<'a>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    sequence: Option<JsonSequence<'a>>,
}
