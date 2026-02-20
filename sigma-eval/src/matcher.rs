// NSM-20260218-002
// FPP Level 5.1 Deterministic Sigma Evaluator (Hardened)
// MITRE ATT&CK v18 detection framework component
// Capability-poor evaluator: no I/O, no network, no process execution.

use crate::parser::{Detection, FieldMatcher, MatchOp, SigmaRule};
use crate::sequence::{
    kristoffersen_feb18_find_sequence_chain, kristoffersen_feb18_parse_timeframe_to_us,
};
use timeline_builder::model::{Timeline, TimelineEvent};

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

#[cfg(feature = "full")]
use lazy_static::lazy_static;
#[cfg(feature = "full")]
use regex::Regex;
#[cfg(feature = "full")]
use std::sync::RwLock;

#[cfg(feature = "full")]
lazy_static! {
    static ref REGEX_CACHE: RwLock<BTreeMap<String, Regex>> = RwLock::new(BTreeMap::new());
}

#[derive(Debug, Clone)]
pub struct SequenceChainItem {
    pub selection: String,
    pub event_index: usize,
    pub ts_unix_micros: i64,
}

#[derive(Debug, Clone)]
pub struct SequenceMatch {
    pub timeframe_us: i64,
    pub chain: Vec<SequenceChainItem>,
}

#[derive(Debug, Clone)]
pub struct MatchDetail {
    pub event_index: usize,
    pub event_id: u32,
    /// Selections that evaluated true for this event in condition-mode,
    /// or the single sequence step selection name in sequence-mode.
    pub matched_selections: Vec<String>,
    /// selection -> list of "Field Op Value" strings (deterministic order)
    pub triggered: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
@@ -287,83 +299,116 @@ fn selection_matches(ev: &TimelineEvent, matchers: &[FieldMatcher]) -> (bool, Ve
    // AND semantics within selection
    let mut triggered: Vec<String> = Vec::new();
    for m in matchers {
        let ok = matcher_matches(ev, m);
        if !ok {
            return (false, Vec::new());
        }
        triggered.push(format!("{} {:?} {}", m.field, m.op, m.value));
    }
    (true, triggered)
}

fn matcher_matches(ev: &TimelineEvent, m: &FieldMatcher) -> bool {
    let field = m.field.as_str();
    let want = m.value.to_lowercase();

    // Special built-ins
    if field.eq_ignore_ascii_case("EventID") {
        let got = ev.event_id.to_string();
        let got = got.to_lowercase();
        return match m.op {
            MatchOp::Equals => got == want,
            MatchOp::Contains => got.contains(&want),
            MatchOp::StartsWith => got.starts_with(&want),
            MatchOp::EndsWith => got.ends_with(&want),
            MatchOp::Base64 => got.contains(&want),
            MatchOp::Regex => regex_is_match(&got, &m.value),
        };
    }

    if field.eq_ignore_ascii_case("Computer") || field.eq_ignore_ascii_case("Host") {
        let got = ev.host.as_str().to_lowercase();
        return match m.op {
            MatchOp::Equals => got == want,
            MatchOp::Contains => got.contains(&want),
            MatchOp::StartsWith => got.starts_with(&want),
            MatchOp::EndsWith => got.ends_with(&want),
            MatchOp::Base64 => got.contains(&want),
            MatchOp::Regex => regex_is_match(&got, &m.value),
        };
    }

    // Look up in EventData fields
    let got_opt = ev
        .fields
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(field))
        .map(|(_, v)| v);

    let got = match got_opt {
        Some(v) => v.to_lowercase(),
        None => return false,
    };

    match m.op {
        MatchOp::Equals => got == want,
        MatchOp::Contains => got.contains(&want),
        MatchOp::StartsWith => got.starts_with(&want),
        MatchOp::EndsWith => got.ends_with(&want),
        MatchOp::Base64 => got.contains(&want),
        MatchOp::Regex => regex_is_match(&got, &m.value),
    }
}

#[cfg(feature = "full")]
fn regex_is_match(value: &str, pattern: &str) -> bool {
    let cached = REGEX_CACHE
        .read()
        .ok()
        .and_then(|cache| cache.get(pattern).cloned());
    let regex = match cached {
        Some(re) => re,
        None => {
            let compiled = match Regex::new(pattern) {
                Ok(r) => r,
                Err(_) => return false,
            };
            if let Ok(mut cache) = REGEX_CACHE.write() {
                cache.insert(pattern.to_string(), compiled.clone());
            }
            compiled
        }
    };
    regex.is_match(value)
}

#[cfg(not(feature = "full"))]
fn regex_is_match(_value: &str, _pattern: &str) -> bool {
    false
}

/* ---------------- Condition parsing (and/or + parentheses) ---------------- */

#[derive(Debug, Clone)]
enum CondToken {
    Sel(String),
    And,
    Or,
}

/// Tokenize condition into identifiers/operators/parens.
fn tokenize_condition(cond: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();

    let flush = |cur: &mut String, out: &mut Vec<String>| {
        if !cur.is_empty() {
            out.push(cur.clone());
            cur.clear();
        }
    };

    for ch in cond.chars() {
        match ch {
            '(' | ')' => {
                flush(&mut cur, &mut out);
