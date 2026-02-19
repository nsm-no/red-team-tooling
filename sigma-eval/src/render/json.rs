// [CLASSIFICATION]
// NSM-FPP-20260219-001 — TASK-005 v1
// SPDX-License-Identifier: MIT
// NOTE: This file is capability-poor; pure rendering. No I/O, no network, no process execution.

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

#[derive(Debug, Serialize)]
struct JsonMatch<'a> {
    event_index: usize,
    event_id: u32,
    ts_unix_micros: i64,

    matched_selections: Vec<&'a str>,

    /// selection -> list of "Field Op Value" strings (deterministic)
    triggered: BTreeMap<&'a str, Vec<&'a str>>,
}

#[derive(Debug, Serialize)]
struct JsonSequence<'a> {
    timeframe_us: i64,
    chain: Vec<JsonSequenceItem<'a>>,
}

#[derive(Debug, Serialize)]
struct JsonSequenceItem<'a> {
    selection: &'a str,
    event_index: usize,
    ts_unix_micros: i64,
}

/// Render evaluation result as deterministic JSON.
/// - Stable ordering is guaranteed by upstream evaluation (sorted matches, sorted selection names)
/// - Trigger maps are rendered as sorted key order via BTreeMap
pub fn kristoffersen_feb18_render_eval_json(
    rule: &SigmaRule,
    timeline: &Timeline,
    result: &EvalResult,
) -> Result<String, String> {
    let rule_title = rule.title.as_deref();
    let mode = result.mode.as_str();

    let mut out_matches: Vec<JsonMatch<'_>> = Vec::with_capacity(result.matches.len());
    for m in &result.matches {
        let ts = timeline
            .events
            .get(m.event_index)
            .ok_or_else(|| "render error: match event_index out of bounds".to_string())?
            .ts_unix_micros;

        // matched selections as &str, stable ordering already enforced upstream
        let matched_selections: Vec<&str> = m.matched_selections.iter().map(|s| s.as_str()).collect();

        // triggered: BTreeMap<&str, Vec<&str>> in sorted key order
        let mut trig_map: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (sel, triggers) in &m.triggered {
            let mut v: Vec<&str> = triggers.iter().map(|t| t.as_str()).collect();
            v.sort(); // deterministic
            trig_map.insert(sel.as_str(), v);
        }

        out_matches.push(JsonMatch {
            event_index: m.event_index,
            event_id: m.event_id,
            ts_unix_micros: ts,
            matched_selections,
            triggered: trig_map,
        });
    }

    // Ensure deterministic sort of matches by (ts, index)
    out_matches.sort_by(|a, b| (a.ts_unix_micros, a.event_index).cmp(&(b.ts_unix_micros, b.event_index)));

    let sequence = result.sequence.as_ref().map(|s| sequence_to_json(s));

    let output = JsonOutput {
        rule_title,
        mode,

        scenario_id: timeline.scenario_id.as_str(),
        seed: timeline.seed,
        scenario_seed: timeline.scenario_seed,

        total_events: result.total_events,
        matched_events: result.matched_events,
        match_rate: result.match_rate,

        matches: out_matches,
        sequence,
    };

    serde_json::to_string_pretty(&output).map_err(|e| e.to_string())
}

fn sequence_to_json(s: &SequenceMatch) -> JsonSequence<'_> {
    let mut chain: Vec<JsonSequenceItem<'_>> = Vec::with_capacity(s.chain.len());
    for item in &s.chain {
        chain.push(JsonSequenceItem {
            selection: item.selection.as_str(),
            event_index: item.event_index,
            ts_unix_micros: item.ts_unix_micros,
        });
    }
    JsonSequence {
        timeframe_us: s.timeframe_us,
        chain,
    }
}
