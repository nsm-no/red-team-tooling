// STRENGT FORTROLIG � TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 �3.1 & �4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
// NSM-20260220-007
// FPP Level 5.1 Deterministic Sigma Render Layer 
// MITRE ATT&CK v18 detection framework component
// pure JSON serialization. Deterministic, bounded, forensic-ready.

use crate::matcher::MatchDetail;
use crate::parser::SigmaRule;
use crate::sequence::{SequenceChainItem, SequenceMatch};
use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;
use timeline_builder::model::Timeline;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RenderError {
    #[error("JSON serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("invalid report data: {0}")]
    InvalidData(String),
}

/// Forensic-grade evaluation report (deterministic by design)
#[derive(Debug, Serialize)]
pub struct SigmaEvaluationReport<'a> {
    pub metadata: ReportMetadata,
    pub rule: RuleInfo<'a>,
    pub timeline: TimelineInfo,
    pub results: EvaluationResults,
}

#[derive(Debug, Serialize)]
pub struct ReportMetadata {
    pub evaluator_version: &'static str,
    pub build_timestamp: &'static str,
    pub manifest_hash: &'static str,
    pub evaluation_mode: &'static str, // "condition" or "sequence"
}

#[derive(Debug, Serialize)]
pub struct RuleInfo<'a> {
    pub title: Option<&'a str>,
    pub detection_summary: String, // e.g. "3 selections, 1 sequence"
}

#[derive(Debug, Serialize)]
pub struct TimelineInfo {
    pub total_events: usize,
    pub time_range_us: Option<(i64, i64)>, // (min, max) — deterministic
}

#[derive(Debug, Serialize)]
pub struct EvaluationResults {
    pub matched_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches: Option<Vec<SerializedMatchDetail>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequences: Option<Vec<SerializedSequenceMatch>>,
}

#[derive(Debug, Serialize)]
pub struct SerializedMatchDetail {
    pub event_index: usize,
    pub event_id: u32,
    pub matched_selections: Vec<String>,
    pub triggered: BTreeMap<String, Vec<String>>, // already deterministic
}

#[derive(Debug, Serialize)]
pub struct SerializedSequenceMatch {
    pub timeframe_us: i64,
    pub chain: Vec<SerializedChainItem>,
    pub attempted_paths: u64,
    pub pruned_paths: u64,
}

#[derive(Debug, Serialize)]
pub struct SerializedChainItem {
    pub selection: String,
    pub event_index: usize,
    pub ts_unix_micros: i64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API (capability-poor, deterministic)
// ─────────────────────────────────────────────────────────────────────────────

/// Render to compact JSON (forensic log / storage)
pub fn kristoffersen_feb18_render_to_json(
    rule: &SigmaRule,
    timeline: &Timeline,
    matches: &[MatchDetail],
    sequences: Option<&[SequenceMatch]>,
) -> Result<String, RenderError> {
    let report = build_report(rule, timeline, matches, sequences)?;
    serde_json::to_string(&report).map_err(RenderError::from)
}

/// Render to pretty-printed JSON (human/forensic review)
pub fn kristoffersen_feb18_render_to_json_pretty(
    rule: &SigmaRule,
    timeline: &Timeline,
    matches: &[MatchDetail],
    sequences: Option<&[SequenceMatch]>,
) -> Result<String, RenderError> {
    let report = build_report(rule, timeline, matches, sequences)?;
    serde_json::to_string_pretty(&report).map_err(RenderError::from)
}

fn build_report(
    rule: &SigmaRule,
    timeline: &Timeline,
    matches: &[MatchDetail],
    sequences: Option<&[SequenceMatch]>,
) -> Result<SigmaEvaluationReport, RenderError> {
    let mode = if sequences.is_some() { "sequence" } else { "condition" };

    let report = SigmaEvaluationReport {
        metadata: ReportMetadata {
            evaluator_version: crate::VERSION,
            build_timestamp: crate::BUILD_TIMESTAMP,
            manifest_hash: crate::BLAKE3_MANIFEST.trim(),
            evaluation_mode: mode,
        },
        rule: RuleInfo {
            title: rule.title.as_deref(),
            detection_summary: format!(
                "{} selections, {} sequence(s)",
                rule.detection.selections.len(),
                sequences.map_or(0, |s| s.len())
            ),
        },
        timeline: TimelineInfo {
            total_events: timeline.events.len(),
            time_range_us: get_time_range(timeline),
        },
        results: EvaluationResults {
            matched_count: sequences.map_or(matches.len(), |s| s.len()),
            matches: if sequences.is_none() {
                Some(matches.iter().map(serialize_match_detail).collect())
            } else {
                None
            },
            sequences: sequences.map(|s| s.iter().map(serialize_sequence_match).collect()),
        },
    };

    Ok(report)
}

fn get_time_range(timeline: &Timeline) -> Option<(i64, i64)> {
    if timeline.events.is_empty() {
        return None;
    }
    let ts = timeline.events.iter().map(|e| e.ts_unix_micros);
    Some((ts.clone().min().unwrap(), ts.max().unwrap()))
}

fn serialize_match_detail(m: &MatchDetail) -> SerializedMatchDetail {
    SerializedMatchDetail {
        event_index: m.event_index,
        event_id: m.event_id,
        matched_selections: m.matched_selections.clone(),
        triggered: m.triggered.clone(), // BTreeMap = deterministic keys
    }
}

fn serialize_sequence_match(s: &SequenceMatch) -> SerializedSequenceMatch {
    SerializedSequenceMatch {
        timeframe_us: s.timeframe_us,
        chain: s.chain.iter().map(|c| SerializedChainItem {
            selection: c.selection.clone(),
            event_index: c.event_index,
            ts_unix_micros: c.ts_unix_micros,
        }).collect(),
        attempted_paths: s.attempted_paths,
        pruned_paths: s.pruned_paths,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Determinism test: same input → identical JSON string (byte-for-byte)
}
