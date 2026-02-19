// [CLASSIFICATION]
// NSM-FPP-20260219-001 — TASK-005 v1
// SPDX-License-Identifier: MIT
// NOTE: This file is capability-poor; parsing only. No I/O, no network, no process execution.

use serde::Deserialize;
use std::collections::BTreeMap;

/// Minimal Sigma YAML representation for deterministic defensive regression testing.
#[derive(Debug, Clone)]
pub struct SigmaRule {
    pub title: Option<String>,
    pub logsource: Option<LogSource>,
    pub detection: Detection,
}

#[derive(Debug, Clone)]
pub struct LogSource {
    pub product: Option<String>,
    pub service: Option<String>,
    pub category: Option<String>,
}

/// Detection block.
/// Backward compatible:
/// - If `sequence` is None, `condition` MUST be Some(...) and evaluation uses boolean condition logic.
/// - If `sequence` is Some(...), evaluation uses sequence logic; `condition` may be None or present (ignored in v1).
#[derive(Debug, Clone)]
pub struct Detection {
    /// Named selections (e.g., "selection", "sel1", ...)
    pub selections: BTreeMap<String, Selection>,
    /// Boolean condition expression string (legacy). Required if `sequence` is None.
    pub condition: Option<String>,
    /// Optional sequence specification.
    pub sequence: Option<SequenceSpec>,
}

/// Sequence specification parsed from:
/// detection:
///   sequence:
///     - selection1
///     - selection2
///   timeframe: 5s
#[derive(Debug, Clone)]
pub struct SequenceSpec {
    pub steps: Vec<String>,
    /// Raw timeframe string; parsed into microseconds by sequence evaluator.
    pub timeframe: String,
}

#[derive(Debug, Clone)]
pub struct Selection {
    /// AND semantics within a selection: all matchers must hold.
    pub matchers: Vec<FieldMatcher>,
}

#[derive(Debug, Clone)]
pub enum MatchOp {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
}

#[derive(Debug, Clone)]
pub struct FieldMatcher {
    pub field: String,
    pub op: MatchOp,
    pub value: String,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    title: Option<String>,
    logsource: Option<RawLogSource>,
    detection: serde_yaml::Value,
}

#[derive(Debug, Deserialize)]
struct RawLogSource {
    product: Option<String>,
    service: Option<String>,
    category: Option<String>,
}

/// Parse Sigma YAML into internal model.
///
/// Supported (legacy):
/// - detection: { <selection_name>: { Field: value, Field|contains: value }, condition: "..." }
///
/// Supported (sequence extension):
/// - detection:
///     selection1: { ... }
///     selection2: { ... }
///     sequence:
///       - selection1
///       - selection2
///     timeframe: 5s
pub fn kristoffersen_feb18_parse_sigma_rule(yaml: &str) -> Result<SigmaRule, String> {
    let raw: RawRule = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;

    let logsource = raw.logsource.map(|ls| LogSource {
        product: ls.product,
        service: ls.service,
        category: ls.category,
    });

    let detection = parse_detection(raw.detection)?;

    Ok(SigmaRule {
        title: raw.title,
        logsource,
        detection,
    })
}

fn parse_detection(val: serde_yaml::Value) -> Result<Detection, String> {
    let mapping = val
        .as_mapping()
        .ok_or_else(|| "detection must be a YAML mapping".to_string())?;

    let mut selections: BTreeMap<String, Selection> = BTreeMap::new();
    let mut condition: Option<String> = None;

    let mut seq_steps: Option<Vec<String>> = None;
    let mut seq_timeframe: Option<String> = None;

    for (k, v) in mapping.iter() {
        let key = k
            .as_str()
            .ok_or_else(|| "detection keys must be strings".to_string())?
            .to_string();

        match key.as_str() {
            "condition" => {
                condition = Some(
                    v.as_str()
                        .ok_or_else(|| "condition must be a string".to_string())?
                        .to_string(),
                );
            }
            "sequence" => {
                seq_steps = Some(parse_sequence_list(v)?);
            }
            "timeframe" => {
                seq_timeframe = Some(
                    v.as_str()
                        .ok_or_else(|| "timeframe must be a string (e.g., 5s, 500ms, 1m)".to_string())?
                        .to_string(),
                );
            }
            _ => {
                // Selection entry
                let sel = parse_selection(&key, v)?;
                selections.insert(key, sel);
            }
        }
    }

    if selections.is_empty() {
        return Err("detection must contain at least one selection".to_string());
    }

    let sequence = match (seq_steps, seq_timeframe) {
        (None, None) => None,
        (Some(steps), Some(tf)) => {
            if steps.is_empty() {
                return Err("detection.sequence must contain at least one step".to_string());
            }
            // Validate all referenced steps exist as selections
            for s in &steps {
                if !selections.contains_key(s) {
                    return Err(format!(
                        "detection.sequence references unknown selection: {}",
                        s
                    ));
                }
            }
            Some(SequenceSpec { steps, timeframe: tf })
        }
        (Some(_), None) => return Err("detection.timeframe is required when detection.sequence is present".to_string()),
        (None, Some(_)) => return Err("detection.sequence is required when detection.timeframe is present".to_string()),
    };

    // Backward compatibility:
    // - If no sequence, condition is required.
    if sequence.is_none() && condition.is_none() {
        return Err("detection.condition is required when no detection.sequence is present".to_string());
    }

    Ok(Detection {
        selections,
        condition,
        sequence,
    })
}

fn parse_sequence_list(v: &serde_yaml::Value) -> Result<Vec<String>, String> {
    let seq = v
        .as_sequence()
        .ok_or_else(|| "detection.sequence must be a YAML list of selection names".to_string())?;

    let mut out: Vec<String> = Vec::with_capacity(seq.len());
    for item in seq {
        let s = item
            .as_str()
            .ok_or_else(|| "detection.sequence items must be strings".to_string())?;
        out.push(s.to_string());
    }
    Ok(out)
}

fn parse_selection(_name: &str, v: &serde_yaml::Value) -> Result<Selection, String> {
    let mapping = v
        .as_mapping()
        .ok_or_else(|| "selection must be a mapping of field matchers".to_string())?;

    let mut matchers: Vec<FieldMatcher> = Vec::new();

    for (k, v) in mapping.iter() {
        let raw_field = k
            .as_str()
            .ok_or_else(|| "selection field keys must be strings".to_string())?;

        let (field, op) = parse_field_operator(raw_field);

        let value = if let Some(s) = v.as_str() {
            s.to_string()
        } else if let Some(n) = v.as_i64() {
            n.to_string()
        } else if let Some(b) = v.as_bool() {
            b.to_string()
        } else {
            return Err(format!(
                "unsupported matcher value type for field {} (use string/number/bool)",
                raw_field
            ));
        };

        matchers.push(FieldMatcher {
            field: field.to_string(),
            op,
            value,
        });
    }

    // Deterministic ordering: sort by (field, op, value)
    matchers.sort_by(|a, b| {
        (a.field.as_str(), op_rank(&a.op), a.value.as_str())
            .cmp(&(b.field.as_str(), op_rank(&b.op), b.value.as_str()))
    });

    Ok(Selection { matchers })
}

fn parse_field_operator(raw: &str) -> (&str, MatchOp) {
    // Examples:
    //   "CommandLine|contains"
    //   "Image|startswith"
    //   "ParentImage|endswith"
    //   "EventID"
    if let Some((field, op)) = raw.split_once('|') {
        let op = match op {
            "contains" => MatchOp::Contains,
            "startswith" => MatchOp::StartsWith,
            "endswith" => MatchOp::EndsWith,
            _ => MatchOp::Equals, // conservative fallback for backward compatibility
        };
        (field, op)
    } else {
        (raw, MatchOp::Equals)
    }
}

fn op_rank(op: &MatchOp) -> u8 {
    match op {
        MatchOp::Equals => 0,
        MatchOp::Contains => 1,
        MatchOp::StartsWith => 2,
        MatchOp::EndsWith => 3,
    }
}
