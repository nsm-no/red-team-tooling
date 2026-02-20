// [CLASSIFICATION]
// NSM-FPP-20260219-001 — TASK-005 v1
// SPDX-License-Identifier: MIT
// NOTE: This file is capability-poor; parsing only. No I/O, no network, no process execution.
// NSM-20260218-002
// FPP Level 5.1 Deterministic Sigma Evaluator (Hardened)
// MITRE ATT&CK v18 detection framework component
// Capability-poor parser: no I/O, no network, no process execution.

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
@@ -38,50 +38,52 @@ pub struct Detection {
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
    Base64,
    Regex,
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
@@ -200,83 +202,113 @@ fn parse_sequence_list(v: &serde_yaml::Value) -> Result<Vec<String>, String> {
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
        let (field, op) = parse_field_operator(raw_field)?;
        let values = parse_matcher_values(raw_field, v)?;

        matchers.push(FieldMatcher {
            field: field.to_string(),
            op,
            value,
        });
        for value in values {
            matchers.push(FieldMatcher {
                field: field.to_string(),
                op: op.clone(),
                value,
            });
        }
    }

    // Deterministic ordering: sort by (field, op, value)
    matchers.sort_by(|a, b| {
        (a.field.as_str(), op_rank(&a.op), a.value.as_str())
            .cmp(&(b.field.as_str(), op_rank(&b.op), b.value.as_str()))
    });

    Ok(Selection { matchers })
}

fn parse_field_operator(raw: &str) -> (&str, MatchOp) {
fn parse_field_operator(raw: &str) -> Result<(&str, MatchOp), String> {
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
            "base64" => MatchOp::Base64,
            "re" => MatchOp::Regex,
            "" => MatchOp::Equals,
            other => {
                return Err(format!(
                    "unsupported field operator '{}' in matcher '{}'",
                    other, raw
                ))
            }
        };
        (field, op)
        Ok((field, op))
    } else {
        Ok((raw, MatchOp::Equals))
    }
}

fn parse_matcher_values(raw_field: &str, v: &serde_yaml::Value) -> Result<Vec<String>, String> {
    if let Some(seq) = v.as_sequence() {
        let mut out: Vec<String> = Vec::with_capacity(seq.len());
        for item in seq {
            out.push(coerce_scalar(raw_field, item)?);
        }
        if out.is_empty() {
            return Err(format!("matcher list for field '{}' cannot be empty", raw_field));
        }
        return Ok(out);
    }

    Ok(vec![coerce_scalar(raw_field, v)?])
}

fn coerce_scalar(raw_field: &str, v: &serde_yaml::Value) -> Result<String, String> {
    if let Some(s) = v.as_str() {
        Ok(s.to_string())
    } else if let Some(n) = v.as_i64() {
        Ok(n.to_string())
    } else if let Some(b) = v.as_bool() {
        Ok(b.to_string())
    } else {
        (raw, MatchOp::Equals)
        Err(format!(
            "unsupported matcher value type for field {} (use scalar or scalar list)",
            raw_field
        ))
    }
}

fn op_rank(op: &MatchOp) -> u8 {
    match op {
        MatchOp::Equals => 0,
        MatchOp::Contains => 1,
        MatchOp::StartsWith => 2,
        MatchOp::EndsWith => 3,
        MatchOp::Base64 => 4,
        MatchOp::Regex => 5,
    }
}
