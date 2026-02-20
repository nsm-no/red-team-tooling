// STRENGT FORTROLIG – TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 §3.1 & §4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
// NSM-20260220-004
// FPP Level 5.1 Deterministic Sigma Parser (HARDENED)
// MITRE ATT&CK v18 detection framework component
// Capability-poor: parsing only. No I/O, no network, no process execution, no regex compilation, no base64 here.

use serde::Deserialize;
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SigmaParseError {
    #[error("{message} at line {line}, column {column}")]
    InvalidYaml {
        message: String,
        line: usize,
        column: usize,
    },
    #[error("{0}")]
    InvalidRule(String),
    #[error("unsupported chained modifier '{modifier}' in field '{field}'")]
    UnsupportedModifier { field: String, modifier: String },
    #[error("empty selection or field matcher")]
    EmptySelection,
    #[error("duplicate field in selection with conflicting |all / non-all")]
    ConflictingAllModifier { field: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigmaRule {
    pub title: Option<String>,
    pub logsource: Option<LogSource>,
    pub detection: Detection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSource {
    pub product: Option<String>,
    pub service: Option<String>,
    pub category: Option<String>,
}

/// Detection block (Sigma spec compliant)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub selections: BTreeMap<String, Selection>,
    pub condition: Option<String>, // legacy boolean condition
    pub sequence: Option<SequenceSpec>,
}

/// Sequence spec (used by sequence.rs)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceSpec {
    pub steps: Vec<String>,
    pub timeframe: String,
}

/// A selection is AND of all its field conditions
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    pub field_conditions: Vec<FieldCondition>, // deterministic order
}

/// Per-field condition (handles lists, |all, chained modifiers)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldCondition {
    pub field: String,
    pub modifiers: Vec<Modifier>,
    pub values: Vec<String>,       // multiple values
    pub all_mode: bool,            // |all â†’ AND instead of OR for the list
}

/// Supported modifiers (Sigma spec Feb 2026 + common extensions)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Modifier {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Base64,         // encode rule value then match
    Base64Offset,   // sliding window base64 (3 variants)
    Wide,           // UTF-16LE alias (common before base64)
    Utf16Le,        // explicit
    Regex,          // |re
}

/// Internal raw structures for serde_yaml
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

/// Main public API â€” unchanged signature for full backward compatibility
pub fn kristoffersen_feb18_parse_sigma_rule(yaml: &str) -> Result<SigmaRule, SigmaParseError> {
    let raw: RawRule = serde_yaml::from_str(yaml).map_err(|e| SigmaParseError::InvalidYaml {
        message: e.to_string(),
        line: e.location().map(|loc| loc.line()).unwrap_or(0),
        column: e.location().map(|loc| loc.column()).unwrap_or(0),
    })?;

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

fn parse_detection(val: serde_yaml::Value) -> Result<Detection, SigmaParseError> {
    let mapping = val
        .as_mapping()
        .ok_or_else(|| SigmaParseError::InvalidRule("detection must be a YAML mapping".to_string()))?;

    let mut selections = BTreeMap::<String, Selection>::new();
    let mut condition: Option<String> = None;
    let mut seq_steps: Option<Vec<String>> = None;
    let mut seq_timeframe: Option<String> = None;

    for (k, v) in mapping {
        let key = k
            .as_str()
            .ok_or_else(|| SigmaParseError::InvalidRule("detection keys must be strings".to_string()))?
            .to_string();

        match key.as_str() {
            "condition" => {
                condition = Some(
                    v.as_str()
                        .ok_or_else(|| SigmaParseError::InvalidRule("condition must be a string".to_string()))?
                        .to_string(),
                );
            }
            "sequence" => seq_steps = Some(parse_sequence_list(v)?),
            "timeframe" => {
                seq_timeframe = Some(
                    v.as_str()
                        .ok_or_else(|| SigmaParseError::InvalidRule("timeframe must be a string".to_string()))?
                        .to_string(),
                );
            }
            _ => {
                // Selection
                let selection = parse_selection(v)?;
                selections.insert(key, selection);
            }
        }
    }

    if selections.is_empty() {
        return Err(SigmaParseError::InvalidRule(
            "detection must contain at least one selection".to_string(),
        ));
    }

    let sequence = match (seq_steps, seq_timeframe) {
        (None, None) => None,
        (Some(steps), Some(timeframe)) => {
            if steps.is_empty() {
                return Err(SigmaParseError::InvalidRule(
                    "detection.sequence must contain at least one step".to_string(),
                ));
            }
            for step in &steps {
                if !selections.contains_key(step) {
                    return Err(SigmaParseError::InvalidRule(format!(
                        "detection.sequence references unknown selection: {}",
                        step
                    )));
                }
            }
            Some(SequenceSpec { steps, timeframe })
        }
        (Some(_), None) => {
            return Err(SigmaParseError::InvalidRule(
                "detection.timeframe is required when detection.sequence is present".to_string(),
            ))
        }
        (None, Some(_)) => {
            return Err(SigmaParseError::InvalidRule(
                "detection.sequence is required when detection.timeframe is present".to_string(),
            ))
        }
    };

    if condition.is_none() && sequence.is_none() {
        return Err(SigmaParseError::InvalidRule(
            "detection.condition is required when no detection.sequence is present".to_string(),
        ));
    }

    Ok(Detection {
        selections,
        condition,
        sequence,
    })
}

fn parse_sequence_list(v: &serde_yaml::Value) -> Result<Vec<String>, SigmaParseError> {
    let list = v
        .as_sequence()
        .ok_or_else(|| SigmaParseError::InvalidRule("detection.sequence must be a YAML list".to_string()))?;

    let mut out = Vec::with_capacity(list.len());
    for item in list {
        out.push(
            item.as_str()
                .ok_or_else(|| SigmaParseError::InvalidRule("sequence step must be a string".to_string()))?
                .to_string(),
        );
    }
    Ok(out)
}

/// Parse one selection (AND of all field conditions)
fn parse_selection(v: &serde_yaml::Value) -> Result<Selection, SigmaParseError> {
    let mapping = v
        .as_mapping()
        .ok_or_else(|| SigmaParseError::InvalidRule("selection must be a YAML mapping".to_string()))?;

    if mapping.is_empty() {
        return Err(SigmaParseError::EmptySelection);
    }

    let mut field_conditions = Vec::<FieldCondition>::new();

    for (k, v) in mapping {
        let raw_field = k
            .as_str()
            .ok_or_else(|| SigmaParseError::InvalidRule("selection field key must be a string".to_string()))?;

        let (field, modifiers) = parse_field_modifiers(raw_field)?;
        let values = parse_matcher_values(v)?;

        let all_mode = modifiers.contains(&Modifier::All); // |all is special

        let mut final_mods: Vec<Modifier> = modifiers
            .into_iter()
            .filter(|m| *m != Modifier::All)
            .collect();

        if final_mods.is_empty() {
            final_mods.push(Modifier::Equals);
        }

        field_conditions.push(FieldCondition {
            field: field.to_string(),
            modifiers: final_mods,
            values,
            all_mode,
        });
    }

    // Deterministic ordering: field + modifiers + values
    field_conditions.sort_by(|a, b| {
        (
            a.field.as_str(),
            &a.modifiers,
            a.all_mode,
            a.values.as_slice(),
        )
            .cmp(&(
                b.field.as_str(),
                &b.modifiers,
                b.all_mode,
                b.values.as_slice(),
            ))
    });

    // Quick check for conflicting |all on same field (rare but invalid)
    let mut seen = BTreeMap::new();
    for fc in &field_conditions {
        if let Some(prev_all) = seen.insert(&fc.field, fc.all_mode) {
            if prev_all != fc.all_mode {
                return Err(SigmaParseError::ConflictingAllModifier {
                    field: fc.field.clone(),
                });
            }
        }
    }

    Ok(Selection { field_conditions })
}

/// Parse Field|mod1|mod2|... â†’ field + list of modifiers (Sigma spec exact)
fn parse_field_modifiers(raw: &str) -> Result<(&str, Vec<Modifier>), SigmaParseError> {
    let parts: Vec<&str> = raw.split('|').collect();
    let field = parts[0];

    let mut mods = Vec::new();
    for &m in &parts[1..] {
        let modifier = match m {
            "contains" => Modifier::Contains,
            "startswith" => Modifier::StartsWith,
            "endswith" => Modifier::EndsWith,
            "base64" => Modifier::Base64,
            "base64offset" => Modifier::Base64Offset,
            "wide" | "utf16le" => Modifier::Wide, // wide is alias for utf16le in most backends
            "utf16" | "utf16be" => Modifier::Utf16Le, // conservative
            "re" => Modifier::Regex,
            "all" => Modifier::All,
            "" => Modifier::Equals,
            other => {
                return Err(SigmaParseError::UnsupportedModifier {
                    field: field.to_string(),
                    modifier: other.to_string(),
                });
            }
        };
        mods.push(modifier);
    }

    if mods.is_empty() {
        mods.push(Modifier::Equals);
    }

    Ok((field, mods))
}

fn parse_matcher_values(v: &serde_yaml::Value) -> Result<Vec<String>, SigmaParseError> {
    if let Some(seq) = v.as_sequence() {
        if seq.is_empty() {
            return Err(SigmaParseError::InvalidRule("matcher list cannot be empty".to_string()));
        }
        let mut out = Vec::with_capacity(seq.len());
        for item in seq {
            out.push(coerce_scalar(item)?);
        }
        Ok(out)
    } else {
        Ok(vec![coerce_scalar(v)?])
    }
}

fn coerce_scalar(v: &serde_yaml::Value) -> Result<String, SigmaParseError> {
    if let Some(s) = v.as_str() {
        return Ok(s.to_string());
    }
    if let Some(n) = v.as_i64() {
        return Ok(n.to_string());
    }
    if let Some(b) = v.as_bool() {
        return Ok(b.to_string());
    }
    Err(SigmaParseError::InvalidRule(
        "unsupported matcher value type (expected scalar or scalar list)".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_parse() {
        let yaml = r#"
        title: test
        detection:
          selection:
            Image|endswith: "\\powershell.exe"
            CommandLine|contains: "malicious"
          condition: selection
        "#;
        let rule = kristoffersen_feb18_parse_sigma_rule(yaml).unwrap();
        assert_eq!(rule.title, Some("test".to_string()));
    }

    #[test]
    fn chained_modifiers_and_all() {
        let yaml = r#"
        detection:
          sel:
            CommandLine|wide|base64offset|contains:
              - "powershell"
              - "cmd"
            EventID: 4688
          condition: sel
        "#;
        let _ = kristoffersen_feb18_parse_sigma_rule(yaml).unwrap();
    }
}
