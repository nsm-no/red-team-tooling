// STRENGT FORTROLIG – TS
// NSM-20260219-001
// kristoffersen_feb19_sigma_eval

// NSM-20260218-002

use serde::Deserialize;
use std::collections::BTreeMap;

/// Minimal Sigma YAML representation for defensive regression testing.
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

#[derive(Debug, Clone)]
pub struct Detection {
    /// Named selections (e.g., "selection", "selection1", ...)
    pub selections: BTreeMap<String, Selection>,
    /// Condition expression string (e.g., "selection", "selection1 and selection2")
    pub condition: String,
}

#[derive(Debug, Clone)]
pub struct Selection {
    /// Each matcher is ANDed within the selection (standard Sigma selection semantics).
    pub matchers: Vec<FieldMatcher>,
}

#[derive(Debug, Clone)]
pub enum MatchOp {
    Equals,
    Contains,
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
/// Supported:
/// - detection: { <selection_name>: { Field: value, Field|contains: value }, condition: "..." }
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

    for (k, v) in mapping.iter() {
        let key = k
            .as_str()
            .ok_or_else(|| "detection keys must be strings".to_string())?
            .to_string();

        if key == "condition" {
            condition = Some(
                v.as_str()
                    .ok_or_else(|| "condition must be a string".to_string())?
                    .to_string(),
            );
            continue;
        }

        // Selection entry
        let sel = parse_selection(&key, v)?;
        selections.insert(key, sel);
    }

    let condition = condition.ok_or_else(|| "detection.condition is required".to_string())?;
    if selections.is_empty() {
        return Err("detection must contain at least one selection".to_string());
    }

    Ok(Detection { selections, condition })
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
    //   "Image"
    if let Some((field, op)) = raw.split_once('|') {
        let op = match op {
            "contains" => MatchOp::Contains,
            _ => MatchOp::Equals, // fallback: treat unknown as equals (conservative)
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
    }
}
