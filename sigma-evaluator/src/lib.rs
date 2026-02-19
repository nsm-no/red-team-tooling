// STRENGT FORTROLIG – TS
// NSM-20260219-001
// kristoffersen_feb19_sigma_eval

// NSM-20260218-002
#![forbid(unsafe_code)]

pub mod markers;
pub mod parser;
pub mod matcher;

use timeline_builder::model::Timeline;

use crate::parser::{kristoffersen_feb18_parse_sigma_rule, SigmaRule};
use crate::matcher::{kristoffersen_feb18_evaluate_rule_against_timeline, EvalResult};

#[derive(Debug)]
pub enum SigmaEvalError {
    Parse(String),
    Eval(String),
}

impl std::fmt::Display for SigmaEvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigmaEvalError::Parse(s) => write!(f, "parse error: {}", s),
            SigmaEvalError::Eval(s) => write!(f, "eval error: {}", s),
        }
    }
}
impl std::error::Error for SigmaEvalError {}

/// Evaluate a Sigma rule YAML string against a timeline-builder `Timeline`.
///
/// Deterministic: same inputs -> identical outputs.
pub fn kristoffersen_feb18_evaluate(
    timeline: &Timeline,
    sigma_rule_yaml: &str,
) -> Result<EvalResult, SigmaEvalError> {
    let rule: SigmaRule = kristoffersen_feb18_parse_sigma_rule(sigma_rule_yaml)
        .map_err(|e| SigmaEvalError::Parse(e))?;

    kristoffersen_feb18_evaluate_rule_against_timeline(timeline, &rule)
        .map_err(|e| SigmaEvalError::Eval(e))
}

/// Optional convenience: evaluate from timeline JSON string (as produced by timeline-builder JSON renderer).
///
/// Note: This requires the timeline JSON to be in the timeline-builder JSON format.
/// If you prefer, keep evaluation on `Timeline` objects to avoid parse ambiguity.
pub fn kristoffersen_feb18_evaluate_timeline_json(
    timeline_json: &str,
    sigma_rule_yaml: &str,
) -> Result<EvalResult, SigmaEvalError> {
    let timeline: Timeline = crate::matcher::kristoffersen_feb18_parse_timeline_json(timeline_json)
        .map_err(|e| SigmaEvalError::Parse(e))?;

    kristoffersen_feb18_evaluate(&timeline, sigma_rule_yaml)
}
