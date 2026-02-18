#!/usr/bin/env python3
"""
Configuration Loader and Validator
Classification: TOP SECRET // FORSVARET // NOFORN
Author: VALKYRIE-7

Loads YAML configuration, substitutes environment variables, and validates required keys.
"""

import os
import yaml
from typing import Any, Dict


def _expand_env_vars(obj: Any) -> Any:
    """
    Recursively traverse the configuration and replace strings of the form
    ${VAR_NAME} with the corresponding environment variable.
    """
    if isinstance(obj, dict):
        return {k: _expand_env_vars(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_expand_env_vars(item) for item in obj]
    elif isinstance(obj, str):
        # Use os.path.expandvars to replace ${VAR} or $VAR
        expanded = os.path.expandvars(obj)
        # If the string is exactly a variable and it's empty after expansion,
        # we might want to warn, but we'll let it pass.
        return expanded
    else:
        return obj


def validate_config(config: Dict[str, Any]) -> None:
    """
    Validate that all required configuration keys are present.
    Raises ValueError with a descriptive message if any are missing.
    """
    required_top_level = ['target', 'browser', 'stealth', 'payload', 'analysis', 'logging', 'report']
    for section in required_top_level:
        if section not in config:
            raise ValueError(f"Missing required top-level configuration section: '{section}'")

    # Validate target section
    target = config['target']
    required_target_keys = ['url', 'input_selector', 'send_selector', 'response_selector']
    for key in required_target_keys:
        if key not in target:
            raise ValueError(f"Missing required key in 'target' section: '{key}'")

    # Validate browser section (all keys optional, but we can check types later)
    browser = config['browser']
    if not isinstance(browser, dict):
        raise ValueError("'browser' section must be a dictionary")

    # Validate stealth section (same, but we'll ensure it's a dict)
    if not isinstance(config['stealth'], dict):
        raise ValueError("'stealth' section must be a dictionary")

    # Validate payload section (must have encodings list and test_cases)
    payload = config['payload']
    if 'encodings' not in payload:
        raise ValueError("Missing 'encodings' list in 'payload' section")
    if not isinstance(payload['encodings'], list):
        raise ValueError("'encodings' must be a list")
    if 'test_cases' not in payload:
        raise ValueError("Missing 'test_cases' list in 'payload' section")
    if not isinstance(payload['test_cases'], list):
        raise ValueError("'test_cases' must be a list")

    # Validate analysis section (must have heuristic, optionally judge_llm)
    analysis = config['analysis']
    if 'heuristic' not in analysis:
        raise ValueError("Missing 'heuristic' subsection in 'analysis' section")
    if not isinstance(analysis['heuristic'], dict):
        raise ValueError("'heuristic' must be a dictionary")
    # Judge LLM is optional; if present, must have api_url and api_key
    if 'judge_llm' in analysis and analysis['judge_llm'].get('enabled', False):
        judge = analysis['judge_llm']
        if 'api_url' not in judge:
            raise ValueError("'judge_llm' enabled but missing 'api_url'")
        if 'api_key' not in judge:
            raise ValueError("'judge_llm' enabled but missing 'api_key'")

    # Validate logging section
    logging_cfg = config['logging']
    required_logging = ['level', 'file']
    for key in required_logging:
        if key not in logging_cfg:
            raise ValueError(f"Missing required key in 'logging' section: '{key}'")

    # Validate report section
    report_cfg = config['report']
    required_report = ['output_path', 'format']
    for key in required_report:
        if key not in report_cfg:
            raise ValueError(f"Missing required key in 'report' section: '{key}'")

    # Optional: add more specific type checks if desired (e.g., level is string)


def load_config(config_path: str = "config.yaml") -> Dict[str, Any]:
    """
    Load YAML configuration from the given path, expand environment variables,
    validate, and return as a dictionary.
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, 'r', encoding='utf-8') as f:
        try:
            config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing YAML file: {e}")

    if not isinstance(config, dict):
        raise ValueError("Configuration file must contain a YAML dictionary (top-level object)")

    # Expand environment variables
    config = _expand_env_vars(config)

    # Validate
    validate_config(config)

    return config


# Optional: if run as script, test loading
if __name__ == "__main__":
    import sys
    try:
        cfg = load_config(sys.argv[1] if len(sys.argv) > 1 else "config.yaml")
        print("Configuration loaded successfully.")
        print("Top-level sections:", list(cfg.keys()))
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)