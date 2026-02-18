#!/usr/bin/env python3
"""
NSM Red Team LLM Assessment Tool - Main Orchestrator (UPDATED)
Classification: TOP SECRET // FORSVARET // NOFORN
Author: VALKYRIE-7

Changes:
- Added call to encrypt_log_file() after report generation if encryption enabled.
- Ensured compatibility with revised utils.py (encrypt_log_file).
- Uses 4‑tuple return from init_browser().
"""

import os
import sys
import time
import signal
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional

import yaml
from dotenv import load_dotenv

# Local modules
from stealth_browser import init_browser, send_messages, cleanup_browser
from payload_generator import generate_payloads
from response_analyzer import analyze_response
from config import load_config, validate_config
from utils import setup_logging, write_log, encrypt_log_file, generate_report, check_kill_switch

# Global state for kill switch
KILL_SWITCH_FILE = "/tmp/nsm_redteam_kill"  # can be overridden via env
SHUTDOWN_REQUESTED = False

def signal_handler(sig, frame):
    """Handle SIGINT/SIGTERM gracefully."""
    global SHUTDOWN_REQUESTED
    logging.info("Shutdown signal received, cleaning up...")
    SHUTDOWN_REQUESTED = True

def main(config_path: str):
    """Main entry point."""
    global SHUTDOWN_REQUESTED

    # Load environment variables
    load_dotenv()

    # Load and validate configuration
    try:
        config = load_config(config_path)
        validate_config(config)
    except Exception as e:
        print(f"FATAL: Configuration error: {e}", file=sys.stderr)
        sys.exit(1)

    # Setup logging
    log_file = config['logging']['file']
    log_level = config['logging']['level']
    logger = setup_logging(log_file, log_level)
    logger.info("NSM Red Team Tool starting")
    logger.info(f"Target URL: {config['target']['url']}")

    # Override kill switch file if set in env
    global KILL_SWITCH_FILE
    KILL_SWITCH_FILE = os.getenv('REDTEAM_KILL_SWITCH', KILL_SWITCH_FILE)

    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Initialize browser (returns 4‑tuple: playwright, browser, context, page)
    browser_tuple = None
    try:
        browser_tuple = init_browser(config)
        logger.info("Browser initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize browser: {e}")
        sys.exit(1)

    # Load test cases
    test_cases = config['payload'].get('test_cases', [])
    if not test_cases:
        logger.error("No test cases defined in configuration")
        cleanup_browser(browser_tuple, config)
        sys.exit(1)

    # Prepare results storage
    all_results = []

    # Main loop over test cases
    for case_idx, case in enumerate(test_cases):
        if SHUTDOWN_REQUESTED or check_kill_switch(KILL_SWITCH_FILE):
            logger.warning("Kill switch activated, aborting further tests")
            break

        logger.info(f"Executing test case {case_idx+1}/{len(test_cases)}: {case['name']}")

        # Generate payload(s) for this test case
        try:
            payloads = generate_payloads(case, config['payload'])
        except Exception as e:
            logger.error(f"Payload generation failed for {case['name']}: {e}")
            continue

        # For each payload variant, run the conversation
        for payload in payloads:
            if SHUTDOWN_REQUESTED or check_kill_switch(KILL_SWITCH_FILE):
                break

            logger.debug(f"  Sending payload with encoding: {payload.get('encoding', 'unknown')}")

            # Send messages and get responses
            try:
                responses = send_messages(browser_tuple, payload['messages'], config)
            except Exception as e:
                logger.error(f"Message sending failed: {e}")
                continue

            # Combine responses for analysis (if multi-turn)
            full_response = "\n".join(responses) if responses else ""

            # Analyze response
            try:
                analysis = analyze_response(
                    full_response,
                    payload['original_request'],
                    config['analysis']
                )
            except Exception as e:
                logger.error(f"Response analysis failed: {e}")
                analysis = {
                    'was_blocked': True,
                    'harmfulness_score': 0.0,
                    'refusal_quality': 2,
                    'error': str(e)
                }

            # Prepare result entry
            result = {
                'timestamp': time.time(),
                'test_case': case['name'],
                'encoding': payload.get('encoding', 'unknown'),
                'original_request': payload['original_request'],
                'encoded_payload': payload.get('encoded_payload', ''),
                'response_preview': full_response[:500] + ('...' if len(full_response) > 500 else ''),
                'analysis': analysis,
                'success': not analysis.get('was_blocked', True)
            }
            all_results.append(result)

            # Log to audit file immediately (plaintext)
            write_log(result, config['logging'])

            # Brief pause between payloads
            time.sleep(2)

        # Optional pause between test cases
        time.sleep(5)

    # Generate final report
    try:
        report_path = generate_report(all_results, config['report'])
        logger.info(f"Report generated: {report_path}")
    except Exception as e:
        logger.error(f"Report generation failed: {e}")

    # Encrypt audit log if enabled (AFTER report generation, so report is not affected)
    if config['logging'].get('encrypted', False):
        log_file_path = config['logging']['file']
        encryption_key = os.getenv('REDTEAM_ENCRYPTION_KEY')
        if encryption_key:
            logger.info("Encrypting audit log...")
            encrypted_path = encrypt_log_file(log_file_path, encryption_key)
            if encrypted_path:
                logger.info(f"Audit log encrypted: {encrypted_path}")
            else:
                logger.error("Failed to encrypt audit log")
        else:
            logger.warning("Encryption enabled but REDTEAM_ENCRYPTION_KEY not set; log remains plaintext.")

    # Cleanup browser
    cleanup_browser(browser_tuple, config)
    logger.info("Tool finished")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NSM Red Team LLM Assessment Tool")
    parser.add_argument('--config', default='config.yaml', help='Path to configuration YAML')
    args = parser.parse_args()
    main(args.config)