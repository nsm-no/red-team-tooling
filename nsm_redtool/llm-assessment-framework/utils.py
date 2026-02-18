"""
Utility Functions Module (REVISED)
Classification: TOP SECRET // FORSVARET // NOFORN
Author: VALKYRIE-7

Provides logging, encryption, report generation, and other helper functions.

CHANGES:
- Removed automatic per-write encryption from write_log().
- Added encrypt_log_file() to encrypt the entire log file at the end of a run.
- Enhanced encrypt_file() with output_path parameter and no automatic deletion.
- Added clear warnings about encryption timing.
"""

import os
import json
import logging
import logging.handlers
from pathlib import Path
from typing import Dict, Any, List, Optional
import time
from datetime import datetime

# Optional encryption (only if cryptography is installed)
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    import base64
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Configure module logger
logger = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Logging Setup
# ----------------------------------------------------------------------
def setup_logging(log_file: str, log_level: str = "INFO") -> logging.Logger:
    """
    Configure logging to file and console.
    Returns the root logger (or a named logger).
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Ensure log directory exists
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # File handler (rotating, 10 MB per file, keep 5 backups)
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=5
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(numeric_level)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel(numeric_level)

    # Get root logger and configure
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    # Remove existing handlers to avoid duplicates
    root_logger.handlers = []
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    logger.info(f"Logging initialized: level={log_level}, file={log_file}")
    return root_logger


# ----------------------------------------------------------------------
# Audit Logging (JSON Lines) – NO PER-WRITE ENCRYPTION
# ----------------------------------------------------------------------
def write_log(entry: Dict[str, Any], logging_config: Dict[str, Any]) -> None:
    """
    Append a JSON entry to the audit log file.
    The file is specified in logging_config['file'].
    Encryption is NOT applied here; call encrypt_log_file() at the end.
    """
    log_file = logging_config.get('file')
    if not log_file:
        logger.warning("No log file specified, skipping audit write")
        return

    # Ensure directory exists
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    # Add timestamp if not present
    if 'timestamp' not in entry:
        entry['timestamp'] = time.time()

    # Write as JSON line
    try:
        with open(log_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry) + '\n')
    except Exception as e:
        logger.error(f"Failed to write audit log: {e}")


# ----------------------------------------------------------------------
# Encryption Helpers
# ----------------------------------------------------------------------
def get_fernet_from_password(password: str, salt: Optional[bytes] = None) -> Fernet:
    """
    Derive a Fernet key from a password using PBKDF2.
    If salt is None, a fixed salt is used (for simplicity; in production, use random salt stored with file).
    """
    if salt is None:
        # Fixed salt (not ideal for production, but okay for operational use with strong passwords)
        salt = b'nsm_redteam_salt_2026'
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return Fernet(key)


def encrypt_file(input_path: str, output_path: Optional[str] = None,
                 encryption_key: Optional[str] = None) -> Optional[str]:
    """
    Encrypt a file using Fernet symmetric encryption.
    If output_path is None, writes to input_path + '.enc'.
    Does NOT delete the input file; caller is responsible if needed.
    Returns the output path on success, None on failure.
    """
    if not CRYPTO_AVAILABLE:
        logger.warning("Cryptography not available, cannot encrypt")
        return None

    key = encryption_key or os.getenv('REDTEAM_ENCRYPTION_KEY')
    if not key:
        logger.error("No encryption key provided (set REDTEAM_ENCRYPTION_KEY)")
        return None

    if output_path is None:
        output_path = input_path + '.enc'

    try:
        # Read plaintext
        with open(input_path, 'rb') as f:
            data = f.read()

        # Encrypt
        fernet = get_fernet_from_password(key)
        encrypted = fernet.encrypt(data)

        # Write encrypted file
        with open(output_path, 'wb') as f:
            f.write(encrypted)

        logger.info(f"File encrypted: {input_path} -> {output_path}")
        return output_path
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return None


def encrypt_log_file(log_file: str, encryption_key: Optional[str] = None) -> Optional[str]:
    """
    Encrypt the entire audit log file in-place (creates .enc and deletes original).
    This should be called AFTER all logging is complete.
    Returns the path to the encrypted file, or None on failure.
    """
    if not os.path.exists(log_file):
        logger.error(f"Log file not found: {log_file}")
        return None

    encrypted_path = encrypt_file(log_file, encryption_key=encryption_key)
    if encrypted_path:
        try:
            os.remove(log_file)
            logger.info(f"Original plaintext log deleted: {log_file}")
        except Exception as e:
            logger.warning(f"Failed to delete original log file: {e}")
    return encrypted_path


def decrypt_file(encrypted_path: str, encryption_key: Optional[str] = None) -> bytes:
    """
    Decrypt a file encrypted with encrypt_file().
    Returns the plaintext bytes.
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("Cryptography not available")

    key = encryption_key or os.getenv('REDTEAM_ENCRYPTION_KEY')
    if not key:
        raise ValueError("No encryption key provided")

    with open(encrypted_path, 'rb') as f:
        encrypted = f.read()

    fernet = get_fernet_from_password(key)
    return fernet.decrypt(encrypted)


# ----------------------------------------------------------------------
# Report Generation
# ----------------------------------------------------------------------
def generate_report(results: List[Dict[str, Any]], report_config: Dict[str, Any]) -> str:
    """
    Generate a report from the test results.
    Supported formats: 'json', 'html' (basic).
    Returns the path to the generated report file.
    """
    output_path = report_config.get('output_path', 'reports/')
    report_format = report_config.get('format', 'json').lower()

    # Create output directory
    Path(output_path).mkdir(parents=True, exist_ok=True)

    # Timestamp for filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_filename = f"redteam_report_{timestamp}"

    if report_format == 'json':
        filename = Path(output_path) / f"{base_filename}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        logger.info(f"JSON report saved: {filename}")
        return str(filename)

    elif report_format == 'html':
        # Simple HTML report (tabular)
        filename = Path(output_path) / f"{base_filename}.html"
        html = _generate_html_report(results)
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        logger.info(f"HTML report saved: {filename}")
        return str(filename)

    else:
        logger.warning(f"Unsupported report format '{report_format}', defaulting to JSON")
        return generate_report(results, {**report_config, 'format': 'json'})


def _generate_html_report(results: List[Dict[str, Any]]) -> str:
    """Internal helper to generate a basic HTML report."""
    html = """<!DOCTYPE html>
<html>
<head>
    <title>NSM Red Team LLM Assessment Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .success { background-color: #d4edda; }
        .blocked { background-color: #f8d7da; }
    </style>
</head>
<body>
    <h1>NSM Red Team LLM Assessment Report</h1>
    <p>Generated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
    <table>
        <tr>
            <th>Timestamp</th>
            <th>Test Case</th>
            <th>Encoding</th>
            <th>Success</th>
            <th>Harmfulness Score</th>
            <th>Refusal Quality</th>
            <th>Response Preview</th>
        </tr>
"""
    for r in results:
        ts = datetime.fromtimestamp(r.get('timestamp', 0)).strftime('%Y-%m-%d %H:%M:%S')
        success_class = 'success' if r.get('success') else 'blocked'
        html += f"""
        <tr class="{success_class}">
            <td>{ts}</td>
            <td>{r.get('test_case', '')}</td>
            <td>{r.get('encoding', '')}</td>
            <td>{r.get('success', False)}</td>
            <td>{r.get('analysis', {}).get('harmfulness_score', 0):.3f}</td>
            <td>{r.get('analysis', {}).get('refusal_quality', 2)}</td>
            <td>{r.get('response_preview', '')[:100]}</td>
        </tr>
"""
    html += """
    </table>
</body>
</html>
"""
    return html


# ----------------------------------------------------------------------
# Kill Switch Check (optional, can be used by main)
# ----------------------------------------------------------------------
def check_kill_switch(kill_switch_file: str = "/tmp/nsm_redteam_kill") -> bool:
    """Return True if kill switch file exists."""
    return os.path.exists(kill_switch_file)


# ----------------------------------------------------------------------
# Environment Helpers
# ----------------------------------------------------------------------
def get_env_with_fallback(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get environment variable with optional default."""
    return os.getenv(key, default)