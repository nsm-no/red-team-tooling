// STRENGT FORTROLIG – TS
// NSM Mandate 2026 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Per Mandate §4.2 – Dual-Use Technology Controls
// valid_until: 2036-02-14

use std::env;
use std::fs;
use std::path::Path;
use std::process::exit;

fn main() {
    println!("cargo:rerun-if-changed=mandate.sha256");
    println!("cargo:rerun-if-changed=build.rs");

    // The official mandate hash (from NSM Mandate 2026)
    const OFFICIAL_HASH: &str = "f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0";

    // Path to mandate.sha256
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let hash_file_path = Path::new(&manifest_dir).join("mandate.sha256");

    // Read the hash file
    let file_hash = match fs::read_to_string(&hash_file_path) {
        Ok(content) => content.trim().to_lowercase(),
        Err(e) => {
            eprintln!("\n\x1b[31m[NSM MANDATE VIOLATION]\x1b[0m");
            eprintln!("  Failed to read mandate.sha256: {}", e);
            eprintln!("  This build is not authorized under NSM Mandate 2026.\n");
            exit(1);
        }
    };

    // Compare hashes
    if file_hash != OFFICIAL_HASH {
        eprintln!("\n\x1b[31m[NSM MANDATE VIOLATION]\x1b[0m");
        eprintln!("  Expected hash: {}", OFFICIAL_HASH);
        eprintln!("  Found hash:    {}", file_hash);
        eprintln!("  This build is not authorized under NSM Mandate 2026.\n");
        exit(1);
    }

    // Success - compile-time mandate verification passed
    println!("\x1b[32m[NSM MANDATE VERIFIED]\x1b[0m");
    println!("  Hash match confirmed: {}", OFFICIAL_HASH);
    println!("  Build authorized under NSM Mandate 2026 §4.2\n");
}



