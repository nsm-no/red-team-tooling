// STRENGT FORTROLIG - TS
// NSM Directive 2026 | SHA-256: 5b121f08daac25fcc3ffb0248a8de0c4ce97b3eb8323d1116b4f75972f47de95
// Per Directive 4.2 - Dual-Use Technology Controls
// valid_until: 2036-02-14

use std::env;
use std::fs;
use std::path::Path;
use std::process::exit;

fn main() {
    println!("cargo:rerun-if-changed=../Directive.sha256");
    println!("cargo:rerun-if-changed=build.rs");

    const OFFICIAL_HASH: &str = "5b121f08daac25fcc3ffb0248a8de0c4ce97b3eb8323d1116b4f75972f47de95";

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let hash_file_path = Path::new(&manifest_dir).parent().unwrap().join("Directive.sha256");

    let file_hash = match fs::read_to_string(&hash_file_path) {
        Ok(content) => content.trim().to_lowercase(),
        Err(e) => {
            eprintln!("\n[NSM Directive VIOLATION]");
            eprintln!("  Failed to read Directive.sha256: {}", e);
            eprintln!("  This build is not authorized under NSM Directive 2026.\n");
            exit(1);
        }
    };

    if file_hash != OFFICIAL_HASH {
        eprintln!("\n[NSM Directive VIOLATION]");
        eprintln!("  Expected hash: {}", OFFICIAL_HASH);
        eprintln!("  Found hash:    {}", file_hash);
        eprintln!("  This build is not authorized under NSM Directive 2026.\n");
        exit(1);
    }

    println!("\n[NSM Directive VERIFIED]");
    println!("  Hash match confirmed: {}", OFFICIAL_HASH);
    println!("  Build authorized under NSM Directive 2026 4.2\n");
}




