// STRENGT FORTROLIG – TS
// NSM Directive 2024-09 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Test: AMSI Bypass Module
// Author: Ingrid <ingrid@nsm.no>
// Last Updated: 2026-02-16

#[cfg(test)]
mod tests {
    use edr_evasion::amsi_bypass;

    #[test]
    fn test_patch_amsi() {
        unsafe { amsi_bypass::patch_amsi().unwrap(); }
        println!("[*] AMSI patch test passed (simulation)");
    }

    #[test]
    fn test_check_powershell_v2() {
        assert!(amsi_bypass::check_powershell_v2_installed());
        println!("[*] PowerShell v2 detection test passed");
    }

    #[test]
    #[ignore = "requires actual EDR telemetry"]
    fn test_amsi_against_mde() {
        println!("[*] This test would verify AMSI bypass against MDE");
        println!("[*] Run only in air-gapped lab with MDE sensor v7.29+");
    }
}
