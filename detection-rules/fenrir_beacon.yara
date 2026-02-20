```yara

// STRENGT FORTROLIG – TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 §3.1 & §4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.

// ============================================================================
// YARA Rules to Detect FENRIR APT-grade Beacon Components
// ============================================================================

// ----------------------------------------------------------------------------
// Rule 1: C# Loader (FENRIR.Loader) – Compiled PE
// ----------------------------------------------------------------------------
rule fenrir_csharp_loader {
    meta:
        description = "Detects the FENRIR C# loader (Loader.cs) based on embedded strings and patterns"
        author = "Void Analyst"
        reference = "loader.cs"
    strings:
        // XOR decryption key (unique)
        $xor_key = "NSM-FENRIR-POC-01" ascii wide

        // Sandbox detection process list (partial)
        $proc1 = "procmon" ascii wide nocase
        $proc2 = "wireshark" ascii wide nocase
        $proc3 = "processhacker" ascii wide nocase
        $proc4 = "x64dbg" ascii wide nocase
        $proc5 = "vmtoolsd" ascii wide nocase

        // Hostname check
        $hostname_prefix = "NSM-TEST-" ascii wide

        // Domain check comment or string
        $domain_check = "System.DirectoryServices.ActiveDirectory.Domain" ascii wide

        // Imported functions (common but combined)
        $import1 = "VirtualAllocEx" ascii wide
        $import2 = "WriteProcessMemory" ascii wide
        $import3 = "CreateRemoteThread" ascii wide
        $import4 = "IsDebuggerPresent" ascii wide

        // PE signature for hollowing (notepad.exe)
        $target_process = "notepad.exe" ascii wide

        // Byte pattern: XOR decryption loop (typical C# byte code pattern)
        // This is a bit generic, but combined with other strings it's strong.
        $xor_loop = { 8B ?? ?? 33 ?? ?? 88 ?? ?? 45 ?? ?? 75 ?? } // approximate

    condition:
        uint16(0) == 0x5A4D and // MZ
        (2 of ($proc*) or $xor_key) and
        (any of ($import*)) and
        ($hostname_prefix or $domain_check)
}

// ----------------------------------------------------------------------------
// Rule 2: Persistence Shellcode (persistence.asm) – Raw binary or PE section
// ----------------------------------------------------------------------------
rule fenrir_persistence_shellcode {
    meta:
        description = "Detects the persistence shellcode (ADS + scheduled task) by its unique data and hashes"
        author = "Void Analyst"
    strings:
        // DJB2 hashes (stored as dwords in little-endian)
        $hash1 = { DB EC A5 15 } // 0x15A5ECDB (NtCreateFile)
        $hash2 = { B2 26 93 D6 } // 0xD69326B2 (NtWriteFile)
        $hash3 = { 79 B4 88 6E } // 0x6E88B479 (NtSetInformationFile)
        $hash4 = { 89 A0 E3 30 } // 0x30E3A089 (RtlAdjustPrivilege)

        // Path strings (ASCII)
        $ads_path = "\\??\\C:\\ProgramData\\Microsoft\\Windows\\Caches\\cache.ps1:payload" ascii
        $task_path = "\\??\\C:\\Windows\\Temp\\task.xml" ascii
        $task_xml = "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task" ascii
        $schtasks_cmd = "schtasks.exe /create /xml" ascii

        // Privilege constant
        $priv_const = { 09 00 00 00 } // SE_INCREASE_QUOTA_PRIVILEGE (9)

        // PEB walking code pattern (common but specific sequence)
        $peb_pattern = { 65 48 8B 04 25 60 00 00 00 48 8B 40 18 48 8B 40 20 } // mov rax, gs:[0x60]; mov rax,[rax+0x18]; mov rax,[rax+0x20]

    condition:
        // Match any two of the hashes, or the ADS path, or the PEB pattern
        (2 of ($hash*) or $ads_path or $peb_pattern) and
        (any of ($task_path, $schtasks_cmd) or $task_xml)
}

// ----------------------------------------------------------------------------
// Rule 3: Beacon Core (beacon.asm) – Full C2 beacon
// ----------------------------------------------------------------------------
rule fenrir_beacon_core {
    meta:
        description = "Detects the main beacon with C2 communications, jitter, and configuration"
        author = "Void Analyst"
    strings:
        // Configuration magic
        $magic = { CE FA ED FE } // 0xFEEDFACE (little-endian)

        // URLs and endpoints
        $url_config = "/config.enc" ascii
        $url_tasks = "/tasks" ascii
        $doh_endpoint = "https://1.1.1.1/dns-query?name=" ascii

        // HTTP headers
        $http_header = "Accept: application/dns-json" ascii

        // ICMP constants (type 8, code 0)
        $icmp_echo = { 08 00 } // ICMP echo request type and code (zero code)

        // Beacon loop pattern (jitter calculation, sleep)
        $jitter_code = { 0F C7 F? } // rdrand instruction (used in jitter)

        // API hashes (partial list from beacon's data section)
        $hash_ntcreatefile = { DB EC A5 15 }
        $hash_winhttpopen = { ?? ?? ?? ?? } // need actual values from code

        // Persistence strings
        $task_name = "WindowsUpdateTask" ascii
        $run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii

    condition:
        // Match either the magic, or a combination of URL strings and ICMP pattern
        $magic or
        ( ($url_config or $url_tasks or $doh_endpoint) and ($icmp_echo or $jitter_code) ) or
        ( ($task_name or $run_key) and $hash_ntcreatefile )
}

// ----------------------------------------------------------------------------
// Rule 4: DNS-over-HTTPS Module (dns_over_https.asm)
// ----------------------------------------------------------------------------
rule fenrir_dns_over_https {
    meta:
        description = "Detects the DNS-over-HTTPS fallback module"
        author = "Void Analyst"
    strings:
        $doh_url = "https://1.1.1.1/dns-query?name=" ascii
        $dns_type = "&type=A" ascii
        $json_accept = "Accept: application/dns-json" ascii
        // Hex encoding routine pattern (bin2hex)
        $bin2hex_code = { C1 C? 04 88 ?? 24 ?? 40 ?? 75 ?? } // rol, mov, etc.

    condition:
        $doh_url and ($dns_type or $json_accept or $bin2hex_code)
}

// ----------------------------------------------------------------------------
// Rule 5: ICMP Fallback Module (icmp_fallback.asm)
// ----------------------------------------------------------------------------
rule fenrir_icmp_fallback {
    meta:
        description = "Detects the ICMP fallback module with IcmpSendEcho and raw sockets"
        author = "Void Analyst"
    strings:
        // ICMP header construction
        $icmp_echo_req = { 08 00 00 00 } // type=8, code=0, checksum placeholder
        // IcmpSendEcho hash (if present)
        $icmp_send_echo_hash = { 8D 2B 9C 6F } // example hash for IcmpSendEcho (need actual)
        // XOR obfuscation loop with rotating key (ror)
        $xor_rot_loop = { 8A ?? ?? 32 ?? 88 ?? ?? C1 C? 08 48 FF C? } // mov al, [rsi+rcx]; xor al, bl; mov [rdi+rcx], al; ror ebx,8; inc rcx

        // Identifier from session key (low 16 bits)
        $id_extract = { 0F B7 41 ?? 89 44 24 ?? } // movzx eax, word [rcx+?]; mov [rsp+?], eax

        // Checksum calculation (RFC 1071)
        $checksum_loop = { 66 8B 06 66 01 D8 66 83 D2 00 48 83 C6 02 48 83 E9 01 75 EF } // typical checksum loop

    condition:
        $icmp_echo_req and ($xor_rot_loop or $checksum_loop)
}

// ----------------------------------------------------------------------------
// Rule 6: Reflective DLL Loader (reflective_loader.asm)
// ----------------------------------------------------------------------------
rule fenrir_reflective_loader {
    meta:
        description = "Detects the reflective DLL loader with PE parsing and import resolution"
        author = "Void Analyst"
    strings:
        // PE parsing code patterns
        $pe_check = { 66 81 3A 4D 5A } // cmp word [rdx], 'MZ'
        $pe_signature = { 81 3E 50 45 00 00 } // cmp dword [rsi], 'PE' (with two zero bytes)
        // Relocation processing
        $reloc_loop = { 8B 46 04 83 E8 08 D1 E8 48 8D 4E 08 } // mov eax, [rsi+4]; sub eax,8; shr eax,1; lea rcx, [rsi+8]
        // Import resolution by name
        $import_by_name = { 48 8B 0E 48 85 C9 74 ?? 48 8B 49 08 } // mov rcx, [rsi]; test rcx, rcx; jz ...; mov rcx, [rcx+8]
        // TLS callback loop
        $tls_callback = { 48 8B 41 18 48 85 C0 74 ?? 48 8B 08 48 85 C9 74 ?? } // mov rax, [rcx+0x18]; test rax,rax; jz; mov rcx,[rax]; test rcx,rcx; jz

        // Hashes for VirtualAlloc etc. (from data section)
        $hash_valloc = { 2C 9F 5E 3B } // example for VirtualAlloc

    condition:
        ($pe_check and $pe_signature) or
        ($reloc_loop and $import_by_name) or
        ($tls_callback and $hash_valloc)
}

// ----------------------------------------------------------------------------
// Rule 7: Generic – Look for DJB2 hash table (common in all asm modules)
// ----------------------------------------------------------------------------
rule fenrir_djb2_hashes {
    meta:
        description = "Detects the characteristic DJB2 hash values used across modules"
        author = "Void Analyst"
    strings:
        // Common hashes from the code (list of known hash dwords)
        $h1 = { DB EC A5 15 } // NtCreateFile
        $h2 = { B2 26 93 D6 } // NtWriteFile
        $h3 = { 79 B4 88 6E } // NtSetInformationFile
        $h4 = { 89 A0 E3 30 } // RtlAdjustPrivilege
        $h5 = { 3D 8A 5F 8B } // NtClose? (8B8A5F3D)
        $h6 = { E3 A3 21 47 } // NtQueryInformationFile? (4721A3E3)
        $h7 = { 2F 3F CB AE } // CreateProcessW (AECB3F2F)
        // etc. – add more from beacon and loader

    condition:
        // At least 3 distinct hashes present
        3 of ($h*)
}
```

---

## Evasion Recommendations

The above YARA rules target specific static patterns in the code. To evade detection, we must modify these patterns without breaking functionality. Below are suggestions for each component, with code snippets where applicable.

### 1. C# Loader Evasion

- **XOR key**: The static key `"NSM-FENRIR-POC-01"` is a strong signature. Replace with a dynamically derived key (e.g., from environment or hashed hostname) or use a more complex encryption (AES) with a key that is not stored as a plain string.
  - *Change*: Instead of XOR with fixed key, use AES-GCM (as in beacon) with a key derived from a system fingerprint.

- **Process list**: The hardcoded process names (`procmon`, etc.) are common. Obfuscate them (e.g., ROT13 or XOR with a simple key) and decode at runtime.
  - *Example*: Store as byte arrays with XOR 0x55, then decode before comparison.

- **Hostname check**: The prefix `NSM-TEST-` is very specific. Change to a more generic check (e.g., check for any hostname not matching a blacklist, or use a different marker). Alternatively, remove this check entirely if not needed.

- **Domain join check**: The use of `System.DirectoryServices.ActiveDirectory.Domain` can be replaced with a native API call (e.g., `NetGetJoinInformation`) to avoid the managed assembly signature.

- **Imported functions**: The list of imported functions (`VirtualAllocEx`, etc.) is typical, but you can use dynamic API resolution (like the shellcode does) to avoid import table entries. Use P/Invoke with `[DllImport]` but with obfuscated names or delay-load.

- **Encrypted payload**: The payload array is in the data section. Use compression (LZ77) before encryption to change the byte pattern, and store it as a resource or in a separate section with random padding.

### 2. Persistence Shellcode Evasion

- **DJB2 hashes**: The hash values are fixed. Replace with a different hash algorithm (e.g., CRC32, or a custom rolling hash) or add a constant XOR to each hash before storage.
  - *Change*: Instead of storing `0x15A5ECDB`, store `0x15A5ECDB ^ 0xDEADBEEF` and XOR at runtime. This changes the byte pattern.

- **ADS path**: The path `\??\C:\ProgramData\Microsoft\Windows\Caches\cache.ps1:payload` is a strong indicator. Vary the directory and filename. Use a more legitimate-looking path, e.g., `C:\Windows\Temp\~.tmp` or mimic a system file. Randomize the ADS name per installation.

- **Task XML**: The XML contains strings like `WindowsUpdateTask` and `<Author>Microsoft</Author>`. Change these to something else (e.g., `AdobeUpdateTask`) and randomize the task name. Also, the XML can be constructed dynamically at runtime from fragments to avoid a full static template.

- **RtlAdjustPrivilege**: The privilege constant `9` is used. You can use `AdjustTokenPrivileges` from kernel32 instead, which is less suspicious (though more code). Or use a different privilege.

- **PEB walking pattern**: The sequence `mov rax, gs:[0x60]; mov rax,[rax+0x18]; mov rax,[rax+0x20]` is very common in shellcode. You can obfuscate by using different offsets (e.g., using `[rax+0x20]` vs `[rax+0x10]` after walking) or by adding dummy instructions. For example, interleave with useless operations that don't affect the result.

### 3. Beacon Core Evasion

- **Configuration magic**: `0xFEEDFACE` is a known pattern. Replace with a different magic (e.g., a random 4-byte value that looks like data) or use a checksum instead of a fixed magic.

- **URLs**: The strings `/config.enc` and `/tasks` are telltale. Obfuscate them (e.g., store as hex or XOR) and decode at runtime. Use HTTPS with domain fronting or CDN to hide the actual endpoint.

- **DNS-over-HTTPS endpoint**: Hardcoded `https://1.1.1.1/dns-query?name=` is distinctive. Use multiple fallback resolvers (e.g., Google 8.8.8.8, Quad9) and rotate. Also, encode the query parameter differently (e.g., base64 instead of hex).

- **ICMP echo request**: The raw bytes `08 00` (type 8, code 0) are common, but you can use other ICMP types (e.g., timestamp request) or vary the code. Also, the checksum calculation routine is standard; you can modify it slightly (e.g., use a different initial value) but must still compute correctly.

- **Jitter calculation**: The use of `rdrand` is not common in malware; consider using `rdtsc` or a combination of timers to generate randomness. Also, the jitter formula can be varied (e.g., use a normal distribution instead of uniform).

- **API hashes**: Same as above, XOR the hashes with a per-session key.

- **Task name**: The scheduled task name `WindowsUpdateTask` is suspicious. Use a random name each time (e.g., generate from hostname or a GUID). Also, use WMI instead of `schtasks.exe` to avoid command-line logging.

### 4. DNS-over-HTTPS Module Evasion

- **Endpoint URL**: Hardcoded to Cloudflare. Use a list of DoH servers and randomize. Also, the query string `?name=` and `&type=A` are static; change to a different parameter order or use POST requests.

- **Hex encoding**: The `bin2hex` routine is simple. Replace with base32 or base64 encoding to avoid the pattern of converting 4 bytes to 8 hex chars.

- **JSON parsing**: The custom parser looks for `"data":"`; you can change the JSON field name or use a different format (e.g., DNS wire format instead of JSON).

### 5. ICMP Fallback Module Evasion

- **XOR obfuscation**: The rotating XOR key (using `ror ebx,8`) is a pattern. Change to a different rotation (e.g., `rol`) or use a different obfuscation (e.g., add a constant, then XOR). The key extraction from session key is fine but can be masked.

- **Identifier**: The low 16 bits of session key are used as identifier. This is good, but the pattern of extracting them ( `movzx eax, word [rcx+?]` ) might be signatured. Use a different derivation (e.g., CRC16 of session key).

- **Checksum**: The checksum algorithm is standard. You can use a different algorithm (e.g., Adler-32) but must match the receiver.

- **IcmpSendEcho usage**: The function itself is not malicious, but the pattern of calling it with specific parameters can be detected. Use the raw socket method only, or vary the parameters (e.g., use a larger data size).

### 6. Reflective DLL Loader Evasion

- **PE parsing**: The sequences like `cmp word [rdx], 'MZ'` and `cmp dword [rsi], 'PE'` are unavoidable, but you can obfuscate by using different registers or adding junk instructions. For example:
  ```asm
  mov ax, [rdx]
  cmp ax, 0x5A4D
  ```
  vs.
  ```asm
  mov ax, [rdx]
  xor ax, 0x1234
  cmp ax, 0x5A4D ^ 0x1234
  ```

- **Relocation loop**: The pattern `mov eax, [rsi+4]; sub eax,8; shr eax,1; lea rcx, [rsi+8]` is characteristic. You can rearrange: first load, then shift, then subtract, etc., but the core operations remain. Add dummy instructions or use different registers.

- **Import resolution**: The code that traverses the import descriptor table is long and has many variants. To avoid signature, you can implement it differently (e.g., use a recursive function) but that adds size. Instead, change the order of operations and use different registers.

- **TLS callback loop**: The pattern `mov rax, [rcx+0x18]; test rax,rax; jz; mov rcx,[rax]; test rcx,rcx; jz` is common. You can replace with a loop that uses `lodsq` or similar.

- **Hashes**: As before, XOR the hash values stored in the data section with a constant to avoid static byte patterns.

### General Evasion Techniques

- **Use dynamic API resolution with different hash algorithms**: Instead of DJB2, use a custom hash or a combination of two algorithms. For example, compute a simple CRC and then XOR with a seed. Store the seeds in a table.

- **Obfuscate strings**: All static strings (paths, URLs, XML) should be XOR-encrypted with a simple key that is not stored in plaintext. Decode them just before use.

- **Polymorphic code**: Use a simple metamorphic engine that reorders instructions and inserts junk code. This is heavy but possible for shellcode.

- **Split the beacon into multiple stages**: Have a small first-stage that downloads the main beacon, so the main beacon's patterns are not on disk.

- **Use legitimate processes for communication**: Instead of raw ICMP or DoH, use HTTPS to a popular CDN or use WebSockets over a legitimate service.

### Example Patches

**Persistence shellcode hash obfuscation**:
Original:
```asm
ntdll_hashes:
    dd 0x15A5ECDB   ; NtCreateFile
```
Obfuscated:
```asm
ntdll_hashes:
    dd 0x15A5ECDB xor 0xDEADBEEF   ; Store as 0xCB085234
```
Then at runtime, before using, XOR again with 0xDEADBEEF.

**Beacon URL obfuscation**:
Original:
```asm
path_config: db '/config.enc', 0
```
Obfuscated:
```asm
path_config_enc: db 0x2F, 0x63, 0x6F, 0x6E, 0x66, 0x69, 0x67, 0x2E, 0x65, 0x6E, 0x63, 0x00  ; plaintext
; or XOR with key
path_config_xor: db 0x4A, 0x46, 0x48, 0x4A, 0x43, 0x44, 0x47, 0x4B, 0x40, 0x4D, 0x46  ; XORed with 0x2A
```
Decode with a small loop before use.

**Randomize task name**:
Instead of hardcoded "WindowsUpdateTask", generate a random name like "EdgeUpdate_{GUID}" using the session key.

**Change the ICMP identifier derivation**:
Use a hash of the session key plus a nonce.

---

// By implementing these changes, the YARA rules above would need to be updated to match the new patterns, making detection harder. The key is to eliminate static, unique strings and byte sequences, and to use dynamic values that change per installation.
