// STRENGT FORTROLIG – TS
//! EDR Evasion – ETW Patching Simulation
//! 
//! Controlled simulation of ntdll function prologue patching (EtwEventWrite).
//! Demonstrates trampoline-based hooking pattern for defense evasion training.
//! MITRE ATT&CK: T1562.006 (Impair Defenses: Indicator Blocking)
//! Environment: Air-gapped buffer-only simulation – no live kernel32/ntdll access

use std::vec::Vec;

/// Simulated ETW function prologue buffer
/// Represents EtwEventWrite entry point in ntdll memory space
pub struct EtwFunctionBuffer {
    /// Simulated memory page (executable region)
    pub code_buffer: Vec<u8>,
    /// Original bytes backup for restoration simulation
    pub original_bytes: Vec<u8>,
    /// Patch applied flag
    pub is_patched: bool,
}

/// x86-64 Trampoline construction constants
pub struct TrampolineOpcodes;

impl TrampolineOpcodes {
    /// MOV RAX, imm64 (48 B8 + 8 bytes address)
    pub const MOV_RAX_IMM64: u8 = 0x48;
    pub const MOV_RAX_IMM64_2: u8 = 0xB8;
    
    /// JMP RAX (FF E0)
    pub const JMP_RAX_1: u8 = 0xFF;
    pub const JMP_RAX_2: u8 = 0xE0;
    
    /// NOP (90) – padding for alignment
    pub const NOP: u8 = 0x90;
    
    /// RET (C3) – alternative patch pattern
    pub const RET: u8 = 0xC3;
}

/// Simulated ETW patcher for T1562.006 training scenarios
impl EtwFunctionBuffer {
    /// Initialize simulated ntdll EtwEventWrite prologue
    /// Original prologue simulation: mov [rsp+0x08], rbx; push rdi; sub rsp, 0x30
    pub fn new_simulated() -> Self {
        // Simulated original function prologue (14 bytes typical)
        let original: Vec<u8> = vec![
            0x48, 0x89, 0x5C, 0x24, 0x08,  // mov [rsp+0x08], rbx
            0x57,                          // push rdi
            0x48, 0x83, 0xEC, 0x30,        // sub rsp, 0x30
            0x48, 0x8B, 0xD9,              // mov rbx, rcx
            0x90, 0x90,                    // nop nop (padding)
        ];
        
        Self {
            code_buffer: original.clone(),
            original_bytes: original,
            is_patched: false,
        }
    }
    
    /// Construct trampoline: MOV RAX, <hook_addr>; JMP RAX
    /// 12 bytes total: 48 B8 [8-byte addr] FF E0
    pub fn construct_trampoline(&self, hook_address: u64) -> Vec<u8> {
        let mut trampoline = Vec::with_capacity(12);
        
        // MOV RAX, imm64
        trampoline.push(TrampolineOpcodes::MOV_RAX_IMM64);
        trampoline.push(TrampolineOpcodes::MOV_RAX_IMM64_2);
        
        // Append 64-bit address (little-endian)
        trampoline.extend_from_slice(&hook_address.to_le_bytes());
        
        // JMP RAX
        trampoline.push(TrampolineOpcodes::JMP_RAX_1);
        trampoline.push(TrampolineOpcodes::JMP_RAX_2);
        
        trampoline
    }
    
    /// Apply patch to simulated buffer
    /// Overwrites prologue with trampoline to redirect execution
    pub fn apply_patch(&mut self, hook_address: u64) -> Result<(), PatchError> {
        if self.is_patched {
            return Err(PatchError::AlreadyPatched);
        }
        
        if self.code_buffer.len() < 12 {
            return Err(PatchError::BufferTooSmall);
        }
        
        // Construct trampoline payload
        let trampoline = self.construct_trampoline(hook_address);
        
        // Save original bytes (already done in new_simulated, but ensure fresh copy)
        self.original_bytes = self.code_buffer.clone();
        
        // Apply patch: Overwrite first 12 bytes with trampoline
        for (i, byte) in trampoline.iter().enumerate() {
            self.code_buffer[i] = *byte;
        }
        
        // Fill remainder with NOPs if trampoline shorter than original read
        for i in trampoline.len()..self.original_bytes.len() {
            if i < self.code_buffer.len() {
                self.code_buffer[i] = TrampolineOpcodes::NOP;
            }
        }
        
        self.is_patched = true;
        Ok(())
    }
    
    /// Restore original bytes (simulated unhooking)
    pub fn restore_original(&mut self) -> Result<(), PatchError> {
        if !self.is_patched {
            return Err(PatchError::NotPatched);
        }
        
        self.code_buffer = self.original_bytes.clone();
        self.is_patched = false;
        Ok(())
    }
    
    /// Verify code integrity (simulated EDR check)
    /// Detection Hypothesis: EDR monitors ntdll code sections via periodic hash checks
    /// or inline hooks that detect jumps to unbacked memory regions.
    pub fn verify_integrity(&self) -> IntegrityStatus {
        if self.code_buffer.len() != self.original_bytes.len() {
            return IntegrityStatus::Modified;
        }
        
        // Check if first bytes match original (prologue integrity)
        if &self.code_buffer[0..5] != &self.original_bytes[0..5] {
            // Detection alert: Prologue modification detected
            // EDR behavioral indicator: Unexpected write to ntdll+.text
            return IntegrityStatus::PrologueModified;
        }
        
        IntegrityStatus::Intact
    }
    
    /// Simulate execution flow diversion
    /// Returns where execution would jump (hook_address) vs original flow
    pub fn trace_execution(&self) -> ExecutionFlow {
        if !self.is_patched {
            return ExecutionFlow::Original;
        }
        
        // Parse trampoline to extract jump target
        if self.code_buffer.len() >= 10 && 
           self.code_buffer[0] == TrampolineOpcodes::MOV_RAX_IMM64 &&
           self.code_buffer[1] == TrampolineOpcodes::MOV_RAX_IMM64_2 {
            
            // Extract 64-bit address from bytes 2-9
            let addr_bytes: [u8; 8] = [
                self.code_buffer[2], self.code_buffer[3],
                self.code_buffer[4], self.code_buffer[5],
                self.code_buffer[6], self.code_buffer[7],
                self.code_buffer[8], self.code_buffer[9],
            ];
            let target = u64::from_le_bytes(addr_bytes);
            return ExecutionFlow::Redirected(target);
        }
        
        ExecutionFlow::Unknown
    }
}

#[derive(Debug)]
pub enum PatchError {
    AlreadyPatched,
    NotPatched,
    BufferTooSmall,
    InvalidAddress,
}

#[derive(Debug, PartialEq)]
pub enum IntegrityStatus {
    Intact,
    Modified,
    PrologueModified,  // Specific detection signature for T1562.006
}

#[derive(Debug)]
pub enum ExecutionFlow {
    Original,
    Redirected(u64),
    Unknown,
}

/// Simulated EDR detection logic for training scenarios
pub struct EdrDetectionSimulator;

impl EdrDetectionSimulator {
    /// Simulate behavioral detection of ETW patching
    /// Detection vectors:
    /// 1. LoadLibraryEx + GetProcAddress + VirtualProtect sequence
    /// 2. WriteProcessMemory to ntdll code section
    /// 3. Execution of unbacked memory (trampoline target)
    pub fn check_patch_behavior(buffer: &EtwFunctionBuffer) -> DetectionAlert {
        match buffer.verify_integrity() {
            IntegrityStatus::PrologueModified => {
                // MITRE ATT&CK T1562.006 signature
                DetectionAlert::High {
                    technique: "T1562.006",
                    description: "ETW bypass via function prologue patching detected",
                    indicators: vec![
                        "ntdll.EtwEventWrite prologue modification".to_string(),
                        "Trampoline pattern: MOV RAX, imm64; JMP RAX".to_string(),
                        "Code integrity violation in .text section".to_string(),
                    ],
                }
            },
            IntegrityStatus::Modified => DetectionAlert::Medium {
                description: "Unexpected memory modification in system module",
            },
            IntegrityStatus::Intact => DetectionAlert::None,
        }
    }
}

#[derive(Debug)]
pub enum DetectionAlert {
    None,
    Medium { description: &'static str },
    High { 
        technique: &'static str, 
        description: &'static str,
        indicators: Vec<String>,
    },
}

/// Training scenario: Simulate ETW disable via patching
pub fn run_etw_patch_scenario() {
    // Initialize simulated EtwEventWrite buffer
    let mut etw_func = EtwFunctionBuffer::new_simulated();
    
    println!("Original bytes: {:02X?}", &etw_func.code_buffer[0..12]);
    
    // Attacker-controlled hook address (simulated shellcode location)
    let malicious_hook: u64 = 0x00007FF812345678;
    
    // Apply patch (T1562.006)
    match etw_func.apply_patch(malicious_hook) {
        Ok(()) => {
            println!("Patch applied: {:02X?}", &etw_func.code_buffer[0..12]);
            
            // Verify redirection
            if let ExecutionFlow::Redirected(addr) = etw_func.trace_execution() {
                println!("Execution redirected to: 0x{:016X}", addr);
            }
            
            // EDR Detection check
            let alert = EdrDetectionSimulator::check_patch_behavior(&etw_func);
            println!("EDR Alert: {:?}", alert);
        },
        Err(e) => println!("Patch failed: {:?}", e),
    }
    
    // Cleanup simulation
    let _ = etw_func.restore_original();
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_trampoline_construction() {
        let buffer = EtwFunctionBuffer::new_simulated();
        let hook_addr: u64 = 0x123456789ABCDEF0;
        let trampoline = buffer.construct_trampoline(hook_addr);
        
        assert_eq!(trampoline.len(), 12);
        assert_eq!(trampoline[0], 0x48); // MOV RAX prefix
        assert_eq!(trampoline[1], 0xB8);
        assert_eq!(trampoline[10], 0xFF); // JMP RAX
        assert_eq!(trampoline[11], 0xE0);
        
        // Verify address encoding
        let encoded_addr = u64::from_le_bytes([
            trampoline[2], trampoline[3], trampoline[4], trampoline[5],
            trampoline[6], trampoline[7], trampoline[8], trampoline[9],
        ]);
        assert_eq!(encoded_addr, hook_addr);
    }
    
    #[test]
    fn test_patch_detection() {
        let mut buffer = EtwFunctionBuffer::new_simulated();
        buffer.apply_patch(0xDEADBEEFCAFEBABE).unwrap();
        
        let status = buffer.verify_integrity();
        assert_eq!(status, IntegrityStatus::PrologueModified);
        
        let alert = EdrDetectionSimulator::check_patch_behavior(&buffer);
        match alert {
            DetectionAlert::High { technique, .. } => {
                assert_eq!(technique, "T1562.006");
            },
            _ => panic!("Expected high severity alert"),
        }
    }
    
    #[test]
    fn test_restore_integrity() {
        let mut buffer = EtwFunctionBuffer::new_simulated();
        let original = buffer.code_buffer.clone();
        
        buffer.apply_patch(0x1234).unwrap();
        assert!(buffer.is_patched);
        
        buffer.restore_original().unwrap();
        assert!(!buffer.is_patched);
        assert_eq!(buffer.code_buffer, original);
    }
}


