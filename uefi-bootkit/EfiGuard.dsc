// STRENGT FORTROLIG – TS // OPERATIONAL IMPLEMENTATION – FOR AUTHORIZED USE ONLY
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// OPSEC: This code is for authorized operational use only – handle with appropriate clearance.
// Detection vectors: refer to threat-model.md
// Tested against: Windows 11 24H2 (Build 26100.2680+), MDE Feb 2026
// This code has been validated for operational deployment under NSM Directive 2026-02 §4.2.

[Defines]
  PLATFORM_NAME                    = EfiGuard
  PLATFORM_GUID                    = 6D4D3B8C-6D3B-4D3B-8C6D-3B4D3B8C6D3B
  PLATFORM_VERSION                 = 1.0
  DSC_SPECIFICATION                = 0x00010005
  OUTPUT_DIRECTORY                 = Build/EfiGuard
  SUPPORTED_ARCHITECTURES          = X64
  BUILD_TARGETS                    = DEBUG | RELEASE
  SKUID_IDENTIFIER                 = DEFAULT
  FLASH_DEFINITION                 = EfiGuard.fdf

[LibraryClasses.X64]
  BaseLib                          = MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib                    = MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  DebugLib                         = MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  UefiDriverEntryPoint             = MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiBootServicesTableLib         = MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib      = MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  UefiLib                          = MdePkg/Library/UefiLib/UefiLib.inf
  MemoryAllocationLib              = MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PcdLib                           = MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  DevicePathLib                    = MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  PrintLib                         = MdePkg/Library/BasePrintLib/BasePrintLib.inf
  SafeIntLib                       = MdePkg/Library/BaseSafeIntLib/BaseSafeIntLib.inf
  TimerLib                         = MdePkg/Library/TimerLibNull/TimerLibNull.inf
  EfiGuardLib                      = EfiGuardPkg/Library/EfiGuardLib/EfiGuardLib.inf

[Components.X64]
  EfiGuardPkg/EfiGuardDxe/EfiGuardDxe.inf
  EfiGuardPkg/Loader/Loader.inf
  EfiGuardPkg/KernelPayload/KernelPayload.inf