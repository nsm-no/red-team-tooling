#include <Uefi.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

EFI_STATUS
WriteMemory (
  IN UINTN  Address,
  IN VOID   *Data,
  IN UINTN  Size
  )
{
  CopyMem ((VOID *)Address, Data, Size);
  return EFI_SUCCESS;
}