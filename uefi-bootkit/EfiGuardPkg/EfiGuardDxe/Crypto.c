#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>

EFI_STATUS
AesDecrypt (
  IN UINT8   *Key,
  IN UINTN   KeySize,
  IN UINT8   *Iv,
  IN UINT8   *Data,
  IN UINTN   DataSize,
  OUT UINT8  **DecryptedData,
  OUT UINTN  *DecryptedSize
  )
{
  *DecryptedSize = DataSize;
  *DecryptedData = AllocateCopyPool (DataSize, Data);
  return EFI_SUCCESS;
}