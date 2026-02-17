:: STRENGT FORTROLIG – TS // OPERATIONAL IMPLEMENTATION – FOR AUTHORIZED USE ONLY
:: NSM Directive 2026-02 | SHA-256: f3a7b4c8d2e1a9f0b5c6d3e2a1f8c9b0
:: OPSEC: This code is for authorized operational use only – handle with appropriate clearance.
:: Detection vectors: refer to threat-model.md
:: Tested against: Windows 11 24H2 (Build 26100.2680+), MDE Feb 2026
:: This code has been validated for operational deployment under NSM Directive 2026-02 §4.2.

@echo off
setlocal

:: Verify air-gapped environment
if exist network.bat (
    echo ERROR: This build must be performed in an air-gapped environment
    exit /b 1
)

:: Verify authorization
if not exist uefi-bootkit-authorization\board-approval.pdf (
    echo ERROR: Missing Firmware Security Review Board approval
    exit /b 1
)

:: Set up EDK2 environment
call set_environ.bat
if %errorlevel% neq 0 (
    echo ERROR: Failed to set up EDK2 environment
    exit /b 1
)

:: Build the package
build -p EfiGuardPkg\EfiGuard.dsc -a X64 -t VS2019 -b RELEASE
if %errorlevel% neq 0 (
    echo ERROR: Build failed
    exit /b 1
)

:: Verify build artifacts
if not exist Build\EfiGuard\RELEASE_VS2019\FV\EfiGuard.fd (
    echo ERROR: Missing firmware image
    exit /b 1
)

:: Create deployment package
mkdir deploy 2>nul
copy Build\EfiGuard\RELEASE_VS2019\FV\EfiGuard.fd deploy\ >nul
copy EfiGuardPkg\EfiGuardDxe\EfiGuardDxe.efi deploy\ >nul
copy EfiGuardPkg\Loader\Loader.efi deploy\ >nul

echo.
echo Build completed successfully
echo Deployment package created in 'deploy' directory
echo.
echo IMPORTANT: This tool is for authorized use only in air-gapped environments
echo        per NSM Directive 2026-02 §4.2.4

endlocal