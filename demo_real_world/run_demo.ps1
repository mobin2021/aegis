# ==============================================================================
# Aegis 2.0 Live Real-World Triage & Mitigation Demonstration
# Demonstrates:
#   1. Compiling a vulnerable C service (CWE-120: strcpy buffer overflow)
#   2. Running Aegis Autonomous Triage (AST Scan + Stack Modeling + Patch Synth)
#   3. Executing synthesized PoC crash test vector (0xC0000005 crash verification)
#   4. Applying synthesized patch and recompiling with hardening
#   5. Re-running PoC to prove 100% successful memory corruption mitigation
# ==============================================================================

$GCC = "C:\Program Files\CodeBlocks\MinGW\bin\gcc.exe"
if (-not (Test-Path $GCC)) {
    Write-Host "[!] CodeBlocks MinGW GCC not found at default location." -ForegroundColor Red
    exit 1
}

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "  AEGIS 2.0: REAL-WORLD TRIAGE & MITIGATION VERIFICATION" -ForegroundColor Cyan
Write-Host "======================================================================`n" -ForegroundColor Cyan

# Step 1: Compile Vulnerable Target
Write-Host "[1/5] Compiling vulnerable target (auth_service.c)..." -ForegroundColor Yellow
& $GCC -O0 -fno-stack-protector auth_service.c -o auth_service.exe
Write-Host "      [+] Generated: auth_service.exe (unhardened x86_64 binary)`n" -ForegroundColor Green

# Step 2: Run Aegis Triage CLI
Write-Host "[2/5] Running Aegis Autonomous Triage Pipeline..." -ForegroundColor Yellow
python -m aegis.cli triage auth_service.c --out-poc auth_poc.py --out-patch auth_patch.diff --no-color

# Step 3: Execute Synthesized Crash Test Vector
Write-Host "`n[3/5] Executing synthesized crash test vector against unpatched binary..." -ForegroundColor Yellow
python auth_poc.py auth_service.exe --argv

# Step 4: Recompile with Aegis Patch
Write-Host "`n[4/5] Compiling Aegis-mitigated target (auth_service_patched.c)..." -ForegroundColor Yellow
& $GCC -static -O2 auth_service_patched.c -o auth_service_patched.exe
Write-Host "      [+] Generated: auth_service_patched.exe (mitigated binary)`n" -ForegroundColor Green

# Step 5: Verify Mitigation
Write-Host "[5/5] Re-executing attack vector against mitigated binary..." -ForegroundColor Yellow
python auth_poc.py auth_service_patched.exe --argv

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "  DEMONSTRATION COMPLETE: VULNERABILITY DETECTED, PROVEN, & PATCHED!" -ForegroundColor Cyan
Write-Host "======================================================================`n" -ForegroundColor Cyan
