# ==============================================================================
# Aegis Studio: PyInstaller Windows 11 Desktop Standalone Build Script
# Compiles Aegis Studio into a single-file portable Windows executable:
#   dist/AegisStudio.exe
# ==============================================================================

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "  AEGIS 2.0: COMPILING STANDALONE WINDOWS DESKTOP EXECUTABLE" -ForegroundColor Cyan
Write-Host "======================================================================`n" -ForegroundColor Cyan

$ROOT = Resolve-Path "$PSScriptRoot\.."
Set-Location $ROOT

Write-Host "[*] Root Directory: $ROOT" -ForegroundColor Gray
Write-Host "[*] Invoking PyInstaller..." -ForegroundColor Yellow

python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name "AegisStudio" `
    --add-data "aegis/gui/index.html;aegis/gui" `
    --add-data "aegis/gui/main.css;aegis/gui" `
    --add-data "aegis/gui/app.js;aegis/gui" `
    --hidden-import "clr" `
    --hidden-import "pythonnet" `
    --hidden-import "webview" `
    --hidden-import "webview.platforms.winforms" `
    --hidden-import "aegis.bridge" `
    --hidden-import "aegis.core.pipeline" `
    --hidden-import "aegis.core.frame_model" `
    --hidden-import "aegis.core.source_scanner" `
    --hidden-import "aegis.core.poc_synthesizer" `
    --hidden-import "aegis.core.patch_engineer" `
    --hidden-import "aegis.core.checksec" `
    --hidden-import "aegis.core.cyclic" `
    packaging/app_launcher.py

if ($LASTEXITCODE -eq 0) {
    Write-Host "`n======================================================================" -ForegroundColor Green
    Write-Host "  BUILD SUCCESSFUL! STANDALONE EXECUTABLE READY:" -ForegroundColor Green
    Write-Host "  $ROOT\dist\AegisStudio.exe" -ForegroundColor White
    Write-Host "======================================================================`n" -ForegroundColor Green
} else {
    Write-Host "`n[!] PyInstaller build failed with exit code $LASTEXITCODE" -ForegroundColor Red
}
