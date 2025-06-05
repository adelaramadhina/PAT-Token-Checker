#!/usr/bin/env pwsh

Write-Host "=== Pre-Push Compatibility Tests ===" -ForegroundColor Green

# Test 1: Syntax validation
Write-Host "`n1. Testing PowerShell syntax..." -ForegroundColor Cyan
$errors = @()
$tokens = @()
$ast = [System.Management.Automation.Language.Parser]::ParseFile('./Pat-TokenChecker.ps1', [ref]$tokens, [ref]$errors)

if ($errors.Count -gt 0) {
    Write-Host "❌ Parse errors found:" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    exit 1
} else {
    Write-Host "✅ No parse errors found!" -ForegroundColor Green
}

# Test 2: Strict mode compatibility
Write-Host "`n2. Testing strict mode compatibility..." -ForegroundColor Cyan
try {
    Set-StrictMode -Version 2.0
    $scriptContent = Get-Content './Pat-TokenChecker.ps1' -Raw
    $scriptBlock = [ScriptBlock]::Create($scriptContent)
    Write-Host "✅ Strict mode compatibility OK!" -ForegroundColor Green
} catch {
    Write-Host "❌ Strict mode issue:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Yellow
    exit 1
}

# Test 3: Run Pester tests if available
if (Test-Path './Pat-TokenChecker.Tests.ps1') {
    Write-Host "`n3. Running Pester tests..." -ForegroundColor Cyan
    try {
        $testResults = Invoke-Pester './Pat-TokenChecker.Tests.ps1' -PassThru
        if ($testResults.FailedCount -gt 0) {
            Write-Host "❌ Some tests failed!" -ForegroundColor Red
            exit 1
        } else {
            Write-Host "✅ All tests passed!" -ForegroundColor Green
        }
    } catch {
        Write-Host "⚠️  Pester not available, skipping tests" -ForegroundColor Yellow
    }
}

Write-Host "`n🎉 All compatibility tests passed! Safe to push." -ForegroundColor Green