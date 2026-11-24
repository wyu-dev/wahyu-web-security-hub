<#
.SYNOPSIS
    WSAS Mode A — Local Manual Security Audit Orchestrator for Windows / Antigravity IDE.
.DESCRIPTION
    Detects project stack automatically, executes available security scanners without ever
    pretending missing tools have run, redacts all sensitive credentials, and generates
    both Markdown and JSON reports with Security Score and Release Gate status.
.EXAMPLE
    .\scripts\local-audit.ps1 -TargetPath "C:\path\to\project"
.EXAMPLE
    .\scripts\local-audit.ps1 -TargetPath ".\tests\fixtures\react-firebase-vuln" -FailOn "high"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetPath,

    [string]$OutputDir = "",

    [ValidateSet("none", "critical", "high", "medium")]
    [string]$FailOn = "none",

    [switch]$EnableAiReview,

    [string]$AiModel = "google/gemini-2.5-flash"
)

$ErrorActionPreference = "Stop"

$HubRoot = Split-Path -Parent $PSScriptRoot
$ResolvedTarget = (Resolve-Path -LiteralPath $TargetPath).Path
$ProjectName = Split-Path -Leaf $ResolvedTarget
$SafeName = ($ProjectName -replace '[^A-Za-z0-9._-]', '-')
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $HubRoot "reports"
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$WorkDir = Join-Path $OutputDir ".tmp-$SafeName-$Timestamp"
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    $PythonCmd = Get-Command py -ErrorAction SilentlyContinue
}
if (-not $PythonCmd) {
    throw "Python 3 is required to run WSAS scripts. Install Python 3 and retry."
}
$PyExe = $PythonCmd.Source

$StackJson = Join-Path $WorkDir "stack.json"
$StaticJson = Join-Path $WorkDir "static.json"
$GitleaksJson = Join-Path $WorkDir "gitleaks.json"
$NpmAuditJson = Join-Path $WorkDir "npm-audit.json"
$ComposerAuditJson = Join-Path $WorkDir "composer-audit.json"
$SemgrepJson = Join-Path $WorkDir "semgrep.json"
$ToolsStatusJson = Join-Path $WorkDir "tools-status.json"

$OutMd = Join-Path $OutputDir "$SafeName-audit-$Timestamp.md"
$OutJson = Join-Path $OutputDir "$SafeName-audit-$Timestamp.json"

$ToolsStatus = New-Object System.Collections.ArrayList

function Add-ToolStatus {
    param([string]$Name, [string]$Status, [string]$Notes)
    [void]$ToolsStatus.Add([PSCustomObject]@{
        name   = $Name
        status = $Status
        notes  = $Notes
    })
}

try {
    Write-Host "`n[1/6] Detecting project stack..." -ForegroundColor Cyan
    & $PyExe (Join-Path $PSScriptRoot "detect-stack.py") $ResolvedTarget --output $StackJson
    if ($LASTEXITCODE -ne 0) { throw "Stack detection failed." }

    $StackObj = Get-Content -LiteralPath $StackJson -Raw | ConvertFrom-Json
    $ProfilesCsv = ($StackObj.profiles -join ",")

    Write-Host "`n[2/6] Running WSAS built-in static & configuration checks..." -ForegroundColor Cyan
    & $PyExe (Join-Path $PSScriptRoot "static-checks.py") $ResolvedTarget --profiles $ProfilesCsv --output $StaticJson
    if ($LASTEXITCODE -eq 0) {
        Add-ToolStatus -Name "wsas-static-checks" -Status "executed" -Notes "Profiles applied: $ProfilesCsv"
    } else {
        Add-ToolStatus -Name "wsas-static-checks" -Status "error" -Notes "Static checks exited with code $LASTEXITCODE"
    }

    Write-Host "`n[3/6] Checking Secret Scanner (Betterleaks / Gitleaks)..." -ForegroundColor Cyan
    $BetterleaksCmd = Get-Command betterleaks -ErrorAction SilentlyContinue
    $GitleaksCmd = Get-Command gitleaks -ErrorAction SilentlyContinue

    if ($BetterleaksCmd) {
        $prevPref = $ErrorActionPreference; $ErrorActionPreference = "Continue"
        & $BetterleaksCmd.Source detect --source $ResolvedTarget --no-git --report-format json --report-path $GitleaksJson --exit-code 0 2>$null
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prevPref
        Add-ToolStatus -Name "betterleaks" -Status "executed" -Notes "Scanned filesystem (exit=$code)"
    } elseif ($GitleaksCmd) {
        $prevPref = $ErrorActionPreference; $ErrorActionPreference = "Continue"
        & $GitleaksCmd.Source detect --source $ResolvedTarget --no-git --report-format json --report-path $GitleaksJson --exit-code 0 2>$null
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prevPref
        Add-ToolStatus -Name "gitleaks" -Status "executed" -Notes "Scanned filesystem (exit=$code)"
    } else {
        Write-Host "  -> gitleaks/betterleaks not installed locally (recorded honestly; install via 'winget install Gitleaks.Gitleaks')." -ForegroundColor Yellow
        Add-ToolStatus -Name "gitleaks/betterleaks" -Status "not_installed" -Notes "Install Gitleaks (winget install Gitleaks.Gitleaks) or Betterleaks for full history & entropy secret scanning."
    }

    Write-Host "`n[4/6] Checking Dependency Audits (npm / composer)..." -ForegroundColor Cyan
    $NpmLock = Join-Path $ResolvedTarget "package-lock.json"
    $NpmCmd = Get-Command npm -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $NpmLock) {
        if ($NpmCmd) {
            Push-Location -LiteralPath $ResolvedTarget
            try {
                $prevPref = $ErrorActionPreference; $ErrorActionPreference = "Continue"
                $npmOut = & npm audit --json 2>$null
                $npmCode = $LASTEXITCODE
                $ErrorActionPreference = $prevPref
                if ($npmOut) {
                    $npmOut | Out-File -FilePath $NpmAuditJson -Encoding utf8
                }
                Add-ToolStatus -Name "npm-audit" -Status "executed" -Notes "Completed against package-lock.json (exit=$npmCode)"
            } finally {
                Pop-Location
            }
        } else {
            Add-ToolStatus -Name "npm-audit" -Status "not_installed" -Notes "package-lock.json found, but npm is not installed."
        }
    } else {
        Add-ToolStatus -Name "npm-audit" -Status "skipped_not_applicable" -Notes "No package-lock.json present in target project."
    }

    $ComposerLock = Join-Path $ResolvedTarget "composer.lock"
    $ComposerCmd = Get-Command composer -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $ComposerLock) {
        if ($ComposerCmd) {
            Push-Location -LiteralPath $ResolvedTarget
            try {
                $prevPref = $ErrorActionPreference; $ErrorActionPreference = "Continue"
                $compOut = & composer audit --format=json 2>$null
                $compCode = $LASTEXITCODE
                $ErrorActionPreference = $prevPref
                if ($compOut) {
                    $compOut | Out-File -FilePath $ComposerAuditJson -Encoding utf8
                }
                Add-ToolStatus -Name "composer-audit" -Status "executed" -Notes "Completed against composer.lock (exit=$compCode)"
            } finally {
                Pop-Location
            }
        } else {
            Add-ToolStatus -Name "composer-audit" -Status "not_installed" -Notes "composer.lock found, but composer is not installed."
        }
    } else {
        Add-ToolStatus -Name "composer-audit" -Status "skipped_not_applicable" -Notes "No composer.lock present in target project."
    }

    Write-Host "`n[5/6] Checking Semgrep SAST..." -ForegroundColor Cyan
    $SemgrepCmd = Get-Command semgrep -ErrorAction SilentlyContinue
    if ($SemgrepCmd) {
        $prevPref = $ErrorActionPreference; $ErrorActionPreference = "Continue"
        & $SemgrepCmd.Source scan --config auto --json --json-output $SemgrepJson $ResolvedTarget 2>$null
        $sgCode = $LASTEXITCODE
        $ErrorActionPreference = $prevPref
        Add-ToolStatus -Name "semgrep" -Status "executed" -Notes "Scanned with --config auto (exit=$sgCode)"
    } else {
        Write-Host "  -> semgrep not installed locally (recorded honestly; runs automatically in GitHub Actions or install via pip/WSL)." -ForegroundColor Yellow
        Add-ToolStatus -Name "semgrep" -Status "not_installed" -Notes "Not installed locally. Use GitHub Actions reusable workflow or install Semgrep CLI."
    }

    Add-ToolStatus -Name "owasp-zap" -Status "skipped_not_applicable" -Notes "Passive DAST requires an authorized running staging URL (never run active scans on production without explicit approval)."

    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ToolsStatusJson, ($ToolsStatus | ConvertTo-Json -Depth 4), $Utf8NoBom)

    Write-Host "`n[6/6] Generating Markdown & JSON Security Audit Reports..." -ForegroundColor Cyan
    $genArgs = @(
        (Join-Path $PSScriptRoot "generate-report.py"),
        "--stack", $StackJson,
        "--static", $StaticJson,
        "--tools-status", $ToolsStatusJson,
        "--mode", "manual-local",
        "--out-md", $OutMd,
        "--out-json", $OutJson,
        "--fail-on", $FailOn
    )
    if (Test-Path -LiteralPath $GitleaksJson) { $genArgs += @("--gitleaks", $GitleaksJson) }
    if (Test-Path -LiteralPath $NpmAuditJson) { $genArgs += @("--npm-audit", $NpmAuditJson) }
    if (Test-Path -LiteralPath $ComposerAuditJson) { $genArgs += @("--composer-audit", $ComposerAuditJson) }
    if (Test-Path -LiteralPath $SemgrepJson) { $genArgs += @("--semgrep", $SemgrepJson) }

    $prevPref = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    & $PyExe @genArgs
    $GateExitCode = $LASTEXITCODE
    $ErrorActionPreference = $prevPref

    if ($EnableAiReview) {
        Write-Host "`n[Optional] Running redacted OpenRouter AI review..." -ForegroundColor Cyan
        $AiOutMd = Join-Path $OutputDir "$SafeName-ai-review-$Timestamp.md"
        & $PyExe (Join-Path $PSScriptRoot "ai-review.py") --report-json $OutJson --model $AiModel --output $AiOutMd
    }

    exit $GateExitCode
}
finally {
    if (Test-Path -LiteralPath $WorkDir) {
        Remove-Item -LiteralPath $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
