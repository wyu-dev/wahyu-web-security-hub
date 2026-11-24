<#
.SYNOPSIS
    Skill entrypoint wrapper that locates and invokes WSAS local-audit.ps1.
    Works both directly inside wahyu-web-security-hub and when installed globally via install-skill.ps1.
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

$SkillDir = Split-Path -Parent $PSScriptRoot
$Candidates = @(
    (Join-Path $SkillDir "resources\wsas-hub\scripts\local-audit.ps1"),
    (Join-Path (Split-Path -Parent (Split-Path -Parent $SkillDir)) "scripts\local-audit.ps1")
)

$AuditScript = $Candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $AuditScript) {
    throw "Could not locate WSAS scripts/local-audit.ps1. Re-run install-skill.ps1 from wahyu-web-security-hub."
}

$params = @{
    TargetPath = $TargetPath
    FailOn     = $FailOn
    AiModel    = $AiModel
}
if (-not [string]::IsNullOrWhiteSpace($OutputDir)) {
    $params["OutputDir"] = $OutputDir
}
if ($EnableAiReview) {
    $params["EnableAiReview"] = $true
}

& $AuditScript @params
exit $LASTEXITCODE
