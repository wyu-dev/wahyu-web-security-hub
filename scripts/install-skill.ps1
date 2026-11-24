<#
.SYNOPSIS
    Installs the WSAS `web-security-audit` skill into Antigravity IDE.
.DESCRIPTION
    Supports both verified Antigravity discovery paths:
      - Global (all projects on this machine): ~/.gemini/config/skills/web-security-audit
      - Workspace (single project VCS):        <WorkspacePath>/.agents/skills/web-security-audit
.EXAMPLE
    .\scripts\install-skill.ps1 -Scope Global
.EXAMPLE
    .\scripts\install-skill.ps1 -Scope Workspace -WorkspacePath "C:\path\to\my-project"
#>

[CmdletBinding()]
param(
    [ValidateSet("Global", "Workspace")]
    [string]$Scope = "Global",

    [string]$WorkspacePath = ""
)

$ErrorActionPreference = "Stop"

$HubRoot = Split-Path -Parent $PSScriptRoot
$SourceSkill = Join-Path $HubRoot "skills\web-security-audit"

if (-not (Test-Path -LiteralPath (Join-Path $SourceSkill "SKILL.md"))) {
    throw "Source skill not found at $SourceSkill"
}

if ($Scope -eq "Global") {
    $DestDir = Join-Path $HOME ".gemini\config\skills\web-security-audit"
} else {
    if ([string]::IsNullOrWhiteSpace($WorkspacePath)) {
        throw "WorkspacePath is required when -Scope Workspace is selected."
    }
    $ResolvedWs = (Resolve-Path -LiteralPath $WorkspacePath).Path
    $DestDir = Join-Path $ResolvedWs ".agents\skills\web-security-audit"
}

New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
Copy-Item -Path (Join-Path $SourceSkill "*") -Destination $DestDir -Recurse -Force

# Also bundle hub scripts + profiles into resources/ so global skill works from any repo
$BundledHub = Join-Path $DestDir "resources\wsas-hub"
New-Item -ItemType Directory -Force -Path (Join-Path $BundledHub "scripts") | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $BundledHub "profiles") | Out-Null
Copy-Item -Path (Join-Path $HubRoot "scripts\*") -Destination (Join-Path $BundledHub "scripts") -Recurse -Force
Copy-Item -Path (Join-Path $HubRoot "profiles\*") -Destination (Join-Path $BundledHub "profiles") -Recurse -Force

# Verify installed SKILL.md frontmatter
$InstalledSkillMd = Join-Path $DestDir "SKILL.md"
$Raw = Get-Content -LiteralPath $InstalledSkillMd -Raw
if ($Raw -notmatch "(?s)^---\r?\n.*?name:\s*web-security-audit.*?description:.*?---") {
    throw "Installed SKILL.md failed frontmatter validation!"
}

Write-Host "Successfully installed Antigravity skill 'web-security-audit' ($Scope):" -ForegroundColor Green
Write-Host "  Location : $DestDir"
Write-Host "  Verified : SKILL.md YAML frontmatter valid, scripts & profiles bundled."
