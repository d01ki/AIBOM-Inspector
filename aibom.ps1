<#
.SYNOPSIS
AIBOM Inspector launcher - one command, no Docker flags to remember.

.DESCRIPTION
  .\aibom.ps1                  guided menu
  .\aibom.ps1 ui               web UI at http://localhost:8000
  .\aibom.ps1 demo             offline blast-radius + drift demo
  .\aibom.ps1 scan .           scan this directory
  .\aibom.ps1 scan https://... scan a public repo URL
  .\aibom.ps1 diff old\ new\   behavioral drift between two revisions

Local paths are mounted read-only and rewritten automatically; reports land in
.\aibom-out. Anything not listed above is passed straight to the CLI.
#>
[CmdletBinding()]
param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CliArgs)

$ErrorActionPreference = 'Stop'

$image = if ($env:AIBOM_IMAGE) { $env:AIBOM_IMAGE } else { 'aibom-inspector' }
$port = if ($env:AIBOM_PORT) { $env:AIBOM_PORT } else { '8000' }
$here = $PSScriptRoot
$work = (Get-Location).ProviderPath
$out = Join-Path $work 'aibom-out'

function Stop-WithError($message) {
    Write-Host "error: $message" -ForegroundColor Red
    exit 2
}

function Assert-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Stop-WithError "Docker is not installed. Install Docker Desktop, or run 'pip install -e .' and use 'aibom' directly."
    }
    docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError 'the Docker daemon is not responding. Start Docker Desktop, wait for it to report ready, then rerun.'
    }
}

function Confirm-Image {
    docker image inspect $image *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Building the $image image (first run only)..."
        docker build -t $image $here
        if ($LASTEXITCODE -ne 0) { Stop-WithError 'the image build failed.' }
    }
}

# Rewrite an existing host path into its mounted location inside the container.
function Convert-Arg($value) {
    if ($value -like '-*' -or $value -match '://') { return $value }
    if (-not (Test-Path -LiteralPath $value)) { return $value }
    $abs = (Resolve-Path -LiteralPath $value).ProviderPath.TrimEnd('\', '/')
    $root = $work.TrimEnd('\', '/')
    if ($abs -eq $root) { return '/work' }
    if ($abs.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar)) {
        $relative = $abs.Substring($root.Length + 1).Replace('\', '/')
        return "/work/$relative"
    }
    Stop-WithError "'$value' is outside $work. cd to a directory that contains it, then rerun."
}

function Invoke-Cli([string[]]$commandArgs) {
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    $mapped = @()
    foreach ($item in $commandArgs) { $mapped += (Convert-Arg $item) }
    docker run --rm -it -v "${work}:/work:ro" -v "${out}:/out" -w /work $image aibom @mapped
    exit $LASTEXITCODE
}

Assert-Docker
Confirm-Image

$first = if ($CliArgs.Count -gt 0) { $CliArgs[0] } else { '' }

switch -Regex ($first) {
    '^(ui|serve|web)$' {
        Write-Host "AIBOM Inspector UI -> http://localhost:$port   (Ctrl-C to stop)"
        docker run --rm -it -p "${port}:8000" -e "AIBOM_PORT=$port" $image
        exit $LASTEXITCODE
    }
    '^(-h|--help|help)$' {
        Get-Help $PSCommandPath -Detailed
        Invoke-Cli @('--help')
    }
    default { Invoke-Cli $CliArgs }
}
