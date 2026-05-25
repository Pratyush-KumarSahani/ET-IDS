param(
    [int]$Port = 8000,
    [string]$HostAddress = "0.0.0.0",
    [string]$PythonVersion = "3.12",
    [string]$ModelPath = "",
    [string]$LabelEncoderPath = "",
    [string]$CaptureInterface = "",
    [string]$CaptureFilter = "tcp or udp",
    [switch]$NoCapture,
    [switch]$UseWindowsFirewall,
    [switch]$SkipInstall,
    [switch]$OpenDashboard
)

$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-NpcapInstalled {
    $registryPaths = @(
        "HKLM:\SOFTWARE\Npcap",
        "HKLM:\SOFTWARE\WOW6432Node\Npcap"
    )

    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            return $true
        }
    }

    $packetDll = Join-Path $env:WINDIR "System32\Npcap\Packet.dll"
    return Test-Path $packetDll
}

function Write-SetupStep {
    param(
        [string]$Name,
        [string]$Status,
        [ConsoleColor]$Color = "Gray"
    )

    Write-Host ("[{0}] {1}" -f $Status, $Name) -ForegroundColor $Color
}

function Resolve-Python {
    param([string]$RequestedVersion)

    # FIRST: use local venv if available
    $venvPython = Join-Path $PSScriptRoot "venv\Scripts\python.exe"

    if (Test-Path $venvPython) {
        $versionOutput = & $venvPython --version 2>&1

        return @{
            Command = $venvPython
            Args = @()
            Version = ($versionOutput | Out-String).Trim()
        }
    }

    # FALLBACK: global python
    $candidates = @(
        @("py", "-$RequestedVersion"),
        @("py", "-3.11"),
        @("python", "")
    )

    foreach ($candidate in $candidates) {
        $command = $candidate[0]
        $versionArg = $candidate[1]

        try {
            $args = @()

            if ($versionArg) {
                $args += $versionArg
            }

            $args += "--version"

            $versionOutput = & $command @args 2>&1

            if ($LASTEXITCODE -ne 0) {
                continue
            }

            $versionText = ($versionOutput | Out-String).Trim()

            if ($versionText -match "3\.13\.0a") {
                Write-Warning "Skipping unstable Python build."
                continue
            }

            $runArgs = @()

            if ($versionArg) {
                $runArgs += $versionArg
            }

            return @{
                Command = $command
                Args = $runArgs
                Version = $versionText
            }
        }
        catch {
            continue
        }
    }

    throw "Could not find Python."
}

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

Write-Host ""
Write-Host "ET-IDS setup wizard" -ForegroundColor Cyan
Write-Host "Project: $projectRoot"
Write-Host ""

$isAdmin = Test-IsAdministrator

if ($isAdmin) {
    Write-SetupStep -Name "Administrator permission" -Status "OK" -Color Green
}
elseif (-not $NoCapture) {
    Write-SetupStep -Name "Administrator permission" -Status "NEEDED" -Color Yellow
    Write-Warning "Live packet capture on Windows usually requires running this launcher as Administrator."
}
else {
    Write-SetupStep -Name "Administrator permission" -Status "SKIP" -Color DarkGray
}

if (-not $NoCapture) {
    if (Test-NpcapInstalled) {
        Write-SetupStep -Name "Npcap packet driver" -Status "OK" -Color Green
    }
    else {
        Write-SetupStep -Name "Npcap packet driver" -Status "MISSING" -Color Yellow
        Write-Warning "Install Npcap first for live capture: https://npcap.com/#download"
        Write-Warning "You can still open the dashboard without capture by running .\start_ids.ps1 -NoCapture -OpenDashboard."
    }

    Write-SetupStep -Name "Live capture" -Status "ON" -Color Green
    Write-Host "Capture filter: $CaptureFilter"
}
else {
    Write-SetupStep -Name "Live capture" -Status "OFF" -Color DarkGray
}

$python = Resolve-Python -RequestedVersion $PythonVersion
Write-SetupStep -Name "Python runtime $($python.Version)" -Status "OK" -Color Green

if (-not $SkipInstall) {
    Write-SetupStep -Name "Python requirements" -Status "INSTALL" -Color Cyan
    & $python.Command @($python.Args + @("-m", "pip", "install", "-r", "requirements.txt"))
    if ($LASTEXITCODE -ne 0) {
        throw "Dependency installation failed."
    }
}
else {
    Write-SetupStep -Name "Python requirements" -Status "SKIP" -Color DarkGray
}

if ($ModelPath) {
    $env:IDS_MODEL_PATH = $ModelPath
}

if ($LabelEncoderPath) {
    $env:IDS_LABEL_ENCODER_PATH = $LabelEncoderPath
}

if ($CaptureInterface) {
    $env:IDS_CAPTURE_INTERFACE = $CaptureInterface
}

if ($CaptureFilter) {
    $env:IDS_CAPTURE_FILTER = $CaptureFilter
}

$env:IDS_AUTO_START = if ($NoCapture) { "false" } else { "true" }
$env:IDS_BLOCK_MODE = if ($UseWindowsFirewall) { "windows_firewall" } else { "memory" }

$dashboardUrl = "http://localhost:$Port"
Write-Host ""
Write-Host "Starting ET-IDS dashboard..." -ForegroundColor Green
Write-Host "Open: $dashboardUrl"
if ($HostAddress -eq "0.0.0.0") {
    Write-Host "LAN access: use http://YOUR-COMPUTER-IP:$Port from another device on the same network."
}
Write-Host "Press Ctrl+C to stop the server."
Write-Host ""

if ($OpenDashboard) {
    Start-Process $dashboardUrl
}

& $python.Command @($python.Args + @("-m", "uvicorn", "fastapi_ids_backend:app", "--host", $HostAddress, "--port", "$Port"))
