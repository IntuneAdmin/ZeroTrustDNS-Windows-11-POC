#Zero Trust DNS PoC Script
#Do not run this in Production
# Jan Mulder - Wolkenman.nl
# 19/09/2026

#requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows 11 - ZTDNS Proof of Concept v3 deployment

.DESCRIPTION
    Configures:
      - Cloudflare 1.1.1.1 as Windows DoH resolver
      - Cloudflare 1.1.1.1 as ZTDNS trusted DoH server
      - ZTDNS Audit Mode
      - ZTDNS MDM bypass = allow
      - Windows 365 / Azure platform exceptions
      - Microsoft 365 PoC IP exceptions

    A transcript is written to C:\Temp\ZTDNS-Windows365-POC-yyyyMMdd-HHmmss.txt

    IMPORTANT:
      This is a PoC configuration. Microsoft 365 and Windows 365 endpoint
      ranges can change. Do not treat the static ranges in this script as
      production source data.
#>

[CmdletBinding()]
param(
    [string]$DnsServer = "1.1.1.1",
    [string]$DohTemplate = "https://cloudflare-dns.com/dns-query",
    [int]$DohPort = 443,
    [switch]$SkipM365Exceptions,
    [switch]$SkipWindows365Exceptions
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

$LogFolder = "C:\Temp"
New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null

$LogFile = Join-Path $LogFolder ("ZTDNS-Windows365-POC-{0}.txt" -f (Get-Date -Format "yyyyMMdd-HHmmss"))

Start-Transcript -Path $LogFile -Force | Out-Null

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Invoke-Netsh {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [string]$Description = "netsh command"
    )

    Write-Host ""
    Write-Host ">> netsh ztdns $($Arguments -join ' ')" -ForegroundColor DarkGray

    $output = & netsh ztdns @Arguments 2>&1
    $exitCode = $LASTEXITCODE

    if ($output) {
        $output | ForEach-Object { Write-Host $_ }
    }

    if ($exitCode -ne 0) {
        throw "$Description failed. netsh exit code: $exitCode"
    }

    return $output
}

function Add-ZtdnsException {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Description,
        [Parameter(Mandatory)][string[]]$Subnets
    )

    Write-Host ""
    Write-Host "Checking ZTDNS exception: $Name" -ForegroundColor Yellow

    # show exception returns an error when the named group does not exist.
    $existing = & netsh ztdns show exception "name=$Name" 2>&1
    $existingExitCode = $LASTEXITCODE

    if ($existingExitCode -eq 0) {
        Write-Host "[$Name] already exists - leaving existing configuration unchanged." -ForegroundColor DarkYellow
        $existing | ForEach-Object { Write-Host $_ }
        return
    }

    $subnetList = $Subnets -join ","

    Invoke-Netsh `
        -Arguments @(
            "add", "exception",
            "name=$Name",
            "description=$Description",
            "subnets=$subnetList"
        ) `
        -Description "Adding ZTDNS exception $Name"

    Write-Host "[$Name] added successfully." -ForegroundColor Green
}

try {
    Write-Step "ZTDNS Windows 365 PoC - START"

    Write-Host "Computer : $env:COMPUTERNAME"
    Write-Host "User     : $env:USERNAME"
    Write-Host "Date     : $(Get-Date)"
    Write-Host "Log file : $LogFile"

    # -----------------------------------------------------------------------
    # 1. Configure Windows DNS over HTTPS
    # -----------------------------------------------------------------------

    Write-Step "1. Configure Cloudflare DoH"

    $doh = Get-DnsClientDohServerAddress -ServerAddress $DnsServer -ErrorAction SilentlyContinue

    if ($null -ne $doh) {
        Write-Host "DoH entry for $DnsServer already exists. Updating it..." -ForegroundColor Yellow

        Set-DnsClientDohServerAddress `
            -ServerAddress $DnsServer `
            -DohTemplate $DohTemplate `
            -AllowFallbackToUdp $false `
            -AutoUpgrade $false
    }
    else {
        Add-DnsClientDohServerAddress `
            -ServerAddress $DnsServer `
            -DohTemplate $DohTemplate `
            -AllowFallbackToUdp $false `
            -AutoUpgrade $false
    }

    Write-Host "Cloudflare DoH configured:" -ForegroundColor Green
    Get-DnsClientDohServerAddress -ServerAddress $DnsServer |
        Format-List ServerAddress,DohTemplate,AllowFallbackToUdp,AutoUpgrade

    # -----------------------------------------------------------------------
    # 2. Configure active Windows network adapters
    # -----------------------------------------------------------------------

    Write-Step "2. Configure Windows DNS Client"

    # Windows 365 uses a virtual network adapter. We deliberately select
    # active interfaces that have an IPv4 default gateway instead of relying
    # on HardwareInterface.
    $activeAdapters = Get-NetIPConfiguration |
        Where-Object {
            $_.IPv4DefaultGateway -ne $null -and
            $_.NetAdapter.Status -eq "Up"
        }

    if (-not $activeAdapters) {
        throw "No active network adapter with an IPv4 default gateway was found."
    }

    foreach ($adapter in $activeAdapters) {
        Write-Host "Configuring DNS on: $($adapter.InterfaceAlias) (Index $($adapter.InterfaceIndex))"

        Set-DnsClientServerAddress `
            -InterfaceIndex $adapter.InterfaceIndex `
            -ServerAddresses @($DnsServer)

        Write-Host "DNS configured successfully." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "Current DNS configuration:" -ForegroundColor Yellow
    Get-DnsClientServerAddress -AddressFamily IPv4 |
        Format-Table InterfaceAlias,InterfaceIndex,ServerAddresses -AutoSize

    # -----------------------------------------------------------------------
    # 3. Configure ZTDNS trusted DNS
    # -----------------------------------------------------------------------

    Write-Step "3. Configure ZTDNS Trusted DNS"

    # Do NOT delete all ZTDNS servers here. Microsoft documents that
    # 'netsh ztdns delete server' removes ALL trusted servers.
    # We only add 1.1.1.1 when it is not already configured.
    $trustedServer = & netsh ztdns show server "address=$DnsServer" 2>&1
    $trustedServerExitCode = $LASTEXITCODE

    if ($trustedServerExitCode -eq 0) {
        Write-Host "ZTDNS trusted server $DnsServer already exists." -ForegroundColor DarkYellow
        $trustedServer | ForEach-Object { Write-Host $_ }
    }
    else {
        Invoke-Netsh `
            -Arguments @(
                "add", "server",
                "type=doh",
                "address=$DnsServer",
                "port=$DohPort",
                "template=$DohTemplate"
            ) `
            -Description "Adding ZTDNS trusted DNS server"

        Write-Host "ZTDNS trusted DNS server added." -ForegroundColor Green
    }

    # -----------------------------------------------------------------------
    # 4. Configure ZTDNS state
    # -----------------------------------------------------------------------

    Write-Step "4. Configure ZTDNS State"

    # mdmbypass is available on the Windows build used for this PoC.
    Invoke-Netsh `
        -Arguments @(
            "set", "state",
            "enable=yes",
            "audit=yes",
            "mdmbypass=allow"
        ) `
        -Description "Configuring ZTDNS state"

    Write-Host "ZTDNS state configured." -ForegroundColor Green

    # -----------------------------------------------------------------------
    # 5. Azure / Windows 365 exceptions
    # -----------------------------------------------------------------------

    if (-not $SkipWindows365Exceptions) {
        Write-Step "5. Windows 365 / Azure Exceptions"

        Add-ZtdnsException `
            -Name "AzureIMDS" `
            -Description "Azure Instance Metadata Service for Windows 365" `
            -Subnets @("169.254.169.254")

        Add-ZtdnsException `
            -Name "AzureWireServer" `
            -Description "Azure WireServer for Windows 365 platform communication" `
            -Subnets @("168.63.129.16")

        # Current Microsoft Windows 365 documentation lists these Azure KMS
        # endpoints. Verify against Microsoft documentation before production.
        Add-ZtdnsException `
            -Name "AzureKMS" `
            -Description "Azure KMS for Windows 365 activation" `
            -Subnets @(
                "20.118.99.224/32",
                "40.83.245.53/32",
                "23.102.135.246/32"
            )

        Add-ZtdnsException `
            -Name "Windows365RDP" `
            -Description "Windows 365 RDP infrastructure - TURN/STUN" `
            -Subnets @("51.5.0.0/16")

        Add-ZtdnsException `
            -Name "Windows365RDPTCP" `
            -Description "Windows 365 RDP TCP connectivity" `
            -Subnets @("40.64.144.0/20")
    }
    else {
        Write-Host "Windows 365 exceptions skipped by parameter." -ForegroundColor DarkYellow
    }

    # -----------------------------------------------------------------------
    # 6. Microsoft 365 exceptions
    # -----------------------------------------------------------------------

    if (-not $SkipM365Exceptions) {
        Write-Step "6. Microsoft 365 PoC Exceptions"

        Add-ZtdnsException `
            -Name "M365Exchange" `
            -Description "Microsoft 365 Exchange Online required IP ranges - PoC" `
            -Subnets @(
                "13.107.6.152/31",
                "13.107.18.10/31",
                "13.107.128.0/22",
                "23.103.160.0/20",
                "40.96.0.0/13",
                "40.104.0.0/15",
                "52.96.0.0/14",
                "131.253.33.215/32",
                "132.245.0.0/16",
                "150.171.32.0/22",
                "204.79.197.215/32"
            )

        Add-ZtdnsException `
            -Name "M365Identity" `
            -Description "Microsoft 365 Entra ID and identity required IP ranges - PoC" `
            -Subnets @(
                "20.20.32.0/19",
                "20.190.128.0/18",
                "20.231.128.0/19",
                "40.126.0.0/18"
            )

        Add-ZtdnsException `
            -Name "M365Office" `
            -Description "Microsoft 365 Office Online required IP ranges - PoC" `
            -Subnets @(
                "13.107.6.171/32",
                "13.107.18.15/32",
                "13.107.140.6/32",
                "52.108.0.0/14",
                "52.244.37.168/32"
            )

        Add-ZtdnsException `
            -Name "M365SharePoint" `
            -Description "Microsoft 365 SharePoint Online and OneDrive required IP ranges - PoC" `
            -Subnets @(
                "13.107.136.0/22",
                "40.108.128.0/17",
                "52.104.0.0/14",
                "104.146.128.0/17",
                "150.171.40.0/22"
            )

        Add-ZtdnsException `
            -Name "M365Teams" `
            -Description "Microsoft Teams required IP ranges - PoC" `
            -Subnets @(
                "52.112.0.0/14",
                "52.122.0.0/15"
            )
    }
    else {
        Write-Host "Microsoft 365 exceptions skipped by parameter." -ForegroundColor DarkYellow
    }

    # -----------------------------------------------------------------------
    # 7. Validation
    # -----------------------------------------------------------------------

    Write-Step "7. Validate ZTDNS State"

    Write-Host "`n--- ZTDNS STATE ---" -ForegroundColor Yellow
    & netsh ztdns show state

    Write-Host "`n--- ZTDNS TRUSTED SERVERS ---" -ForegroundColor Yellow
    & netsh ztdns show server

    Write-Host "`n--- ZTDNS EXCEPTIONS ---" -ForegroundColor Yellow
    & netsh ztdns show exception

    Write-Host "`n--- WINDOWS DoH ---" -ForegroundColor Yellow
    Get-DnsClientDohServerAddress -ServerAddress $DnsServer |
        Format-List ServerAddress,DohTemplate,AllowFallbackToUdp,AutoUpgrade

    Write-Host "`n--- WINDOWS DNS CLIENT ---" -ForegroundColor Yellow
    Get-DnsClientServerAddress -AddressFamily IPv4 |
        Format-Table InterfaceAlias,InterfaceIndex,ServerAddresses -AutoSize

    # -----------------------------------------------------------------------
    # 8. DNS tests
    # -----------------------------------------------------------------------

    Write-Step "8. DNS Tests"

    Write-Host "Test 1: Direct query to Cloudflare 1.1.1.1" -ForegroundColor Yellow
    Resolve-DnsName "www.microsoft.com" -Server $DnsServer |
        Format-Table Name,Type,TTL,IPAddress -AutoSize

    Write-Host ""
    Write-Host "Test 2: Normal Windows DNS resolution" -ForegroundColor Yellow

    try {
        Resolve-DnsName "www.microsoft.com" |
            Format-Table Name,Type,TTL,IPAddress -AutoSize

        Write-Host "Normal Windows DNS resolution: SUCCESS" -ForegroundColor Green
    }
    catch {
        Write-Warning "Normal Windows DNS resolution failed: $($_.Exception.Message)"
        Write-Host "The direct DoH test above can still be used to verify connectivity to the trusted DNS server."
    }

    Write-Step "ZTDNS Windows 365 PoC - COMPLETE"

    Write-Host "Log file:" -ForegroundColor Yellow
    Write-Host $LogFile -ForegroundColor Green

    Write-Host ""
    Write-Host "NOTE: This is a PoC. Review Microsoft 365 and Windows 365 endpoint requirements before production deployment." -ForegroundColor Yellow
}
catch {
    Write-Host ""
    Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
    Write-Host "ZTDNS POC FAILED" -ForegroundColor Red
    Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "See log: $LogFile" -ForegroundColor Yellow

    exit 1
}
finally {
    Stop-Transcript | Out-Null
}
