#requires -RunAsAdministrator

<#
.SYNOPSIS
    Removes the Windows 11 ZTDNS PoC configuration.

.DESCRIPTION
    Reverses the changes made by the ZeroTrustDNS-Windows-11-POC installation script:

      - Disables ZTDNS enforcement
      - Removes the POC ZTDNS exceptions
      - Removes the POC Cloudflare DoH configuration for 1.1.1.1
      - Resets DNS server configuration on active adapters to DHCP/default
      - Removes the Cloudflare 1.1.1.1 ZTDNS trusted server when it is the
        only trusted server configured

    IMPORTANT:
      Microsoft documents `netsh ztdns delete server` as deleting ALL
      trusted ZTDNS servers. Therefore this script will only execute that
      command when it detects that 1.1.1.1 is the only configured trusted
      server.

      If other trusted ZTDNS servers are present, they are left untouched
      and a warning is written to the log.

      The script cannot reconstruct a pre-existing custom DNS/DoH configuration
      because the original state was not captured by the installation script.
      It therefore restores the Windows DNS interfaces to their default/DHCP
      DNS configuration and removes the POC Cloudflare DoH entry.

    Run from an elevated PowerShell session.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

$LogFolder = "C:\Temp"
New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null

$LogFile = Join-Path $LogFolder (
    "Remove-ZTDNS-Windows11-POC-{0}.txt" -f (Get-Date -Format "yyyyMMdd-HHmmss")
)

Start-Transcript -Path $LogFile -Force | Out-Null

$DnsServer = "1.1.1.1"

$PocExceptions = @(
    "AzureIMDS",
    "AzureWireServer",
    "AzureKMS",
    "Windows365RDP",
    "Windows365RDPTCP",
    "M365Exchange",
    "M365Identity",
    "M365Office",
    "M365SharePoint",
    "M365Teams",
    "OneDriveTest"
)

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Invoke-Ztdns {
    param(
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Description,
        [switch]$IgnoreErrors
    )

    Write-Host ""
    Write-Host ">> netsh ztdns $($Arguments -join ' ')" -ForegroundColor DarkGray

    $output = & netsh ztdns @Arguments 2>&1
    $exitCode = $LASTEXITCODE

    if ($output) {
        $output | ForEach-Object { Write-Host $_ }
    }

    if ($exitCode -ne 0 -and -not $IgnoreErrors) {
        throw "$Description failed. netsh exit code: $exitCode"
    }

    return $output
}

try {
    Write-Step "ZTDNS Windows 11 PoC - REMOVE"

    Write-Host "Computer : $env:COMPUTERNAME"
    Write-Host "User     : $env:USERNAME"
    Write-Host "Date     : $(Get-Date)"
    Write-Host "Log file : $LogFile"

    # -----------------------------------------------------------------------
    # 1. Disable ZTDNS first
    # -----------------------------------------------------------------------

    Write-Step "1. Disable ZTDNS"

    Invoke-Ztdns `
        -Arguments @(
            "set", "state",
            "enable=no",
            "audit=no"
        ) `
        -Description "Disabling ZTDNS"

    Write-Host "ZTDNS disabled." -ForegroundColor Green

    # -----------------------------------------------------------------------
    # 2. Remove POC exceptions
    # -----------------------------------------------------------------------

    Write-Step "2. Remove ZTDNS PoC Exceptions"

    foreach ($name in $PocExceptions) {

        Write-Host "Checking exception: $name" -ForegroundColor Yellow

        $existing = & netsh ztdns show exception "name=$name" 2>&1
        $existingExitCode = $LASTEXITCODE

        if ($existingExitCode -eq 0) {
            Invoke-Ztdns `
                -Arguments @(
                    "delete", "exception",
                    "name=$name"
                ) `
                -Description "Removing ZTDNS exception $name"

            Write-Host "[$name] removed." -ForegroundColor Green
        }
        else {
            Write-Host "[$name] not present - skipping." -ForegroundColor DarkGray
        }
    }

    # -----------------------------------------------------------------------
    # 3. Remove Cloudflare DoH configuration
    # -----------------------------------------------------------------------

    Write-Step "3. Remove Cloudflare DoH Configuration"

    $dohConfig = Get-DnsClientDohServerAddress `
        -ServerAddress $DnsServer `
        -ErrorAction SilentlyContinue

    if ($null -ne $dohConfig) {
        Write-Host "Removing Windows DoH configuration for $DnsServer..." -ForegroundColor Yellow

        Remove-DnsClientDohServerAddress `
            -ServerAddress $DnsServer `
            -Confirm:$false

        Write-Host "Cloudflare DoH configuration removed." -ForegroundColor Green
    }
    else {
        Write-Host "No Windows DoH configuration for $DnsServer found." -ForegroundColor DarkGray
    }

    # -----------------------------------------------------------------------
    # 4. Reset DNS client interfaces
    # -----------------------------------------------------------------------

    Write-Step "4. Reset Windows DNS Client to Default/DHCP"

    $adapters = Get-NetAdapter |
        Where-Object {
            $_.Status -eq "Up" -and
            $_.HardwareInterface -eq $true
        }

    foreach ($adapter in $adapters) {

        Write-Host "Resetting DNS on: $($adapter.Name) (Index $($adapter.ifIndex))"

        Set-DnsClientServerAddress `
            -InterfaceIndex $adapter.ifIndex `
            -ResetServerAddresses

        Write-Host "DNS reset successfully." -ForegroundColor Green
    }

    # -----------------------------------------------------------------------
    # 5. Remove Cloudflare from ZTDNS trusted servers
    # -----------------------------------------------------------------------

    Write-Step "5. Remove ZTDNS Trusted Server"

    Write-Host "Checking configured ZTDNS trusted servers..." -ForegroundColor Yellow

    $serverOutput = & netsh ztdns show server 2>&1
    $serverExitCode = $LASTEXITCODE

    if ($serverOutput) {
        $serverOutput | ForEach-Object { Write-Host $_ }
    }

    if ($serverExitCode -ne 0) {
        Write-Warning "Could not read the ZTDNS trusted server configuration."
    }
    else {
        $serverText = ($serverOutput | Out-String)

        # Extract IPv4 addresses from the output.
        $ipMatches = [regex]::Matches(
            $serverText,
            '\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ) | ForEach-Object {
            $_.Value
        } | Select-Object -Unique

        if ($ipMatches.Count -eq 1 -and $ipMatches[0] -eq $DnsServer) {

            Write-Host "Only $DnsServer is configured as a trusted ZTDNS server." -ForegroundColor Yellow
            Write-Host "Removing all trusted ZTDNS servers is safe for this POC state." -ForegroundColor Yellow

            Invoke-Ztdns `
                -Arguments @("delete", "server") `
                -Description "Removing the ZTDNS trusted server"

            Write-Host "ZTDNS trusted server removed." -ForegroundColor Green
        }
        elseif ($ipMatches.Count -eq 0) {
            Write-Warning "No IPv4 trusted server could be identified. Leaving ZTDNS trusted servers untouched."
        }
        else {
            Write-Warning "Multiple trusted ZTDNS servers are configured: $($ipMatches -join ', ')"
            Write-Warning "Leaving all trusted servers untouched to avoid deleting configuration that was not created by this POC."
            Write-Warning "Microsoft documents 'netsh ztdns delete server' as deleting ALL trusted servers."
        }
    }

    # -----------------------------------------------------------------------
    # 6. Clear DNS cache
    # -----------------------------------------------------------------------

    Write-Step "6. Clear DNS Cache"

    Clear-DnsClientCache
    Write-Host "DNS cache cleared." -ForegroundColor Green

    # -----------------------------------------------------------------------
    # 7. Validation
    # -----------------------------------------------------------------------

    Write-Step "7. Validate Removal"

    Write-Host "`n--- ZTDNS STATE ---" -ForegroundColor Yellow
    & netsh ztdns show state

    Write-Host "`n--- ZTDNS TRUSTED SERVERS ---" -ForegroundColor Yellow
    & netsh ztdns show server

    Write-Host "`n--- ZTDNS EXCEPTIONS ---" -ForegroundColor Yellow
    & netsh ztdns show exception

    Write-Host "`n--- WINDOWS DoH FOR 1.1.1.1 ---" -ForegroundColor Yellow
    $remainingDoh = Get-DnsClientDohServerAddress `
        -ServerAddress $DnsServer `
        -ErrorAction SilentlyContinue

    if ($remainingDoh) {
        $remainingDoh | Format-List ServerAddress,DohTemplate,AllowFallbackToUdp,AutoUpgrade
    }
    else {
        Write-Host "No DoH configuration for $DnsServer remains." -ForegroundColor Green
    }

    Write-Host "`n--- WINDOWS DNS CLIENT ---" -ForegroundColor Yellow
    Get-DnsClientServerAddress -AddressFamily IPv4 |
        Format-Table InterfaceAlias,InterfaceIndex,ServerAddresses -AutoSize

    Write-Step "ZTDNS Windows 11 PoC - REMOVAL COMPLETE"

    Write-Host "ZTDNS has been disabled and the POC configuration was removed where safe to do so." -ForegroundColor Green
    Write-Host "Log file:" -ForegroundColor Yellow
    Write-Host $LogFile -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
    Write-Host "ZTDNS POC REMOVAL FAILED" -ForegroundColor Red
    Write-Host "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "See log: $LogFile" -ForegroundColor Yellow

    exit 1
}
finally {
    Stop-Transcript | Out-Null
}
