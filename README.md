# Zero Trust DNS Windows 11 POC
Experimental POC script for Zero Trust DNS on Windows 11

# ⚠️ POC / lab configuration ⚠️

This repository is intended for testing and understanding ZTDNS. It is not a production-ready Windows 11 baseline. Microsoft 365 and Windows 365 endpoints can change, and required exceptions should be validated before production deployment.

ZTDNS is not intended to replace a full network firewall or Protective DNS service. The important POC concept is that Windows controls DNS-based destination discovery and can block traffic that does not satisfy the ZTDNS trust model.

<img width="690" height="288" alt="image" src="https://github.com/user-attachments/assets/f123d34f-f235-49e1-ab04-a316812d7854" />


# The POC combines:

- Windows 11 Zero Trust DNS (ZTDNS)
- Cloudflare 1.1.1.1 as the DNS provider used for the POC
- DNS over HTTPS (DoH)
- ZTDNS audit and block modes
- Microsoft 365 IP exceptions
- MDM bypass
- ZTDNS event logging
- Testing of legitimate application traffic such as OneDrive and Microsoft Defender
- Detection of DNS bypass attempts such as direct DNS traffic to 1.1.1.1:53

The goal is to understand how ZTDNS behaves before designing a production configuration.

# Prerequisites

- Windows 11
- Administrator permissions
- Windows 11 System or VM 
- Internet connectivity
- PowerShell
- Cloudflare DNS / DoH endpoint: (1.1.1.1 -> https://cloudflare-dns.com/dns-query)

# Microsoft 365 exceptions

Microsoft 365 applications can use endpoints that do not always behave like a simple DNS-discovered destination.
The POC therefore contains separate exception groups for services such as:

- Exchange Online
- Microsoft Entra ID / Identity
- Microsoft 365 / Office
- SharePoint / OneDrive
- Microsoft Teams

#ZTDNS event logs
ZTDNS provides useful Windows Event Viewer logs.

Open:Event Viewer
└── Applications and Services Logs -> Microsoft -> Windows -> ZTDNS -> BlockedConnections

# Useful commands

- ZTDNS State: netsh ztdns show state
- Trusted DNS servers: netsh ztdns show server
- Exceptions: netsh ztdns show exception
- Add an exception: netsh ztdns add exception name=Example description="POC exception" subnet=203.0.113.10/32
- Delete an exception: netsh ztdns delete exception name=Example
- Enable audit mode: netsh ztdns set state audit=yes
- Enable block mode: netsh ztdns set state audit=no
- Enable MDM bypass: netsh ztdns set state mdmbypass=allow

# Running the POC script
The repository includes a PowerShell script that configures the Windows 11 ZTDNS POC.

Open PowerShell as Administrator, navigate to the folder containing the script and run:

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\Install-ZTDNS-Windows11-POC.ps1

The script writes its output to a log file under: C:\Temp\
This makes it possible to review what the script configured and troubleshoot any errors.

