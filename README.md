# ![WinRecon Logo](assets/winrecon-logo.png)

## WinRecon

**WinRecon** is a PowerShell-based enumeration script designed to gather essential information for privilege escalation on Windows systems. This script collects a comprehensive set of system details to help identify vulnerabilities and misconfigurations that may lead to privilege escalation.

---

## Features

- **Complete System Enumeration**: Gather detailed system information, including OS version, architecture, and user configurations.
- **Privilege Escalation Path Detection**: Identify potential escalation opportunities such as:
  - Unquoted service paths
  - Insecure permissions on services, files, and registries
  - Vulnerable installed software
  - Active sessions and login histories
- **Quick & Automated**: Streamlined process to gather key details without manual investigation.

---

## Usage

1. **Upload** the `winrecon.ps1` script to the target Windows machine.
2. **Open PowerShell** with administrator privileges on the target machine.
3. Run the script with the following command:
   ```powershell
   .\winrecon.ps1
