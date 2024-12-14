Write-Host "`n" -NoNewLine

# Function to get the version name based on build number
function Get-WindowsVersion {
    param (
        [int]$buildNumber
    )

    switch ($buildNumber) {
        {$_ -ge 22631} { return "23H2" }   # Windows 11 Version 23H2
        {$_ -ge 22621} { return "22H2" }   # Windows 11 Version 22H2
        {$_ -ge 22000} { return "21H2" }   # Windows 11 Version 21H2
        {$_ -ge 19045} { return "22H2" }   # Windows 10 Version 22H2
        {$_ -ge 19044} { return "21H2" }   # Windows 10 Version 21H2
        {$_ -ge 19043} { return "21H1" }   # Windows 10 Version 21H1
        {$_ -ge 19042} { return "20H2" }   # Windows 10 Version 20H2
        {$_ -ge 19041} { return "2004" }   # Windows 10 Version 2004
        {$_ -ge 18363} { return "1909" }   # Windows 10 Version 1909
        {$_ -ge 18362} { return "1903" }   # Windows 10 Version 1903
        {$_ -ge 17763} { return "1809" }   # Windows 10 Version 1809
        {$_ -ge 17134} { return "1803" }   # Windows 10 Version 1803
        {$_ -ge 16299} { return "1709" }   # Windows 10 Version 1709
        {$_ -ge 15063} { return "1703" }   # Windows 10 Version 1703
        {$_ -ge 14393} { return "1607" }   # Windows 10 Version 1607
        {$_ -ge 10586} { return "1511" }   # Windows 10 Version 1511
        {$_ -ge 10240} { return "1507" }   # Windows 10 Version 1507
        {$_ -ge 9600}  { return "NT 6.3" } # Windows 8.1
        {$_ -ge 9200}  { return "NT 6.2" } # Windows 8
        {$_ -ge 7601}  { return "NT 6.1" } # Windows 7 SP1
        {$_ -ge 6002}  { return "NT 6.0" } # Windows Vista SP1
        {$_ -ge 3790}  { return "NT 5.2" } # Windows Server 2003
        {$_ -ge 2600}  { return "NT 5.1" } # Windows XP
        {$_ -ge 2700}  { return "NT 5.1" } # Windows XP
        {$_ -ge 2710}  { return "NT 5.1" } # Windows XP
        {$_ -ge 3000}  { return "4.90" }   # Windows 2000
        {$_ -ge 2195}  { return "NT 5.0" } # Windows 2000
        {$_ -eq 2222}  { return "4.10" }   # Windows 98 SE special case
        {$_ -ge 1998}  { return "4.10" }   # Windows 98
        {$_ -ge 1381}  { return "NT 4.0" }
        {$_ -ge 950}   { return "4.00" }
        {$_ -ge 1057}  { return "NT 3.51" }
        {$_ -ge 807}   { return "NT 3.5" }
        {$_ -ge 153}   { return "3.2" }
        {$_ -ge 300}   { return "3.11" }
        {$_ -ge 528}   { return "NT 3.1" }
        {$_ -ge 102}   { return "3.10" }
        {$_ -ge 103}   { return "3.10" }
        # Add other cases as necessary
        default { return "Unknown" }
    }
}

function Get-SystemInfo {
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "                    System Info                    " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "`n" -NoNewLine

    Write-Host "Host: $(hostname) - $(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -ne 'Loopback' } | Select-Object -ExpandProperty IPAddress -First 1)" -ForegroundColor White
    # System Information
    $systemInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $buildNumber = $systemInfo.BuildNumber
    $versionName = Get-WindowsVersion -buildNumber $buildNumber
    $systemType = $systemInfo.OSArchitecture
    Write-Host "Version: $($systemInfo.Caption) [$versionName] $systemType" -ForegroundColor White
    Write-Host "Build Number: $($systemInfo.Version) [$buildNumber]" -ForegroundColor White

}

Get-SystemInfo

# Determine if the machine is part of a domain by checking for the Get-ADUser cmdlet
function Get-UserGroups {
    Write-Host "`n" -NoNewLine
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "                    User Groups                    " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan

    if (Get-Command Get-ADUser -ErrorAction SilentlyContinue) {
        Write-Host "`n" -NoNewLine
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().SamAccountName
        $currentGroups = (Get-ADUser $currentUser -Property MemberOf).MemberOf | ForEach-Object { (Get-ADGroup $_ -ErrorAction SilentlyContinue).Name } -join ', '
        Write-Host "Current User: " -ForegroundColor Cyan -NoNewline
        Write-Host "$currentUser" -ForegroundColor Cyan -NoNewline
        Write-Host " - " -NoNewline
        Write-Host $currentGroups -ForegroundColor White
        Get-ADUser -Filter * -Property MemberOf, Enabled | Where-Object { $_.SamAccountName -ne $currentUser } | ForEach-Object { 
            $user = $_.SamAccountName
            $accountStatus = $_.Enabled
            $groups = $_.MemberOf | ForEach-Object { (Get-ADGroup $_ -ErrorAction SilentlyContinue).Name } -join ', '
            if (-not $accountStatus) {
                Write-Host "[X] " -ForegroundColor Red -NoNewline
                Write-Host "$user" -ForegroundColor Cyan -NoNewline
            } else {
                Write-Host "[A] " -ForegroundColor White -NoNewline
                Write-Host "$user" -ForegroundColor Cyan -NoNewline
            }
            Write-Host " - " -NoNewline
            Write-Host $groups -ForegroundColor White
        }
        Write-Host "`n" -NoNewLine
    } else {
        Write-Host "`n" -NoNewLine
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
        $currentGroups = (Get-LocalGroup | Where-Object { (Get-LocalGroupMember $_.Name -Member $currentUser -ErrorAction SilentlyContinue) }).Name -join ', '
        Write-Host "[+] Current User" -ForegroundColor Cyan
        Write-Host "$currentUser" -ForegroundColor White -NoNewline
        Write-Host " - " -NoNewline
        Write-Host $currentGroups -ForegroundColor White
	Write-Host "`n" -NoNewLine
	Write-Host "[+] All Users" -ForegroundColor Cyan
        Get-LocalUser | Where-Object { $_.Name -ne $currentUser } | ForEach-Object { 
            $user = $_.Name
            $accountStatus = $_.Enabled
            $groups = (Get-LocalGroup | Where-Object { (Get-LocalGroupMember $_.Name -Member $user -ErrorAction SilentlyContinue) }).Name -join ', '
            if (-not $accountStatus) {
                Write-Host "$user" -ForegroundColor Red -NoNewline
            } else {
                Write-Host "$user" -ForegroundColor White -NoNewline
            }
            Write-Host " - " -NoNewline
            Write-Host $groups -ForegroundColor White
        }
    }
}

Get-UserGroups

function Get-UserFolderContents {
    Write-Host "`n" -NoNewLine
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "                User Folder Contents               " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan
    $basePath = "C:\Users\"

    # Get all user folders in C:\Users\
    $userFolders = Get-ChildItem -Path $basePath -Directory -ErrorAction SilentlyContinue

    foreach ($userFolder in $userFolders) {
        # Get the known subfolders (Documents, Desktop, Pictures, etc.)
        $subFolders = Get-ChildItem -Path $userFolder.FullName -Directory -ErrorAction SilentlyContinue

        foreach ($subFolder in $subFolders) {
            # Check if there are files within the subfolder
            $files = Get-ChildItem -Path $subFolder.FullName -Recurse -File -ErrorAction SilentlyContinue

            if ($files) {
                Write-Host "`n" -NoNewline
                # Highlight the folder name (e.g., Documents, Desktop)
                Write-Host "[+] $($userFolder.Name) - $($subFolder.Name)" -ForegroundColor Cyan

                foreach ($file in $files) {
                    # Highlight file types in yellow
                    if ($file.Extension -match "\.txt$|\.pdf$|\.xls$|\.xlsx$|\.doc$|\.docx$|\.ini$") {
                        Write-Host $file.FullName -ForegroundColor Yellow
                    }
                    else {
                        Write-Host $file.FullName -ForegroundColor White
                    }
                }
            }
        }
    }
}

Get-UserFolderContents

function Get-PowerShellHistory {
    Write-Host "`n" -NoNewLine
    write-host "`n===================================================" -foregroundcolor cyan
    write-host "                                                   " -backgroundcolor white
    write-host "                  PowerShell History               " -foregroundcolor darkblue -backgroundcolor white
    write-host "                                                   " -backgroundcolor white
    write-host "===================================================" -foregroundcolor cyan
    
    # Define the whitelist of commands to exclude
    $whitelist = @('cls', 'exit', 'ls', 'dir', 'whoami', 'clear', 'Clear-History')

    # Display the command history
    try {
        $history = Get-History
        
        # Remove duplicate commands based on CommandLine
        $uniqueHistory = $history | Sort-Object CommandLine -Unique
        
        # Filter out whitelisted commands
        $filteredHistory = $uniqueHistory | Where-Object { $whitelist -notcontains $_.CommandLine.Trim() }
        
        if ($filteredHistory.Count -eq 0) {
            Write-Host "No relevant history available." -ForegroundColor Red
        } else {
            $filteredHistory | Format-Table -Property Id, CommandLine -AutoSize
        }
    } catch {
        Write-Host "Unable to access command history." -ForegroundColor Red
    }

    # Get the PSReadline history file path(s) and display them
    try {
        $historyPaths = (Get-PSReadlineOption).HistorySavePath

        if ($historyPaths -is [System.Array]) {
            $historyPaths | ForEach-Object {
                Write-Host "`n[+] PowerShell History File Path: " -ForegroundColor Cyan
                Write-Host "$_" -ForegroundColor Yellow

                # Read and process the history file
                if (Test-Path $_) {
                    $historyFileContent = Get-Content $_ | Sort-Object -Unique

                    # Filter out whitelisted commands from the history file content
                    $filteredHistoryFileContent = $historyFileContent | Where-Object { $whitelist -notcontains $_.Trim() }

                    Write-Host "Output: " -ForegroundColor White
                    $filteredHistoryFileContent | ForEach-Object { Write-Host $_ -ForegroundColor White }
                } else {
                    Write-Host "History file not found: $_" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "`n[+] PowerShell History File Path: " -ForegroundColor Cyan
            Write-Host $historyPaths -ForegroundColor Yellow

            # Read and process the history file
            if (Test-Path $historyPaths) {
                $historyFileContent = Get-Content $historyPaths | Sort-Object -Unique

                # Filter out whitelisted commands from the history file content
                $filteredHistoryFileContent = $historyFileContent | Where-Object { $whitelist -notcontains $_.Trim() }

                Write-Host "Output: " -ForegroundColor White
                $filteredHistoryFileContent | ForEach-Object { Write-Host $_ -ForegroundColor White }
            } else {
                Write-Host "History file not found: $historyPaths" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "Unable to access PowerShell history file." -ForegroundColor Red
    }
}

# Run the function
Get-PowerShellHistory

function Get-RecentFiles {
    Write-Host "`n" -NoNewLine
    write-host "`n===================================================" -foregroundcolor cyan
    write-host "                                                   " -backgroundcolor white
    write-host "               Recent Accessed Files               " -foregroundcolor darkblue -backgroundcolor white
    write-host "                                                   " -backgroundcolor white
    write-host "===================================================" -foregroundcolor cyan
    
    $recentPath = "$env:APPDATA\\Microsoft\\Windows\\Recent"
    try {
        Get-ChildItem -Path $recentPath -ErrorAction Stop | Sort-Object LastWriteTime -Descending | Select-Object Name, LastWriteTime | Format-Table -AutoSize
    } catch {
        Write-Host "Unable to access recent files." -ForegroundColor Red
    }
}

Get-RecentFiles

function Get-InstalledSoftware {
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "                Installed Software                 " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "`n" -NoNewLine
    Write-Host "[+] Installed Software (64-bit):" -ForegroundColor Cyan 
    try {
        Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
        Select-Object -Property DisplayName | 
        Where-Object { $_.DisplayName -ne $null } |
        Format-Table -AutoSize
    } catch {
        Write-Host "Failed to enumerate 64-bit software" -ForegroundColor Red
    }

    Write-Host "[+] Installed Software (32-bit on 64-bit OS):" -ForegroundColor Cyan
    try {
        Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | 
        Select-Object -Property DisplayName | 
        Where-Object { $_.DisplayName -ne $null } |
        Format-Table -AutoSize
    } catch {
        Write-Host "Failed to enumerate 32-bit software" -ForegroundColor Red
    }
}

Get-InstalledSoftware

function Get-ProgramFilesContents {
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "              Program Files Contents               " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "`n" -NoNewLine

    $programFilesPath = [Environment]::GetFolderPath("ProgramFiles")
    try {
        # If the directory exists, print it with a "[+] Directory:" header
        Write-Host "[+] Directory: $programFilesPath" -ForegroundColor Cyan
        # Get the contents without printing the directory path again
        Get-ChildItem -Path $programFilesPath -ErrorAction Stop | ForEach-Object {
            Write-Host $_.FullName -ForegroundColor White
        }
    } catch {
        Write-Host "Unable to access Program Files directory." -ForegroundColor Red
    }

    $programFilesX86Path = ${env:ProgramFiles(x86)}
    if ($null -ne $programFilesX86Path) {
        try {
            # If the directory exists, print it with a "[+] Directory:" header
            Write-Host "`n[+] Directory: $programFilesX86Path" -ForegroundColor Cyan
            # Get the contents without printing the directory path again
            Get-ChildItem -Path $programFilesX86Path -ErrorAction Stop | ForEach-Object {
                Write-Host $_.FullName -ForegroundColor White
            }
        } catch {
            Write-Host "Unable to access Program Files (x86) directory." -ForegroundColor Red
        }
    } else {
        Write-Host "Program Files (x86) directory not present on this system." -ForegroundColor Yellow
    }
}

Get-ProgramFilesContents

function Find-KDBXFiles {
    Write-Host "`n" -NoNewLine
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "              KeePass Database Files               " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan

    try {
        # Get all drives on the system
        $allDrives = (Get-PSDrive -PSProvider FileSystem).Root

        # Search for KeePass-related directories or files
        $keepassPaths = Get-ChildItem -Path $allDrives -Directory -Recurse -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -like "*keepass*" }

        if ($keepassPaths) {
            Write-Host "`n[+] " -ForegroundColor Yellow -NoNewline
	    Write-Host "KeePass Directories Found:" -ForegroundColor White

            # Iterate through KeePass-related directories and search for .kdbx files
            foreach ($path in $keepassPaths) {
                Write-Host "`nSearching in: $($path.FullName)" -ForegroundColor Cyan

                $kdbxFiles = Get-ChildItem -Path $path.FullName -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

                if ($kdbxFiles) {
                    Write-Host "`n[+] " -ForegroundColor Yellow -NoNewLine
                    Write-Host "Found KeePass Database Files:" -ForegroundColor White
                    $kdbxFiles | ForEach-Object {
                        Write-Host "File: $($_.FullName) | Size: $($_.Length) bytes" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "No KeePass (.kdbx) files found in: $($path.FullName)" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "No KeePass directories found on any drive." -ForegroundColor Red
        }
    } catch {
        Write-Host "An error occurred while searching for KeePass database files." -ForegroundColor Red
    }
}

Find-KDBXFiles

function Find-XAMPPConfigFiles {
    Write-Host "`n" -NoNewLine
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "              Sensitive XAMPP Files                " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan

    # Define exact file names to exclude (case-insensitive check)
    $excludeFiles = @(
        "docs.txt", "ABOUT_APACHE.txt", "INSTALL.txt", "OPENSSL-NEWS.txt", "OPENSSL-README.txt", 
        "MING-README.txt", "COPYRIGHT.txt", "GPL.txt", "Copyright.txt", "LICENCE.txt", 
        "redist.txt", "khronos.license.txt", "FTL.TXT", "gpl.txt", "openports.txt", 
        "errmsg-utf8.txt", "browscap.ini", "snapshot.txt", "news.txt", "readme-redist-bins.txt", 
        "readme_de.txt", "readme_en.txt", "CHANGES.txt", "NOTICE.txt", "README.txt",
        "COPYING.txt", "GeoIP\COPYING.txt", "giflib\COPYING.txt", "libxml2\COPYING.txt", 
        "msmtp\COPYING.txt", "pbxt\COPYING.txt", "ucd-snmp\COPYING.txt", 
        "php\docs\Archive_Tar\docs\Archive_Tar.txt", "php\extras\mibs\*.txt", "php\pear\.channels\.alias\*.txt",
        "php\tests\emptyDir\empty_dir.txt", "webdav.txt"
    )
    try {
        # Search for the xampp folder on all drives
        $xamppPath = Get-ChildItem -Path (Get-PSDrive -PSProvider FileSystem).Root -Directory -Recurse -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -eq "xampp" } |
                     Select-Object -First 1 -ExpandProperty FullName

        if ($xamppPath) {
            # Search for .txt and .ini files within the XAMPP directory, excluding specified files (case-insensitive check on full path)
            $configFiles = Get-ChildItem -Path $xamppPath -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue |
                           Where-Object { 
                               ($excludeFiles -notcontains ($_.Name.ToLower())) -and 
                               ($_.FullName -notmatch '\\license.txt$') 
                           }

            if ($configFiles) {
                Write-Host "`n[+] " -ForegroundColor Yellow -NoNewLine
                Write-Host "Found Text and Configuration Files:" -ForegroundColor White

                # Categorize and display the files
                $snmpFiles = $configFiles | Where-Object { $_.FullName -match '\\mibs\\.*\.txt$' }
                $pearFiles = $configFiles | Where-Object { $_.FullName -match '\\pear\\.*\.txt$' }
                $configurationFiles = $configFiles | Where-Object { $_.FullName -match '\\xampp-control\.ini$' }
                $sensitiveFiles = $configFiles | Where-Object { $_.FullName -match '\\passwords\.txt$' -or $_.FullName -match '\\properties\.ini$' -or $_.FullName -match '\\my\.ini$' }
                $documentationFiles = $configFiles | Where-Object { $_.FullName -match '\\docs\\.*\.txt$' }
                $otherFiles = $configFiles | Where-Object { 
                    $_.FullName -notmatch '\\mibs\\.*\.txt$' -and 
                    $_.FullName -notmatch '\\pear\\.*\.txt$' -and
                    $_.FullName -notmatch '\\passwords\.txt$' -and
                    $_.FullName -notmatch '\\properties\.ini$' -and
                    $_.FullName -notmatch '\\xampp-control\.ini$' -and
                    $_.FullName -notmatch '\\docs\\.*\.txt$' -and
                    $_.FullName -notmatch '\\my\.ini$'
                }

                # Display categories
                if ($sensitiveFiles) {
                    Write-Host "`n[+] Sensitive Files:" -ForegroundColor Cyan
                    $sensitiveFiles | ForEach-Object { Write-Host "File: $($_.FullName) | Size: $($_.Length) bytes" -ForegroundColor Yellow }
                }

                if ($configurationFiles) {
                    Write-Host "`n[+] Configuration Files:" -ForegroundColor Cyan
                    $configurationFiles | ForEach-Object { Write-Host "File: $($_.FullName) | Size: $($_.Length) bytes" -ForegroundColor White }
                }

                if ($otherFiles) {
                    Write-Host "`n[+] Other Files:" -ForegroundColor Cyan
                    $otherFiles | ForEach-Object { Write-Host "File: $($_.FullName) | Size: $($_.Length) bytes" -ForegroundColor White }
                }

                if ($snmpFiles) {
                    Write-Host "`n[+] SNMP Files:" -ForegroundColor Cyan
                    $snmpFiles | ForEach-Object { Write-Host "File: $($_.FullName) | Size: $($_.Length) bytes" -ForegroundColor White }
                }

                if ($pearFiles) {
                    Write-Host "`n[+] PEAR Files:" -ForegroundColor Cyan
                    $pearFiles | ForEach-Object { Write-Host "File: $($_.FullName) | Size: $($_.Length) bytes" -ForegroundColor White }
                }

                if ($documentationFiles) {
                    Write-Host "`n[+] Documentation Files:" -ForegroundColor Cyan
                    $documentationFiles | ForEach-Object { Write-Host "File: $($_.FullName) | Size: $($_.Length) bytes" -ForegroundColor White }
                }

            } else {
                Write-Host "No text or configuration files (.txt, .ini) found in the XAMPP directory." -ForegroundColor Red
            }
        } else {
            Write-Host "XAMPP directory not found on any drive." -ForegroundColor Red
        }
    } catch {
        Write-Host "An error occurred while searching for the XAMPP directory. Details: $_" -ForegroundColor Red
    }
}

Find-XAMPPConfigFiles

function Get-NetworkConnections {
    Write-Host "`n" -NoNewLine
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "            Active Network Connections             " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan

    # Define very common processes to exclude
    $commonProcesses = @(
        "svchost", "explorer", "System Idle Process", "conhost", "csrss", "winlogon", 
        "lsass", "smss", "dwm", "taskhostw", "audiodg", "sihost", "ctfmon", 
        "RuntimeBroker", "SearchHost", "Widgets", "ShellExperienceHost", 
        "StartMenuExperienceHost", "spoolsv", "WmiPrvSE", "fontdrvhost", 
        "services", "LogonUI", "Memory Compression", "SecurityHealthService", 
        "AggregatorHost", "SearchIndexer", "rdpclip", "Idle", "System", 
        "dllhost", "WUDFHost", "wininit", "VGAuthService", "vmtoolsd", 
        "vm3dservice", "msteamsupdate", "backgroundTaskHost", "WindowsTerminal", 
        "MicrosoftEdgeUpdate", "msedgewebview2", "SecurityHealthSystray", 
        "OneDrive", "PhoneExperienceHost", "WidgetService", "LockApp", 
        "MpDefenderCoreService", "MsMpEng", "SgrmBroker", "Registry"
    )

    try {
        # TCP Connections with Process IDs
        Write-Host "`n" -NoNewLine
        Write-Host "[+] TCP Connections:" -ForegroundColor Cyan
        Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess |
        ForEach-Object {
            $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            if ($process -and -not ($commonProcesses -contains $process.ProcessName)) {
                [PSCustomObject]@{
                    LocalAddress   = $_.LocalAddress
                    LocalPort      = $_.LocalPort
                    RemoteAddress  = $_.RemoteAddress
                    RemotePort     = $_.RemotePort
                    State          = $_.State
                    ProcessID      = $_.OwningProcess
                    ProcessName    = $process.ProcessName
                }
            }
        } | Format-Table -AutoSize

        # UDP Connections with Process IDs
        Write-Host "[+] UDP Connections:" -ForegroundColor Cyan
        Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess |
        ForEach-Object {
            $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            if ($process -and -not ($commonProcesses -contains $process.ProcessName)) {
                [PSCustomObject]@{
                    LocalAddress   = $_.LocalAddress
                    LocalPort      = $_.LocalPort
                    ProcessID      = $_.OwningProcess
                    ProcessName    = $process.ProcessName
                }
            }
        } | Format-Table -AutoSize
    } catch {
        Write-Host "Unable to retrieve network connections." -ForegroundColor Red
    }
}

# Run the function
Get-NetworkConnections

function Get-RunningProcesses {
    Write-Host "`n" -NoNewLine
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "                 Running Processes                 " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan

    # Define very common processes to exclude
    $commonProcesses = @(
        "svchost", "explorer", "System Idle Process", "conhost", "csrss", "winlogon", 
        "lsass", "smss", "dwm", "taskhostw", "audiodg", "sihost", "ctfmon", 
        "RuntimeBroker", "SearchHost", "Widgets", "ShellExperienceHost", 
        "StartMenuExperienceHost", "spoolsv", "WmiPrvSE", "fontdrvhost", 
        "services", "LogonUI", "Memory Compression", "SecurityHealthService", 
        "AggregatorHost", "SearchIndexer", "rdpclip", "Idle", "System", 
        "dllhost", "WUDFHost", "wininit", "VGAuthService", "vmtoolsd", 
        "vm3dservice", "msteamsupdate", "backgroundTaskHost", "WindowsTerminal", 
        "MicrosoftEdgeUpdate", "msedgewebview2", "SecurityHealthSystray", 
        "OneDrive", "PhoneExperienceHost", "WidgetService", "LockApp", 
        "MpDefenderCoreService", "MsMpEng", "SgrmBroker", "Registry"
    )

    try {
        # Exclude common processes
        Get-Process | Where-Object { 
            -not ($commonProcesses -contains $_.ProcessName)
        } | Sort-Object CPU -Descending |
        Select-Object -Property ProcessName, Id, CPU, PM, Path |
        Format-Table -AutoSize
    } catch {
        Write-Host "Unable to enumerate running processes." -ForegroundColor Red
    }
}
# Run the function
Get-RunningProcesses

function Find-BrowserCredentials {
    write-host "`n===================================================" -foregroundcolor cyan
    write-host "                                                   " -backgroundcolor white
    write-host "             Browser Credential Files              " -foregroundcolor darkblue -backgroundcolor white
    write-host "                                                   " -backgroundcolor white
    write-host "===================================================" -foregroundcolor cyan
    write-host "`n" -NoNewLine

    # Define browser paths
    $paths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",     # Chrome
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data",   # Edge
        "$env:APPDATA\Mozilla\Firefox\Profiles\*\logins.json",             # Firefox
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data"  # Brave
    )

    $foundFiles = @()  # Array to store found files

    # Iterate over each defined path
    foreach ($path in $paths) {
        try {
            # Get matching files at the specified path
            $files = Get-ChildItem -Path $path -ErrorAction SilentlyContinue

            if ($files) {
                $foundFiles += $files  # Add to the results array
                foreach ($file in $files) {
                    Write-Host "[+] Found: $($file.FullName)" -ForegroundColor Yellow
                }
            }
        } catch {
            Write-Host "[!] Unable to access $path" -ForegroundColor Red
        }
    }

    # Summarize Results
    if ($foundFiles.Count -eq 0) {
        Write-Host "`n[!] No credential files found for any browser." -ForegroundColor Red
    }
}

Find-BrowserCredentials

function Get-StartupPrograms {
    write-host "`n===================================================" -foregroundcolor cyan
    write-host "                                                   " -backgroundcolor white
    write-host "                 Startup Programs                  " -foregroundcolor darkblue -backgroundcolor white
    write-host "                                                   " -backgroundcolor white
    write-host "===================================================" -foregroundcolor cyan
    
    try {
        Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-Table -AutoSize
    } catch {
        Write-Host "Unable to retrieve startup programs." -ForegroundColor Red
    }
}

Get-StartupPrograms

function Get-ScheduledTasks {
    write-host "`n===================================================" -foregroundcolor cyan
    write-host "                                                   " -backgroundcolor white
    write-host "                  Scheduled Tasks                  " -foregroundcolor darkblue -backgroundcolor white
    write-host "                                                   " -backgroundcolor white
    write-host "===================================================" -foregroundcolor cyan

    try {
        Get-ScheduledTask | Select-Object TaskName, State, TaskPath | Format-Table -AutoSize
    } catch {
        Write-Host "Unable to retrieve scheduled tasks." -ForegroundColor Red
    }
}

Get-ScheduledTasks
