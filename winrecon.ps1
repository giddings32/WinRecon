# Define variables to track enabled functions (default all enabled)
$EnableSystemInfo = $true
$EnableUserGroups = $true
$EnableUserFolderContents = $true
$EnablePowerShellHistory = $true
$EnableEventViewerCredentials = $true
$EnableRecentFiles = $true
$EnableInstalledSoftware = $true
$EnableProgramFilesContents = $true
$EnableKDBXFiles = $true
$EnableXAMPPConfigFiles = $true
$EnableNetworkConnections = $true
$EnableRunningProcesses = $true
$EnableBrowserCredentials = $true
$EnableStartupPrograms = $true
$EnableScheduledTaskEscalation = $true
$EnableUnquotedServicePaths = $true
$EnableServiceBinaryHijacking = $true
$EnableDLLHijacking = $true
$EnableUserPrivileges = $true

# Initial Menu for Recon Mode
do {
    Write-Host "`n" -NoNewLine
    Write-Host "Select the Recon Mode:"
    Write-Host "1. Run Full Recon - Execute all recon functions without changes."
    Write-Host "2. Run Custom Recon - (Select which functions to enable)"
    Write-Host "3. Run Recon with Exclusions (Select which functions to disable)."
    Write-Host "`n" -NoNewLine
    $ReconMode = Read-Host "Enter 1, 2, or 3"

    # Check input validity
    if ($ReconMode -notin "1", "2", "3") {
        Write-Host "Invalid input. Please enter 1, 2, or 3." -ForegroundColor Yellow
    }
} until ($ReconMode -in "1", "2", "3")  # Keep asking until input is valid

function Get-ValidUserInput {
    param (
        [string]$PromptMessage,
        [array]$ValidOptions
    )

    # Ensure valid options are provided, or default to numbers 1-15
    if (-not $ValidOptions) {
        $ValidOptions = 1..19
    }

    do {
        # Prompt user for input
        $userInput = Read-Host $PromptMessage

        # Validate input: Ensure it matches the pattern (numbers separated by commas)
        if ($userInput -match '^\d+(,\d+)*$') {
            # Convert input into an array and check each number
            $inputArray = $userInput -split ',' | ForEach-Object { $_.Trim() }

            # Ensure all numbers are within the valid range
            if ($inputArray | Where-Object { $_ -notin $ValidOptions }) {
                Write-Host "Invalid input: Numbers must be between $($ValidOptions -join ' and ')." -ForegroundColor Yellow
            }
            else {
                return $inputArray  # Valid input
            }
        }
        else {
            Write-Host "Invalid input format: Please enter numbers only, separated by commas (e.g., 1,2,3)." -ForegroundColor Yellow
        }
    } until ($false)  # Loop until valid input is provided
}

# Handle Recon Mode Selection
switch ($ReconMode) {
    "1" {
        Write-Host "`n" -NoNewLine
        Write-Host "Running Full Recon... All functions will be executed."
        # No changes to function enable/disable variables
    }
    "2" {
        Write-Host "`n" -NoNewLine
        Write-Host "Running Custom Recon... All functions are disabled. Select which functions to enable."
        # Disable all functions
        $EnableSystemInfo = $false
        $EnableUserGroups = $false
        $EnableUserFolderContents = $false
        $EnablePowerShellHistory = $false
        $EnableEventViewerCredentials = $false
        $EnableRecentFiles = $false
        $EnableInstalledSoftware = $false
        $EnableProgramFilesContents = $false
        $EnableKDBXFiles = $false
        $EnableXAMPPConfigFiles = $false
        $EnableNetworkConnections = $false
        $EnableRunningProcesses = $false
        $EnableBrowserCredentials = $false
        $EnableStartupPrograms = $false
        $EnableScheduledTaskEscalation = $false
        $EnableUnquotedServicePaths = $false
        $EnableServiceBinaryHijacking = $false
        $EnableDLLHijacking = $false
        $EnableUserPrivileges = $false

        # Ask user which functions to enable
        Write-Host "`n" -NoNewLine
        Write-Host "Select the functions to ENABLE:"
        Write-Host " 1. System Info"
        Write-Host " 2. User Groups"
        Write-Host " 3. User Folder Contents"
        Write-Host " 4. Powershell History"
        Write-Host " 5. Event Viewer Credentials"
        Write-Host " 6. Recent Files"
        Write-Host " 7. Installed Software"
        Write-Host " 8. Program Files Contents"
        Write-Host " 9. KDBX Files"
        Write-Host "10. XAMPP Config Files"
        Write-Host "11. Network Connections"
        Write-Host "12. Running Processes"
        Write-Host "13. Browser Credentials"
        Write-Host "14. Startup Programs"
        Write-Host "15. Scheduled Task Escalation"
        Write-Host "16. Unquoted Service Paths"
        Write-Host "17. Service Binary Hijacking"
        Write-Host "18. DLL Hijacking"
        Write-Host "19. User Privileges"
        Write-Host "`n" -NoNewLine

        $enableInput = Get-ValidUserInput "Enter numbers 1-19 separated by commas" -ValidOptions $validOptions
        Write-Host "You selected to enable the following options: $($enableInput -join ', ')"

        if ($enableInput) {
            $enabledFunctions = $enableInput -split ',' | ForEach-Object { $_.Trim() }
            foreach ($func in $enabledFunctions) {
                switch ($func) {
                    "1" { $EnableSystemInfo = $true }
                    "2" { $EnableUserGroups = $true }
                    "3" { $EnableUserFolderContents = $true }
                    "4" { $EnablePowerShellHistory = $true }
                    "5" { $EnableEventViewerCredentials = $true }
                    "6" { $EnableRecentFiles = $true }
                    "7" { $EnableInstalledSoftware = $true }
                    "8" { $EnableProgramFilesContents = $true }
                    "9" { $EnableKDBXFiles = $true }
                    "10" { $EnableXAMPPConfigFiles = $true }
                    "11" { $EnableNetworkConnections = $true }
                    "12" { $EnableRunningProcesses = $true }
                    "13" { $EnableBrowserCredentials = $true }
                    "14" { $EnableStartupPrograms = $true }
                    "15" { $EnableScheduledTaskEscalation = $true }
                    "16" { $EnableUnquotedServicePaths = $true }
                    "17" { $EnableServiceBinaryHijacking = $true }
                    "18" { $EnableDLLHijacking = $true }
                    "19" { $EnableUserPrivileges = $true }
                }
            }
        }
    }
    "3" {
        Write-Host "`n" -NoNewLine
        Write-Host "Running Recon with Exclusions... All functions are enabled. Select which ones to disable."
        Write-Host "Enter numbers to DISABLE (e.g., 1,2,3). Press Enter to keep all enabled."
        Write-Host " 1. System Info"
        Write-Host " 2. User Groups"
        Write-Host " 3. User Folder Contents"
        Write-Host " 4. Powershell History"
        Write-Host " 5. Event Viewer Credentials"
        Write-Host " 6. Recent Files"
        Write-Host " 7. Installed Software"
        Write-Host " 8. Program Files Contents"
        Write-Host " 9. KDBX Files"
        Write-Host "10. XAMPP Config Files"
        Write-Host "11. Network Connections"
        Write-Host "12. Running Processes"
        Write-Host "13. Browser Credentials"
        Write-Host "14. Startup Programs"
        Write-Host "15. Scheduled Task Escalation"
        Write-Host "16. Unquoted Service Paths"
        Write-Host "17. Service Binary Hijacking"
        Write-Host "18. DLL Hijacking"
        Write-Host "19. User Privileges"
        Write-Host "`n" -NoNewLine
        $disableInput = Get-ValidUserInput "Enter numbers 1-19 separated by commas" -ValidOptions $validOptions
        Write-Host "You selected to enable the following options: $($disableInput -join ', ')"

        if ($disableInput) {
            $disabledFunctions = $disableInput -split ',' | ForEach-Object { $_.Trim() }
            foreach ($func in $disabledFunctions) {
                switch ($func) {
                    "1" { $EnableSystemInfo = $false }
                    "2" { $EnableUserGroups = $false }
                    "3" { $EnableUserFolderContents = $false }
                    "4" { $EnablePowerShellHistory = $false }
                    "5" { $EnableEventViewerCredentials = $true }
                    "6" { $EnableRecentFiles = $false }
                    "7" { $EnableInstalledSoftware = $false }
                    "8" { $EnableProgramFilesContents = $false }
                    "9" { $EnableKDBXFiles = $false }
                    "10" { $EnableXAMPPConfigFiles = $false }
                    "11" { $EnableNetworkConnections = $false }
                    "12" { $EnableRunningProcesses = $false }
                    "13" { $EnableBrowserCredentials = $false }
                    "14" { $EnableStartupPrograms = $false }
                    "15" { $EnableScheduledTaskEscalation = $false }
                    "16" { $EnableUnquotedServicePaths = $false }
                    "17" { $EnableServiceBinaryHijacking = $false }
                    "18" { $EnableDLLHijacking = $false }
                    "19" { $EnableUserPrivileges = $false }
                }
            }
        }
    }
    default {
        Write-Host "Invalid input. Exiting script." -ForegroundColor Red
        exit
    }
}

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

function Get-UserGroups {
    Write-Host "`n" -NoNewLine
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "                    User Groups                    " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan

    Write-Host "`n" -NoNewLine
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
    $currentGroups = (Get-LocalGroup | Where-Object { (Get-LocalGroupMember $_.Name -Member $currentUser -ErrorAction SilentlyContinue) }).Name -join ', '

    # Current User
    Write-Host "[+] Current User" -ForegroundColor Cyan
    Write-Host "$currentUser" -ForegroundColor White -NoNewline
    Write-Host " - " -NoNewline
    Write-Host $currentGroups -ForegroundColor White
    Write-Host "`n" -NoNewLine

    # All Users on System
    Write-Host "[+] All System Users" -ForegroundColor Cyan
    Get-LocalUser | ForEach-Object { 
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
    Write-Host "`n" -NoNewLine
  
    # IF Joined to Domain
    $netUserOutput = & net user /domain 2>&1
    $outputLines = $netUserOutput -split "`r?`n"
    if ($outputLines -join "`n" -notmatch "System error 1355 has occurred") {
        
	# All Domain Users
	$filteredLines = $outputLines | Where-Object {
            $_ -notmatch "^(The request will be processed|User accounts for|^-+$|The command completed successfully|^\s*$)"
        }
        $usernames = $filteredLines -join ' ' -split '\s{2,}' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        Write-Host "[+] All Domain Users" -ForegroundColor Cyan
        foreach ($user in $usernames) {
            
	    # All Domain Groups for Each User
	    $netUserGroupOutput = & net user /domain $user 2>&1
    	    $startIndex = $netUserGroupOutput | ForEach-Object { $_ } | Select-String -Pattern "^Local Group Memberships" | Select-Object -ExpandProperty LineNumber -First 1 
    	    $startIndex = ($startIndex - 1)
    	    $filteredGroupLines = $netUserGroupOutput[$startIndex..($netUserGroupOutput.Length -1)]
    	    $formattedGroupOutput = $filteredGroupLines | ForEach-Object {
                if ($_ -match '\s{2,}') {
                    ($_ -split '\s{2,}', 2)[1].Trim() -replace '\s{2,}', ', '
                }
    	    }
    	    $groups = ($formattedGroupOutput | Where-Object { $_ -ne "" }) -join ", "
    	    $groups = $groups.Trim(", ")
	    $groups = $groups -replace "\*", ""
	    if ($groups -match "Domain Admins") {
                Write-Host "$user" -ForegroundColor Green -NoNewLine
		Write-Host " - $groups"
            } else {
                Write-Host "$user" -ForegroundColor White -NoNewLine
		Write-Host " - $groups"
	    }
        }
        Write-Host "`n" -NoNewLine
        
	# All Domain Groups
	$netGroupOutputLines = & net group /domain 2>&1
	$groupNames = $netGroupOutputLines | Where-Object {
            $_ -notmatch "^(The request will be processed|Group accounts for|^-+$|The command completed successfully|^\s*$)"
        }
	Write-Host "[+] All Domain Groups" -ForegroundColor Cyan
	foreach ($group in $groupNames) {
            # All Users for Each Domain Group
	    $group = $group -replace "\*", ""
	    $netGroupUserOutput = net group "`"$group`"" /domain 2>&1
    	    $startIndex = $netGroupUserOutput | ForEach-Object { $_ } | Select-String -Pattern "^Members" | Select-Object -ExpandProperty LineNumber -First 1 
    	    $filteredNetGroupUserLines = $netGroupUserOutput[$startIndex..($netGroupUserOutput.Length -1)]
    	    $formattedNetGroupUserOutput = $filteredNetGroupUserLines | ForEach-Object {
                if ($_ -match '\s{2,}') {
                    ($_ -split '\s{2,}', 2) -replace '\s{2,}', ', '
                }
    	    }
	    $groupUsers = ($formattedNetGroupUserOutput | Where-Object { $_ -ne "" }) -join ", "
	    $groupUsers = $groupUsers.Trim(", ")
	    $groupUsers = $groupUsers -replace '\,\s*\,', ','
	    if ($group -match "Domain Admins") {
                if ([string]::IsNullOrWhiteSpace($groupUsers)) {
		} else {
		    Write-Host "$group" -ForegroundColor Green -NoNewLine
		    Write-Host " - $groupUsers"
		}
	    } else {
		if ([string]::IsNullOrWhiteSpace($groupUsers)) {
                } else {
                    Write-Host "$group" -ForegroundColor White -NoNewLine
		    Write-Host " - $groupUsers"
		}
	    }
        }
        foreach ($group in $groupNames) {
            # All Users for Each Domain Group
	    $group = $group -replace "^\*", ""
	    $netGroupUserOutput = net group "`"$group`"" /domain 2>&1
    	    $startIndex = $netGroupUserOutput | ForEach-Object { $_ } | Select-String -Pattern "^Members" | Select-Object -ExpandProperty LineNumber -First 1 
    	    $filteredNetGroupUserLines = $netGroupUserOutput[$startIndex..($netGroupUserOutput.Length -1)]
    	    $formattedNetGroupUserOutput = $filteredNetGroupUserLines | ForEach-Object {
                if ($_ -match '\s{2,}') {
                    ($_ -split '\s{2,}', 2) -replace '\s{2,}', ' | '
                }
    	    }
	    $groupUsers = ($formattedNetGroupUserOutput | Where-Object { $_ -ne "" }) -join " | "
	    $groupUsers = $groupUsers.Trim(" |")
	    $groupUsers = $groupUsers -replace '\|\s*\|', '|'
            if ([string]::IsNullOrWhiteSpace($groupUsers)) {
                Write-Host "$group - No Users Assigned" -ForegroundColor DarkGray
	    }
	}
    }
}

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

function Get-PowerShellHistory {
    Write-Host "`n" -NoNewLine
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "                  PowerShell History               " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan
    
    # Define the whitelist of commands to exclude
    $whitelist = @('cls', 'exit', 'ls', 'dir', 'whoami', 'clear', 'Clear-History')

    # Define keywords to highlight (case-insensitive)
    $highlightKeywords = @('user.txt', 'users.txt', 'password', 'pass', 'Enter-PSSession', 'Secret', 'Start-Transcript')

    # Function to check and highlight only the keywords within lines
    function Highlight-Line {
        param ($line)
        $highlighted = $false
        
        # Process each keyword and replace its match with highlighted output
        foreach ($keyword in $highlightKeywords) {
            if ($line -match "(?i)\b$keyword\b") {
                $highlighted = $true
                $splitParts = $line -split "(?i)($keyword)"  # Split the line into parts around the keyword
                foreach ($part in $splitParts) {
                    if ($part -match "(?i)$keyword") {
                        Write-Host $part -ForegroundColor Yellow -NoNewline  # Highlight keyword
                    } else {
                        Write-Host $part -ForegroundColor White -NoNewline  # Normal text
                    }
                }
                Write-Host ""  # Move to the next line
                break
            }
        }

        # If no keywords matched, print the line normally
        if (-not $highlighted) {
            Write-Host $line -ForegroundColor White
        }
    }

    # Display the live command history
    try {
        $history = Get-History
        
        # Remove duplicate commands based on CommandLine
        $uniqueHistory = $history | Sort-Object CommandLine -Unique
        
        # Filter out whitelisted commands
        $filteredHistory = $uniqueHistory | Where-Object { $whitelist -notcontains $_.CommandLine.Trim() }
        
        if ($filteredHistory.Count -eq 0) {
            Write-Host "No relevant history available." -ForegroundColor Red
        } else {
            Write-Host "`n[+] Live PowerShell Command History:" -ForegroundColor Cyan
            $filteredHistory | ForEach-Object {
                Highlight-Line $_.CommandLine
            }
        }
    } catch {
        Write-Host "Unable to access command history." -ForegroundColor Red
    }

    # Get the PSReadLine history file path(s) and display them
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
                    $filteredHistoryFileContent | ForEach-Object { Highlight-Line $_ }
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
                $filteredHistoryFileContent | ForEach-Object { Highlight-Line $_ }
            } else {
                Write-Host "History file not found: $historyPaths" -ForegroundColor Red
            }
        }
    } catch {
        Write-Host "Unable to access PowerShell history file." -ForegroundColor Red
    }
}

function Get-EventViewerCredentials {
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "              Event-Viewer Credentials             " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan

    # Keywords to search for
    $keywords = '(?i)(\$password|\$pass |\$securepassword|\$cred|password|-Password|Pass- |pass=|pwd=|securestring|plaintext|secret|apikey|accesskey|secretkey|privatekey|-p |-u |sshkey|identityfile|credentials|login|signin|unencrypted|securestring|plaintext|PSCredential|Get-Credential|Authorization:)'

    $excludeList = '(?i)(EventViewerCredentials|BrowserCredentials|\$sensitiveFiles|_cmdletization_methodParameter|exploits +=|highlightKeywords = @|No credential files found for any browser.)'

    # Function to print lines with matched keyword highlighted
    function Highlight-Keyword {
        param ($line, $keywords)
        # Find all matches of the keywords
        $matches = [regex]::Matches($line, $keywords)
        $currentIndex = 0

        foreach ($match in $matches) {
            # Print part before the match in white
            Write-Host -NoNewline ($line.Substring($currentIndex, $match.Index - $currentIndex)) -ForegroundColor White

            # Print the matched keyword in yellow
            Write-Host -NoNewline $match.Value -ForegroundColor Yellow

            # Move the index forward
            $currentIndex = $match.Index + $match.Length
        }

        # Print the remaining part of the line in white
        Write-Host $line.Substring($currentIndex) -ForegroundColor White
    }

    # -------------------------
    # PowerShell Operational Logs
    # -------------------------
    Write-Host "`n[+] Searching PowerShell Operational Logs:" -ForegroundColor Cyan
    try {
        $psEvents = Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -ErrorAction SilentlyContinue |
                    Where-Object { $_.Message -match $keywords -and $_.Message -notmatch $excludeList }
    
        if ($psEvents) {
            $psEvents | ForEach-Object {
                # Extract the full message
                $message = $_.Message
    
                Write-Host "Event ID: $($_.Id)" -ForegroundColor Yellow
                Write-Host "Time Created: $($_.TimeCreated)" -ForegroundColor Cyan
    
                # Print relevant lines filtered by keywords
                $message -split "`n" | Where-Object { $_ -match $keywords -and $_ -notmatch $excludeList } | ForEach-Object {
                    Highlight-Keyword $_ $keywords
                }
                Write-Host ""  # Blank line for readability
            }
        } else {
            Write-Host "No credential-related events found in PowerShell Operational logs." -ForegroundColor Green
        }
    } catch {
        Write-Host "Unable to access PowerShell Operational logs. Check permissions." -ForegroundColor Red
    }
}

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

function Get-InstalledSoftware {
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "                Installed Software                 " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan

    # Function to display software with version immediately after the name
    function Get-Software {
        param ($RegistryPath)

        try {
            Get-ItemProperty -Path $RegistryPath | 
            Select-Object -Property DisplayName, DisplayVersion |
            Where-Object { $_.DisplayName -ne $null } |
            Sort-Object DisplayName |
            ForEach-Object {
                $name = $_.DisplayName
                $version = if ($_.DisplayVersion) { "version: $($_.DisplayVersion)" } else { "version: N/A" }
                Write-Host ("{0} | {1}" -f $name, $version) -ForegroundColor White
            }
        } catch {
            Write-Host "Failed to access registry path: $RegistryPath" -ForegroundColor Red
        }
    }

    Write-Host "`n[+] Installed Software (64-bit):" -ForegroundColor Cyan
    Get-Software "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"

    Write-Host "`n[+] Installed Software (32-bit on 64-bit OS):" -ForegroundColor Cyan
    Get-Software "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    Write-Host "`n" -NoNewLine
}

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

function Get-KDBXFiles {
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

function Get-XAMPPConfigFiles {
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

function Get-BrowserCredentials {
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

function Get-ScheduledTaskEscalation {
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "             Scheduled Task Escalation             " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "[Ref]: https://github.com/giddings32/WinRecon/blob/main/attack-methods/Scheduled_Task_Escalation.md" -ForegroundColor Cyan

    # Function to calculate task frequency
    function Calculate-TaskFrequency {
        param ($NextRunTime, $LastRunTime)
        try {
            $nextRun = [datetime]::ParseExact($NextRunTime, "M/d/yyyy h:mm:ss tt", $null)
            $lastRun = [datetime]::ParseExact($LastRunTime, "M/d/yyyy h:mm:ss tt", $null)
            $difference = $nextRun - $lastRun

            $output = ""
            if ($difference.Days -gt 0) { $output += "$($difference.Days) Days " }
            if ($difference.Hours -gt 0) { $output += "$($difference.Hours) Hours " }
            if ($difference.Minutes -gt 0) { $output += "$($difference.Minutes) Minutes " }
            if ($difference.Seconds -gt 0 -and $difference.Minutes -eq 0) { $output += "$($difference.Seconds) Seconds " }
            return $output.Trim()
        } catch {
            return "Unknown Frequency"
        }
    }

    # Function to resolve environment variables
    function Resolve-EnvironmentVariables {
        param ($path)
        try {
            return [System.Environment]::ExpandEnvironmentVariables($path)
        } catch {
            return $path
        }
    }

    # Function to sanitize TaskToRun path and run icacls
    function Check-ScheduledTaskPermissions {
        param ($TaskToRun)

        # Resolve environment variables and trim everything after the first space
        $resolvedPath = Resolve-EnvironmentVariables $TaskToRun
        $exePath = $resolvedPath -split ' ' | Select-Object -First 1

        # Early return if path is invalid
        if (-not (Test-Path $exePath)) {
            return $false
        }

        $includePermissionsRegex = ':(.*\b[WF]\b.*)'

        # Get the current user's groups
        $userIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $userGroups = $userIdentity.Groups | ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]).Value }
        $userGroups += $userIdentity.Name

        $filteredPermissions = @()
        try {
            $icaclsOutput = icacls $exePath 2>&1 | Where-Object {
                $_ -notmatch "Successfully processed" -and $_ -match $includePermissionsRegex
            }

            foreach ($line in $icaclsOutput) {
                # Extract the group name before the colon
                $groupName = ($line -split ':')[0].Trim()
                if ($userGroups -contains $groupName) {
                    $filteredPermissions += ($line -replace [regex]::Escape($exePath), '').Trim()
                }
            }

            if ($filteredPermissions) {
                return $filteredPermissions
            }
        } catch { }

        return $false
    }

    try {
        $schtasksOutput = schtasks /query /fo LIST /v 2>&1
        if (-not $schtasksOutput) {
            Write-Host "No scheduled tasks found or permission denied." -ForegroundColor Red
            return
        }

        $taskRegex = @{
            TaskName       = 'TaskName:\s+(.+)'
            TaskToRun      = 'Task To Run:\s+(.+)'
            NextRunTime    = 'Next Run Time:\s+(.+)'
            LastRunTime    = 'Last Run Time:\s+(.+)'
            Author         = 'Author:\s+(.+)'
            RunAsUser      = 'Run As User:\s+(.+)'
        }

        $tasks = @()
        $currentTask = @{ TaskName = ""; TaskToRun = ""; NextRunTime = ""; LastRunTime = ""; Author = ""; RunAsUser = "" }

        foreach ($line in $schtasksOutput) {
            if ($line -match $taskRegex.TaskName) { $currentTask.TaskName = $Matches[1] }
            elseif ($line -match $taskRegex.TaskToRun) {
                $resolvedPath = Resolve-EnvironmentVariables $Matches[1]
                $currentTask.TaskToRun = $resolvedPath
            }
            elseif ($line -match $taskRegex.NextRunTime) { $currentTask.NextRunTime = $Matches[1] }
            elseif ($line -match $taskRegex.LastRunTime) { $currentTask.LastRunTime = $Matches[1] }
            elseif ($line -match $taskRegex.Author) { $currentTask.Author = $Matches[1] }
            elseif ($line -match $taskRegex.RunAsUser) { $currentTask.RunAsUser = $Matches[1] }

            if ($line -eq "") {
                # Skip tasks where TaskToRun is a COM handler or invalid path
                if ($currentTask.TaskToRun -notmatch '^{.*}$' -and $currentTask.TaskToRun -match '\.') {
                    # Skip tasks where RunAsUser matches current user (strip domain)
                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -replace '.*\\', ''
                    if ($currentTask.RunAsUser -ne $currentUser) {
                        $tasks += [PSCustomObject]$currentTask
                    }
                }
                $currentTask = @{ TaskName = ""; TaskToRun = ""; NextRunTime = ""; LastRunTime = ""; Author = ""; RunAsUser = "" }
            }
        }

        # Remove duplicate tasks
        $uniqueTasks = $tasks | Sort-Object -Property @{Expression = { "$($_.TaskName)|$($_.TaskToRun)|$($_.NextRunTime)|$($_.Author)|$($_.RunAsUser)" }} -Unique

        foreach ($task in $uniqueTasks) {
            $permissions = Check-ScheduledTaskPermissions -TaskToRun $task.TaskToRun

            # Only display tasks with exploitable permissions
            if ($permissions) {
                Write-Host "`n[+] Task: $($task.TaskName)" -ForegroundColor Yellow
                Write-Host "    Task To Run: $($task.TaskToRun)" -ForegroundColor Yellow

                if ($task.NextRunTime -and $task.LastRunTime) {
                    $frequency = Calculate-TaskFrequency -NextRunTime $task.NextRunTime -LastRunTime $task.LastRunTime
                    Write-Host "    Task Runs Every: $frequency" -ForegroundColor White
                }

                Write-Host "    Author: $($task.Author)" -ForegroundColor White
                Write-Host "        Run As User: $($task.RunAsUser)" -ForegroundColor Yellow
                Write-Host "        [!] Exploitable Permissions Found:" -ForegroundColor Yellow
                foreach ($perm in $permissions) {
                    Write-Host "            $perm" -ForegroundColor Yellow
                }
            }
        }

    } catch {
        Write-Host "An error occurred while retrieving scheduled tasks: $_" -ForegroundColor Red
    }
}

function Get-UnquotedServicePaths {
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "             Unquoted Service Paths Check          " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "[Ref]: https://github.com/giddings32/WinRecon/blob/main/attack-methods/Unquoted_Service_Paths.md" -ForegroundColor Cyan

    # Define inclusion for permissions: must contain W or F
    $includePermissionsRegex = ':(.*\b[WF]\b.*)'

    # Function to check if a path is unquoted
    function Is-UnquotedPath {
        param ($Path)
        return ($Path -match '^[A-Za-z]:\\[^"]+ .+') -and ($Path -notmatch '^".+?"$')
    }

    # Function to check if a user is in a group
    function Is-UserInGroup {
        param ($GroupName)
        $userIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $userGroups = $userIdentity.Groups | ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]).Value }
        $userGroups += $userIdentity.Name
        return $userGroups -contains $GroupName
    }

    # Function to check if the current user matches the file owner
    function Is-UserOwner {
        param ($Path)
        try {
            $acl = Get-Acl -Path $Path -ErrorAction SilentlyContinue
            $owner = $acl.Owner
            return Is-UserInGroup -GroupName $owner
        } catch {
            return $false
        }
    }

    # Function to run icacls and filter permissions
    function Check-ICacls {
        param ($Path)

        # Split path into segments
        $pathParts = $Path -split '\\'
        $builtPath = ""
        $lastPath = ""

        $exploitablePaths = @() # Store exploitable paths to display later

        for ($i = 0; $i -lt $pathParts.Length - 1; $i++) {
            $builtPath += "$($pathParts[$i])\"  # Incrementally build the path
            $currentSegment = $pathParts[$i + 1]

            # Check if the next directory contains a space
            if ($currentSegment -match ' ') {
                $finalPath = if ($builtPath -eq "C:\") { "C:\" } else { $builtPath.TrimEnd('\') }
                if ($finalPath -ne $lastPath) {  # Avoid duplicate checks
                    $lastPath = $finalPath  # Save the last checked path

                    try {
                        # Run icacls and include only permissions with W or F after the colon
                        $validPermissions = icacls $finalPath 2>&1 | Where-Object {
                            $_ -notmatch "Successfully processed" -and
                            $_ -match $includePermissionsRegex
                        } | ForEach-Object {
                            $line = $_ -replace '^\s+', ''  # Clean up whitespace
                            $line = $line -replace [regex]::Escape($finalPath), ''  # Remove $finalPath from the output
			    $line = $line.Trim()                     # Trim trailing whitespace
                            $groupName = $line -replace '(:.*$)', ''  # Extract group name

                            if ($groupName -eq "CREATOR OWNER") {
                                if (Is-UserOwner -Path $finalPath) {
                                    $line
                                }
                            }
                            elseif (Is-UserInGroup -GroupName $groupName) {
                                $line
                            }
                        }

                        if ($validPermissions) {
                            # Add modified path with potential executable
                            $splitSegment = ($currentSegment -split ' ')[0] + ".exe"
                            $exploitablePaths += @{
                                Path = "$finalPath\$splitSegment"
                                Permissions = $validPermissions
                            }
                        }
                    } catch {
                        Write-Host "        Unable to check permissions for: $finalPath" -ForegroundColor Red
                    }
                }
            }
        }

        # Print exploitable paths if any valid permissions are found
        foreach ($pathEntry in $exploitablePaths) {
            Write-Host "    Exploitable Path: $($pathEntry.Path)" -ForegroundColor Cyan
            foreach ($perm in $pathEntry.Permissions) {
                Write-Host "        $perm" -ForegroundColor White
            }
        }
    }

    # Retrieve all services with their binary paths
    try {
        $services = Get-CimInstance Win32_Service | Where-Object { $_.PathName }

        foreach ($service in $services) {
            $cleanedPath = $service.PathName -replace '\s+[-/].*$', ''
            $cleanedPath = $cleanedPath.Trim()

            if (Is-UnquotedPath $cleanedPath) {
                Write-Host "`n[+] Service: $($service.Name)" -ForegroundColor Cyan
                Write-Host "    Binary Path: $cleanedPath" -ForegroundColor Yellow

                # Run icacls and filter permissions
                Check-ICacls -Path $cleanedPath
            }
        }
    } catch {
        Write-Host "Unable to fetch services. Check your permissions." -ForegroundColor Red
    }
}

function Get-ServiceBinaryHijacking {
    Write-Host "`n===================================================" -ForegroundColor Cyan
    write-host "                                                   " -backgroundcolor white
    Write-Host "          Service Binary Hijacking Check           " -ForegroundColor DarkBlue -backgroundcolor white
    write-host "                                                   " -backgroundcolor white
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "[Ref]: https://github.com/giddings32/WinRecon/blob/main/attack-methods/Service_Binary_Hijacking.md" -ForegroundColor Cyan

    # Define exclusion patterns for account names
    $excludePatterns = @(
        "NT AUTHORITY\\SYSTEM",
        "BUILTIN\\Administrators",
        "APPLICATION PACKAGE AUTHORITY\\ALL APPLICATION PACKAGES",
        "NT SERVICE\\TrustedInstaller"
    )

    # Define exclusion patterns for permissions
    $excludePermissions = @("\(RX\)$")

    # Define permission meanings
    $PermissionMeanings = @{
        "(F)"  = "Full control"
        "(M)"  = "Modify"
        "(RX)" = "Read and Execute"
        "(R)"  = "Read"
        "(W)"  = "Write"
        "(D)"  = "Delete"
        "(I)"  = "Inherited"
        "(OI)" = "Object inherit"
        "(CI)" = "Container inherit"
        "(IO)" = "Inherited only"
        "(N)"  = "No access"
    }

    # Helper function to add meanings to permissions
    function Add-PermissionMeanings {
        param ($line)
        $updatedLine = $line
        foreach ($perm in $PermissionMeanings.Keys) {
            if ($line -match [regex]::Escape($perm)) {
                $updatedLine += " --> $($PermissionMeanings[$perm])"
            }
        }
        return $updatedLine
    }

    # Fetch running services with binary paths
    $services = Get-CimInstance -ClassName Win32_Service |
        Where-Object { $_.State -eq 'Running' -and $_.PathName } |
        Select-Object Name, PathName

    foreach ($service in $services) {
        $binaryPath = $service.PathName -replace '"', '' -split '\s+' | Select-Object -First 1

        try {
            # Run icacls and capture output
            $icaclsOutput = icacls $binaryPath 2>&1

            # Skip services with "file not found" errors
            if ($icaclsOutput -match "The system cannot find the file specified") {
                continue
            }

            # Filter output dynamically, remove "Successfully processed"
            $filteredOutput = $icaclsOutput | Where-Object {
                $_ -notmatch ($excludePatterns -join "|") -and `
                $_ -notmatch ($excludePermissions -join "|") -and `
                $_ -notmatch "Successfully processed"
            }

            # Only print services with remaining permissions
            if ($filteredOutput -and ($filteredOutput | Where-Object { $_ -match ':' })) {
                Write-Host "`n[+] Service: $($service.Name)" -ForegroundColor Cyan
                Write-Host "    Binary Path: $binaryPath" -ForegroundColor White

                # Align permissions under "Binary Path" with meanings
                $filteredOutput | ForEach-Object {
                    $lineWithMeanings = Add-PermissionMeanings $_
                    Write-Host ("    " + $lineWithMeanings.TrimStart()) -ForegroundColor White
                }
            }
        } catch {
            Write-Host "`n[!] Unable to access binary path: $binaryPath" -ForegroundColor Red
        }
    }
}

function Get-DLLHijacking {
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "               DLL Hijacking Check                 " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "[Ref]: https://github.com/giddings32/WinRecon/blob/main/attack-methods/DLL_Hijacking.md" -ForegroundColor Cyan

    # List of known vulnerable software and versions
    $vulnerableSoftware = @(
        @{ Name = "Adobe Device Central CS5"; Version = "N/A"; DLL = "qtcf.dll" }
        @{ Name = "Adobe Dreamweaver CS4"; Version = "N/A"; DLL = "ibfs32.dll" }
        @{ Name = "Adobe Dreamweaver CS5"; Version = "11.0 build 4909"; DLL = "mfc90loc.dll" }
        @{ Name = "Adobe ExtendedScript Toolkit CS5"; Version = "3.5.0.52"; DLL = "dwmapi.dll" }
        @{ Name = "Adobe Extension Manager CS5"; Version = "5.0.298"; DLL = "dwmapi.dll" }
        @{ Name = "Adobe Illustrator CS4"; Version = "N/A"; DLL = "aires.dll" }
        @{ Name = "Adobe InDesign CS4"; Version = "N/A"; DLL = "ibfs32.dll" }
        @{ Name = "Adobe On Location CS4"; Version = "N/A"; DLL = "ibfs32.dll" }
        @{ Name = "Adobe Photoshop CS2"; Version = "N/A"; DLL = "Wintab32.dll" }
        @{ Name = "Adobe Premier Pro CS4"; Version = "N/A"; DLL = "ibfs32.dll" }
        @{ Name = "Apple Safari"; Version = "5.0.1"; DLL = "dwmapi.dll" }
        @{ Name = "Autodesk AutoCAD"; Version = "2007"; DLL = "color.dll" }
        @{ Name = "Avast!"; Version = "5.0.594"; DLL = "mfc90loc.dll" }
        @{ Name = "BS.Player"; Version = "2.56 build 1043"; DLL = "mfc71loc.dll" }
        @{ Name = "Cisco Packet Tracer"; Version = "5.2"; DLL = "wintab32.dll" }
        @{ Name = "Corel PHOTO-PAINT X3"; Version = "13.0.0.576"; DLL = "crlrib.dll" }
        @{ Name = "CorelDRAW X3"; Version = "13.0.0.576"; DLL = "crlrib.dll" }
        @{ Name = "Daemon Tools Lite"; Version = "N/A"; DLL = "mfc80loc.dll" }
        @{ Name = "Dashlane"; Version = "N/A"; DLL = "" }
        @{ Name = "Ettercap NG"; Version = "0.7.3"; DLL = "wpcap.dll" }
        @{ Name = "FileZilla Client"; Version = "3.63.1"; DLL = "TextShaping.dll" } # Validated
        @{ Name = "Google Earth"; Version = "5.1.3535.3218"; DLL = "quserex.dll" }
        @{ Name = "Huawei eSpace"; Version = "1.1.11.103"; DLL = "" }
        @{ Name = "Hubstaff"; Version = "1.6.14-61e5e22e"; DLL = "wow64log" }
        @{ Name = "InterVideo WinDVD"; Version = "5"; DLL = "cpqdvd.dll" }
        @{ Name = "Media Player Classic"; Version = "1.3.2189.0"; DLL = "iacenc.dll" }
        @{ Name = "Media Player Classic"; Version = "6.4.9.1"; DLL = "iacenc.dll" }
        @{ Name = "Microsoft Address Book"; Version = "6.00.2900.5512"; DLL = "wab32res.dll" }
        @{ Name = "Microsoft Group Convertor"; Version = "N/A"; DLL = "imm.dll" }
        @{ Name = "Microsoft Internet Connection Signup Wizard"; Version = "N/A"; DLL = "smmscrpt.dll" }
        @{ Name = "Microsoft Internet Explorer"; Version = "7"; DLL = "" }
        @{ Name = "Microsoft Office Groove"; Version = "2007"; DLL = "mso.dll" }
        @{ Name = "Microsoft PowerPoint"; Version = "2007"; DLL = "rpawinet.dll" }
        @{ Name = "Microsoft PowerPoint"; Version = "2010"; DLL = "pptimpconv.dll" }
        @{ Name = "Microsoft Visio"; Version = "2003"; DLL = "mfc71enu.dll" }
        @{ Name = "Microsoft Vista"; Version = "N/A"; DLL = "fveapi.dll" }
        @{ Name = "Microsoft Windows Contacts"; Version = "N/A"; DLL = "wab32res.dll" }
        @{ Name = "Microsoft Windows 11 Pro"; Version = "10.0.22621"; DLL = "apds.dll" }
        @{ Name = "Microsoft Windows 7"; Version = "7"; DLL = "wab32res.dll" }
        @{ Name = "Microsoft Windows Internet Communication Settings"; Version = "N/A"; DLL = "schannel.dll" }
        @{ Name = "Microsoft Windows Live Email"; Version = "N/A"; DLL = "dwmapi.dll" }
        @{ Name = "Microsoft Windows Movie Maker"; Version = "2.6.4038.0"; DLL = "hhctrl.ocx" }
        @{ Name = "Mozilla Firefox"; Version = "3.6.8"; DLL = "dwmapi.dll" }
        @{ Name = "Mozilla Thunderbird"; Version = "N/A"; DLL = "dwmapi.dll" }
        @{ Name = "NullSoft Winamp"; Version = "5.581"; DLL = "wnaspi32.dll" }
        @{ Name = "Nvidia Driver"; Version = "N/A"; DLL = "nview.dll" }
        @{ Name = "Opera"; Version = "10.61"; DLL = "dwmapi.dll" }
        @{ Name = "OutSystems Service Studio 11.53.30"; Version = "11.53.30"; DLL = "" }
        @{ Name = "Roxio Creator DE"; Version = "N/A"; DLL = "HomeUtils9.dll" }
        @{ Name = "Roxio MyDVD"; Version = "9"; DLL = "HomeUtils9.dll" }
        @{ Name = "Roxio Photosuite"; Version = "9"; DLL = "homeutils9.dll" }
        @{ Name = "Skype"; Version = "4.2.0.169"; DLL = "wab32.dll" }
        @{ Name = "TeamMate Audit Management Software Suite"; Version = "N/A"; DLL = "mfc71enu.dll" }
        @{ Name = "TeamViewer"; Version = "5.0.8703"; DLL = "dwmapi.dll" }
        @{ Name = "TechSmith Snagit"; Version = "10 (Build 788)"; DLL = "dwmapi.dll" }
        @{ Name = "VideoLAN VLC Media Player"; Version = "1.1.3"; DLL = "wintab32.dll" }
        @{ Name = "VMware Workstation"; Version = "15.1.0"; DLL = "" }
        @{ Name = "Wireshark"; Version = "1.2.10"; DLL = "airpcap.dll" }
        @{ Name = "μTorrent (uTorrent)"; Version = "2.0.3"; DLL = "plugin_dll.dll" }
    )

    function Is-PathWritable {
        param($Path)
        try {
            # Retrieve ACL for the path
            $acl = Get-Acl -Path $Path -ErrorAction Stop

            # Get current user and all groups/roles the user belongs to
            $userIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $userGroups = $userIdentity.Groups | ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]) }
            $userGroups += $userIdentity.Name  # Add current user

            # Check for writable permissions
            $writablePermissions = $acl.Access | Where-Object {
                $_.FileSystemRights -match "Write|Modify|FullControl" -and
                $_.AccessControlType -eq "Allow" -and
                ($userGroups -contains $_.IdentityReference)
            }

            return $writablePermissions.Count -gt 0
        } catch {
            return $false
        }
    }

    # Fetch installed software from the registry
    $installedSoftware = @()
    $installedSoftware += Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" -ErrorAction SilentlyContinue |
                          Select-Object DisplayName, PSChildName, DisplayVersion, InstallLocation

    $installedSoftware += Get-ItemProperty "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*" -ErrorAction SilentlyContinue |
                          Select-Object DisplayName, PSChildName, DisplayVersion, InstallLocation

    foreach ($software in $installedSoftware) {
        if (-not $software.InstallLocation) { continue } # Skip if InstallLocation is empty

        $isVulnerable = $false
        $vulnDLL = $null

        foreach ($vuln in $vulnerableSoftware) {
            if (($software.DisplayName -match [regex]::Escape($vuln.Name) -or 
                 $software.PSChildName -match [regex]::Escape($vuln.Name)) -and 
                 $software.DisplayVersion -match $vuln.Version) {
                $isVulnerable = $true
                $vulnDLL = $vuln.DLL
                break
            }
        }

        $color = if ($isVulnerable) { "Yellow" } else { "White" }

        Write-Host "`n[+] Program: $($software.DisplayName)" -ForegroundColor $color
        Write-Host "    Identifier: $($software.PSChildName)" -ForegroundColor $color
        Write-Host "    Version: $($software.DisplayVersion)" -ForegroundColor $color
        Write-Host "    Path: $($software.InstallLocation)" -ForegroundColor $color

        if (Is-PathWritable $software.InstallLocation) {
            Write-Host "    [!] Path is Writable" -ForegroundColor Yellow
        } else {
            Write-Host "    Path is Not Writable" -ForegroundColor White
        }

        if ($isVulnerable -and $vulnDLL) {
            Write-Host "    Vulnerable DLL: $vulnDLL" -ForegroundColor Yellow
        }
    }

    Write-Host "`n[+] Checking Operating System for Vulnerabilities..." -ForegroundColor Cyan
    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $osName = $os.Caption.Trim()
        $osVersion = $os.Version

        foreach ($vuln in $vulnerableSoftware) {
            if ($vuln.Name -match "Microsoft Windows" -and $osVersion -match $vuln.Version) {
                Write-Host "`n[+] OS: $osName" -ForegroundColor Yellow
                Write-Host "    Version: $osVersion" -ForegroundColor Yellow
                Write-Host "    Path: C:\\Windows\\" -ForegroundColor Yellow

                if (Is-PathWritable "C:\\Windows\\") {
                    Write-Host "    [!] Path is Writable" -ForegroundColor Yellow
                } else {
                    Write-Host "    Path is Not Writable" -ForegroundColor White
                }

                Write-Host "    Vulnerable DLL: $($vuln.DLL)" -ForegroundColor Yellow
                break
            }
        }
    } catch {
        Write-Host "Unable to check OS version and vulnerabilities." -ForegroundColor Red
    }

    # Additional code: Search for DLL hijacking within running services
    Write-Host "`n[+] Checking Running Services for Potential DLL Hijacking..." -ForegroundColor Cyan
    $commonPaths = @(
         "\\Windows\\System32\\svchost.exe"
         "\\Windows\\System32\\lsass.exe"
         "\\Windows\\System32\\dllhost.exe"
         "\\Windows\\System32\\msdtc.exe"
         "\\Windows\\System32\\SearchIndexer.exe"
         "\\Windows\\System32\\vm3dservice.exe"
         "\\Windows\\System32\\SecurityHealthService.exe"
         "\\Windows\\System32\\spoolsv.exe"
         "\\Windows\\System32\\SgrmBroker.exe"
         "\\ProgramData\\Microsoft\\Windows Defender\\"
         "\\Program Files\\VMware\\VMware Tools\\VMware VGAuth\\VGAuthService.exe"
	 "\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe"
    )

   try {
        $services = Get-CimInstance -ClassName Win32_Service | Where-Object {
            $_.State -eq "Running" -and
            -not [string]::IsNullOrWhiteSpace($_.PathName) -and
            ($_.PathName -notmatch ($commonPaths -join "|"))
        }

        foreach ($service in $services) {
            $path = $service.PathName -replace '"', ''
            $directoryPath = [System.IO.Path]::GetDirectoryName($path)

            Write-Host "`n[+] Program: $($service.DisplayName)" -ForegroundColor White
            Write-Host "    AutoRun: $([bool]($service.StartMode -eq 'Auto') -replace 'True', 'On' -replace 'False', 'Off')" -ForegroundColor White
            Write-Host "    Runs As: $($service.StartName)" -ForegroundColor White
            Write-Host "    Path: $path" -ForegroundColor White

            if (Is-PathWritable $directoryPath) {
                Write-Host "    [!] Directory is Writable" -ForegroundColor Yellow
            } else {
                Write-Host "    Directory is Not Writable" -ForegroundColor White
            }
        }
    } catch {
        Write-Host "Unable to enumerate running services." -ForegroundColor Red
    }
}

function Get-UserPrivileges {
    Write-Host "`n===================================================" -ForegroundColor Cyan
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "                   User Privileges                 " -ForegroundColor DarkBlue -BackgroundColor White
    Write-Host "                                                   " -BackgroundColor White
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "`n" -NoNewLine

    try {
        # Get current user's privileges
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name -replace '.*\\', ''
        $privileges = whoami /priv 2>&1

        # Function to check Windows version
        function Get-WindowsVersion {
            try {
                $os = (Get-CimInstance Win32_OperatingSystem).Caption
                return $os
            } catch {
                return "Unknown"
            }
        }

        # Recommend exploits based on Windows version and privilege
        function Recommend-Exploit {
            param($privilege)
            $osVersion = Get-WindowsVersion
            $exploits = @()

            switch ($privilege) {
                "SeImpersonatePrivilege" {
                    if ($osVersion -match "Windows 8|Windows 8.1|Windows 10|Windows 11|Windows Server 2012|Windows Server 2016|Windows Server 2019") {
                        $exploits += "SigmaPotato"
                    }
                    if ($osVersion -match "Windows 8|Windows 8.1|Windows 10|Windows 11|Windows Server 2012|Windows Server 2016|Windows Server 2019|Windows Server 2022") {
                        $exploits += "GodPotato"
                    }
                    if ($osVersion -match "Windows 10|Windows Server 2016|Windows Server 2019") {
                        $exploits += "PrintSpoofer"
                    }
                }
                "SeBackupPrivilege" {
                    if ($osVersion -match "Windows 7|Windows Server 2008|Windows Server 2012|Windows Server 2016") {
                        $exploits += "BackupPotato"
                    }
                }
                "SeAssignPrimaryTokenPrivilege" {
                    if ($osVersion -match "Windows 8|Windows 10|Windows Server 2012|Windows Server 2016") {
                        $exploits += "TokenMagic"
                    }
                }
                "SeLoadDriverPrivilege" {
                    if ($osVersion -match "Windows 8|Windows 10|Windows Server 2016|Windows Server 2019") {
                        $exploits += "DriverAbuse"
                    }
                }
                "SeDebugPrivilege" {
                    if ($osVersion -match "Windows 10|Windows Server 2016|Windows Server 2019|Windows 11") {
                        $exploits += "DbgPotato"
                    }
                }
            }

            if ($exploits.Count -eq 0) {
                return "N/A"
            } else {
                return ($exploits -join ", ")
            }
        }

        # Function to check privilege status
        function Check-Privilege {
            param($privilegeName)
            $result = $privileges | Select-String $privilegeName
            if ($result -match "\s+Enabled") {
                return $true
            } else {
                return $false
            }
        }

        # List of privileges to check
        $privilegeList = @(
            "SeImpersonatePrivilege",
            "SeBackupPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeLoadDriverPrivilege",
            "SeDebugPrivilege"
        )

        # Check each privilege and display results
        foreach ($privilege in $privilegeList) {
            if (Check-Privilege -privilegeName $privilege) {
                Write-Host "${currentUser}: $privilege Enabled" -ForegroundColor Yellow
                $recommendedExploits = Recommend-Exploit -privilege $privilege
                Write-Host "    Recommend Exploit: $recommendedExploits" -ForegroundColor Cyan
            } else {
                Write-Host "${currentUser}: $privilege Not Enabled" -ForegroundColor White
            }
        }

    } catch {
        Write-Host "An error occurred while checking privileges: $_" -ForegroundColor Red
    }
}



# Call enabled functions silently
if ($EnableSystemInfo) { Get-SystemInfo }
if ($EnableUserGroups) { Get-UserGroups }
if ($EnableUserFolderContents) { Get-UserFolderContents }
if ($EnablePowerShellHistory) { Get-PowerShellHistory }
if ($EnableEventViewerCredentials) { Get-EventViewerCredentials }
if ($EnableDPAPIMasterKeys) { Get-DPAPIMasterKeys }
if ($EnableRecentFiles) { Get-RecentFiles }
if ($EnableInstalledSoftware) { Get-InstalledSoftware }
if ($EnableProgramFilesContents) { Get-ProgramFilesContents }
if ($EnableKDBXFiles) { Get-KDBXFiles }
if ($EnableXAMPPConfigFiles) { Get-XAMPPConfigFiles }
if ($EnableNetworkConnections) { Get-NetworkConnections }
if ($EnableRunningProcesses) { Get-RunningProcesses }
if ($EnableBrowserCredentials) { Get-BrowserCredentials }
if ($EnableStartupPrograms) { Get-StartupPrograms }
if ($EnableScheduledTaskEscalation) { Get-ScheduledTaskEscalation }
if ($EnableUnquotedServicePaths) { Get-UnquotedServicePaths }
if ($EnableServiceBinaryHijacking) { Get-ServiceBinaryHijacking }
if ($EnableDLLHijacking) { Get-DLLHijacking }
if ($EnableUserPrivileges) { Get-UserPrivileges }
write-host "`n" -NoNewLine
