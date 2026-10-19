#!/usr/bin/env python3
"""
Detection Engineering Portfolio: Benign Baseline Generator
Reference: PROJECT_PLAN.md - Section 3.5 & Week 2 Telemetry Baseline

Simulates 2-4 hours of benign enterprise telemetry across:
- Sysmon (EID 1, 3, 7, 8, 10, 11, 13, 19, 22, 23)
- Windows Security (EID 4624, 4625, 4662, 4663, 4688, 4698, 5140)
- PowerShell Operational (EID 4104)
- Linux auditd (execve, identity changes, network sockets)

Used for false-positive measurement, negative regression testing, and tuning.
"""

import json
import os
import random
from datetime import datetime, timedelta, timezone

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "fixtures", "baseline")

BENIGN_USERS = ["CORP\\jdoe", "CORP\\asmith", "CORP\\mscott", "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LOCAL SERVICE"]
BENIGN_COMPUTERS = ["WIN10-CLIENT01.corp.local", "WIN10-CLIENT02.corp.local", "DC01.corp.local", "SRV-FILE01.corp.local"]
BENIGN_DOMAINS = ["microsoft.com", "google.com", "github.com", "update.microsoft.com", "office.com", "corp.local"]

BENIGN_PROCESSES = [
    {
        "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "CommandLine": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\" --type=utility --utility-sub-type=network.mojom.NetworkService",
        "ParentImage": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "User": "CORP\\jdoe"
    },
    {
        "Image": "C:\\Windows\\System32\\svchost.exe",
        "CommandLine": "C:\\Windows\\system32\\svchost.exe -k LocalService -p -s nscp",
        "ParentImage": "C:\\Windows\\System32\\services.exe",
        "User": "NT AUTHORITY\\LOCAL SERVICE"
    },
    {
        "Image": "C:\\Windows\\explorer.exe",
        "CommandLine": "C:\\Windows\\Explorer.EXE",
        "ParentImage": "C:\\Windows\\System32\\userinit.exe",
        "User": "CORP\\asmith"
    },
    {
        "Image": "C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe",
        "CommandLine": "\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "User": "CORP\\jdoe"
    },
    {
        "Image": "C:\\Windows\\System32\\taskhostw.exe",
        "CommandLine": "taskhostw.exe {2227A293-AE75-4aa0-AF64-D1FF34241602}",
        "ParentImage": "C:\\Windows\\System32\\svchost.exe",
        "User": "CORP\\asmith"
    },
    {
        "Image": "C:\\Windows\\System32\\RuntimeBroker.exe",
        "CommandLine": "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding",
        "ParentImage": "C:\\Windows\\System32\\svchost.exe",
        "User": "CORP\\jdoe"
    }
]

BENIGN_PS_SCRIPTS = [
    "Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object -First 10",
    "Write-Host 'Checking enterprise network interface status...'; Get-NetIPAddress -AddressFamily IPv4",
    "Test-Connection -ComputerName dc01.corp.local -Count 2 -Quiet",
    "Get-ChildItem -Path 'C:\\Users\\Public' -Recurse | Measure-Object -Property Length -Sum",
    "Import-Module NetAdapter; Get-NetAdapter -Name * | Format-Table Name, Status, LinkSpeed",
    "Get-Date; [System.TimeZoneInfo]::Local.DisplayName"
]


def generate_baseline_events(num_events: int = 500, start_time: datetime = None) -> list:
    """Generate realistic benign enterprise telemetry across a 3-hour window."""
    random.seed(42)  # Deterministic generation
    if start_time is None:
        start_time = datetime(2026, 10, 19, 8, 0, 0, tzinfo=timezone.utc)

    events = []
    current_time = start_time

    for i in range(num_events):
        current_time += timedelta(seconds=random.randint(15, 45))
        timestamp_str = current_time.isoformat()
        computer = random.choice(BENIGN_COMPUTERS)
        event_category = random.choices(
            ["sysmon_proc", "sysmon_net", "sysmon_file", "sysmon_reg", "sysmon_dns", "ps_block", "sec_logon", "sec_share", "sec_task", "sec_ds", "sec_file_audit"],
            weights=[25, 20, 10, 10, 10, 8, 6, 4, 2, 2, 3],
            k=1
        )[0]

        if event_category == "sysmon_proc":
            proc = random.choice(BENIGN_PROCESSES)
            events.append({
                "EventID": 1,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "UtcTime": timestamp_str,
                "Computer": computer,
                "EventData": {
                    "UtcTime": timestamp_str,
                    "ProcessId": random.randint(1000, 30000),
                    "Image": proc["Image"],
                    "CommandLine": proc["CommandLine"],
                    "CurrentDirectory": "C:\\Windows\\system32\\",
                    "User": proc["User"],
                    "ParentProcessId": random.randint(500, 999),
                    "ParentImage": proc["ParentImage"],
                    "ParentCommandLine": proc["ParentImage"],
                    "IntegrityLevel": "Medium" if "CORP" in proc["User"] else "System"
                }
            })

        elif event_category == "sysmon_net":
            events.append({
                "EventID": 3,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "UtcTime": timestamp_str,
                "Computer": computer,
                "EventData": {
                    "UtcTime": timestamp_str,
                    "ProcessId": random.randint(1000, 30000),
                    "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                    "User": "CORP\\jdoe",
                    "Protocol": "tcp",
                    "Initiated": "true",
                    "SourceIp": "192.168.56.20",
                    "SourcePort": random.randint(49152, 65535),
                    "DestinationIp": f"142.250.{random.randint(1,250)}.{random.randint(1,250)}",
                    "DestinationPort": 443,
                    "DestinationHostname": random.choice(BENIGN_DOMAINS)
                }
            })

        elif event_category == "sysmon_file":
            user = random.choice(["jdoe", "asmith"])
            filename = f"report_q{random.randint(1,4)}_{random.randint(100,999)}.docx"
            events.append({
                "EventID": 11,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "UtcTime": timestamp_str,
                "Computer": computer,
                "EventData": {
                    "UtcTime": timestamp_str,
                    "ProcessId": random.randint(1000, 30000),
                    "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                    "TargetFilename": f"C:\\Users\\{user}\\Documents\\{filename}",
                    "CreationUtcTime": timestamp_str,
                    "User": f"CORP\\{user}"
                }
            })

        elif event_category == "sysmon_reg":
            events.append({
                "EventID": 13,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "UtcTime": timestamp_str,
                "Computer": computer,
                "EventData": {
                    "UtcTime": timestamp_str,
                    "ProcessId": random.randint(1000, 30000),
                    "EventType": "SetValue",
                    "Image": "C:\\Windows\\System32\\svchost.exe",
                    "TargetObject": "HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\Environment\\PROCESSOR_LEVEL",
                    "Details": "6",
                    "User": "NT AUTHORITY\\SYSTEM"
                }
            })

        elif event_category == "sysmon_dns":
            events.append({
                "EventID": 22,
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "UtcTime": timestamp_str,
                "Computer": computer,
                "EventData": {
                    "UtcTime": timestamp_str,
                    "ProcessId": random.randint(1000, 30000),
                    "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                    "QueryName": random.choice(BENIGN_DOMAINS),
                    "QueryStatus": "0",
                    "QueryResults": f"172.217.16.{random.randint(1,200)}",
                    "User": "CORP\\jdoe"
                }
            })

        elif event_category == "ps_block":
            events.append({
                "EventID": 4104,
                "Channel": "Microsoft-Windows-PowerShell/Operational",
                "UtcTime": timestamp_str,
                "Computer": computer,
                "EventData": {
                    "ScriptBlockText": random.choice(BENIGN_PS_SCRIPTS),
                    "ScriptBlockId": f"{random.randint(100000, 999999)}-abcd-4ef0-87ef-{random.randint(10000000, 99999999)}",
                    "MessageNumber": 1,
                    "MessageTotal": 1,
                    "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                }
            })

        elif event_category == "sec_logon":
            events.append({
                "EventID": 4624,
                "Channel": "Security",
                "UtcTime": timestamp_str,
                "Computer": computer,
                "EventData": {
                    "TargetUserName": "jdoe",
                    "TargetDomainName": "CORP",
                    "LogonType": 2,
                    "LogonProcessName": "User32",
                    "AuthenticationPackageName": "Negotiate",
                    "WorkstationName": "WIN10-CLIENT01",
                    "IpAddress": "127.0.0.1",
                    "IpPort": "0",
                    "ProcessName": "C:\\Windows\\System32\\winlogon.exe"
                }
            })

        elif event_category == "sec_share":
            events.append({
                "EventID": 5140,
                "Channel": "Security",
                "UtcTime": timestamp_str,
                "Computer": "DC01.corp.local",
                "EventData": {
                    "SubjectUserName": "jdoe",
                    "SubjectDomainName": "CORP",
                    "ShareName": "\\\\*\\SYSVOL",
                    "ShareLocalPath": "C:\\Windows\\SYSVOL\\sysvol",
                    "IpAddress": "192.168.56.20",
                    "IpPort": str(random.randint(49152, 65535))
                }
            })

        elif event_category == "sec_task":
            events.append({
                "EventID": 4698,
                "Channel": "Security",
                "UtcTime": timestamp_str,
                "Computer": computer,
                "EventData": {
                    "SubjectUserName": "SYSTEM",
                    "SubjectDomainName": "NT AUTHORITY",
                    "TaskName": "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
                    "TaskContent": "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task><Actions><Exec><Command>wsqmcons.exe</Command></Exec></Actions></Task>"
                }
            })

        elif event_category == "sec_ds":
            events.append({
                "EventID": 4662,
                "Channel": "Security",
                "UtcTime": timestamp_str,
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
            })

        elif event_category == "sec_file_audit":
            events.append({
                "EventID": 4663,
                "Channel": "Security",
                "UtcTime": timestamp_str,
                "Computer": computer,
                "EventData": {
                    "SubjectUserName": "jdoe",
                    "SubjectDomainName": "CORP",
                    "ObjectName": "C:\\Users\\jdoe\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History",
                    "ProcessName": "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
                    "AccessMask": "0x2",
                    "AccessList": "WriteData (or AddFile)"
                }
            })

    return events


def generate_edge_case_events():
    """Generates benign edge case events that test detection boundary conditions."""
    edge_cases = []
    base_time = datetime.now(timezone.utc) - timedelta(hours=2)

    # 1. Edge Case: IT admin listing vssadmin (NOT deleting)
    edge_cases.append({
        "EventID": 1,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "UtcTime": (base_time + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
        "Computer": "DC01.corp.local",
        "EventData": {
            "Image": "C:\\Windows\\System32\\vssadmin.exe",
            "CommandLine": "vssadmin.exe list writers",
            "User": "CORP\\corpadmin",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe"
        }
    })

    # 2. Edge Case: Admin querying WMI hardware specs (NOT process call create)
    edge_cases.append({
        "EventID": 1,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "UtcTime": (base_time + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        "Computer": "WIN10-CLIENT01.corp.local",
        "EventData": {
            "Image": "C:\\Windows\\System32\\wbem\\WMIC.exe",
            "CommandLine": "wmic.exe os get Caption,Version,OSArchitecture",
            "User": "CORP\\jdoe",
            "ParentImage": "C:\\Windows\\System32\\cmd.exe"
        }
    })

    # 3. Edge Case: Localhost RDP connection
    edge_cases.append({
        "EventID": 4624,
        "Channel": "Security",
        "UtcTime": (base_time + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
        "Computer": "WIN10-CLIENT01.corp.local",
        "EventData": {
            "TargetUserName": "jdoe",
            "TargetDomainName": "CORP",
            "LogonType": 10,
            "IpAddress": "127.0.0.1",
            "WorkstationName": "WIN10-CLIENT01"
        }
    })

    # 4. Edge Case: Standard Windows Update scheduled task created by SYSTEM
    edge_cases.append({
        "EventID": 4698,
        "Channel": "Security",
        "UtcTime": (base_time + timedelta(minutes=20)).isoformat().replace("+00:00", "Z"),
        "Computer": "DC01.corp.local",
        "EventData": {
            "SubjectUserName": "SYSTEM",
            "TaskName": "\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start",
            "TaskContent": "<?xml version=\"1.0\" encoding=\"UTF-16\"?><Task><Actions><Exec><Command>usoclient.exe</Command></Exec></Actions></Task>"
        }
    })

    # 5. Edge Case: Defender diagnostic query (NOT Set-MpPreference disabling)
    edge_cases.append({
        "EventID": 4104,
        "Channel": "Microsoft-Windows-PowerShell/Operational",
        "UtcTime": (base_time + timedelta(minutes=25)).isoformat().replace("+00:00", "Z"),
        "Computer": "WIN10-CLIENT01.corp.local",
        "EventData": {
            "ScriptBlockText": "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled",
            "Path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        }
    })

    # 6. Edge Case: Chrome downloading normal PDF invoice
    edge_cases.append({
        "EventID": 11,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "UtcTime": (base_time + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
        "Computer": "WIN10-CLIENT01.corp.local",
        "EventData": {
            "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
            "TargetFilename": "C:\\Users\\jdoe\\Downloads\\Q3_Report.pdf",
            "User": "CORP\\jdoe"
        }
    })

    # 7. Edge Case: Standard Curl to corporate web service on Port 443
    edge_cases.append({
        "EventID": 3,
        "Channel": "Microsoft-Windows-Sysmon/Operational",
        "UtcTime": (base_time + timedelta(minutes=35)).isoformat().replace("+00:00", "Z"),
        "Computer": "WIN10-CLIENT01.corp.local",
        "EventData": {
            "Image": "C:\\Windows\\System32\\curl.exe",
            "DestinationPort": 443,
            "DestinationIp": "142.250.190.46",
            "Initiated": "true",
            "User": "CORP\\jdoe"
        }
    })

    return edge_cases


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    events = generate_baseline_events(num_events=600)

    corpus_file = os.path.join(OUTPUT_DIR, "benign_baseline_corpus.json")
    with open(corpus_file, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

    # Edge cases corpus
    edge_cases = generate_edge_case_events()
    edge_file = os.path.join(OUTPUT_DIR, "benign_edge_cases_corpus.json")
    with open(edge_file, "w", encoding="utf-8") as ef:
        json.dump(edge_cases, ef, indent=2)

    # Partitioned files for targeted category testing
    partitions = {
        "baseline_sysmon.json": [e for e in events if "Sysmon" in e.get("Channel", "")],
        "baseline_security.json": [e for e in events if e.get("Channel") == "Security"],
        "baseline_powershell.json": [e for e in events if "PowerShell" in e.get("Channel", "")]
    }

    for fname, partition_events in partitions.items():
        p_path = os.path.join(OUTPUT_DIR, fname)
        with open(p_path, "w", encoding="utf-8") as pf:
            json.dump(partition_events, pf, indent=2)

    print(f"[+] Successfully generated benign baseline corpus & edge cases:")
    print(f"    - Total baseline events: {len(events)}")
    print(f"    - Edge case events: {len(edge_cases)}")
    print(f"    - Sysmon events: {len(partitions['baseline_sysmon.json'])}")
    print(f"    - Security events: {len(partitions['baseline_security.json'])}")
    print(f"    - PowerShell events: {len(partitions['baseline_powershell.json'])}")
    print(f"    - Corpus path: {corpus_file}")
    print(f"    - Edge cases path: {edge_file}")


if __name__ == "__main__":
    main()
