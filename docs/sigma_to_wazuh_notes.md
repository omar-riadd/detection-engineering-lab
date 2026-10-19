# Sigma to Wazuh Transpilation: Technical Architecture & Field Mapping Reference

> **Document Version:** 1.0.0  
> **Last Updated:** 2026-10-19  
> **Status:** Active Technical Specification  
> **Target Engine:** Wazuh SIEM 4.x `analysisd` Rule Engine

---

## 1. Executive Summary & The Transpilation Challenge

In enterprise security operations, maintaining detections across disparate SIEM and EDR platforms leads to vendor lock-in and high maintenance overhead. The **Sigma** project provides an open, vendor-agnostic specification for authoring log signatures. However, while query-based SIEM backends (e.g., Microsoft Sentinel KQL, Splunk SPL, Elastic DSL) are natively supported by the standard `pySigma` conversion engine, **no official, fully maintained pySigma backend exists for Wazuh**.

Unlike query engines that execute queries across indexed columnar data stores at search time, Wazuh employs an OSSEC-derived stream-based analysis engine (`analysisd`). Rules in Wazuh are defined using structured **XML schemas** that evaluate logs deterministically in memory at ingestion time.

To bridge this architectural gap without sacrificing Sigma as our single source of truth, this project implements a custom Python transpiler (`scripts/convert_sigma.py`) utilizing **Jinja2 templating** and a maintained **field mapping table**.

---

## 2. Core Differences: Sigma AST vs. Wazuh `analysisd`

| Feature | Sigma Standard | Wazuh XML (`analysisd`) | Transpiler Solution |
|---|---|---|---|
| **Paradigm** | Query search expression (Boolean AST) | Ingestion-time rule matching engine | Translates AST nodes into XML `<field>` tags |
| **Field Paths** | Standardized taxonomy (`CommandLine`, `Image`) | Dynamic decoded JSON paths (`win.eventdata.commandLine`) | Deterministic field normalization dictionary |
| **Logic Model** | Arbitrary boolean expressions (`AND`, `OR`, `NOT`, nested) | Conjunction of child tags; Disjunction requires sibling rules | Flattens simple selections; splits complex boolean logic |
| **Scoping** | Metadata `logsource` (product, service, category) | Hierarchical parent rules (`<if_sid>`) | Maps `logsource` and Event IDs to root Wazuh parent SIDs |
| **Regex Syntax** | Wildcards (`*`, `?`) and regex modifiers | OSSEC POSIX regex (`sre`) and PCRE2 | Translates Sigma wildcards to PCRE expressions (`(?i)`) |
| **Correlations** | Aggregations (`count() > 5 by Host | near`) | Multi-rule state tracking (`<if_matched_sids>`, `<same_source_ip>`) | Translates temporal correlation to composite rule chains |

---

## 3. Field Mapping Reference Table

Wazuh processes Windows Event Logs collected via the `win-eventchannel` log collector into structured JSON objects rooted under `win.eventdata` or `win.system`. The table below defines the mapping from Sigma standard fields to Wazuh decoded JSON attributes:

| Sigma Standard Field | Windows Event ID | Windows Native Field Name | Wazuh Decoded XML Path | Type |
|---|---|---|---|---|
| `EventID` | All | `System.EventID` | `win.system.eventID` | Numeric |
| `Channel` | All | `System.Channel` | `win.system.channel` | String |
| `Computer` | All | `System.Computer` | `win.system.computer` | String |
| `User` / `SubjectUserName` | EID 1, 4624, 4662, 5140 | `SubjectUserName` / `User` | `win.eventdata.subjectUserName` / `win.eventdata.user` | String |
| `SubjectDomainName` | EID 4624, 4662, 5140 | `SubjectDomainName` | `win.eventdata.subjectDomainName` | String |
| `Image` | Sysmon EID 1 | `NewProcessName` / `Image` | `win.eventdata.image` | File Path |
| `CommandLine` | Sysmon EID 1, Sec 4688 | `CommandLine` | `win.eventdata.commandLine` | String |
| `ParentImage` | Sysmon EID 1 | `ParentProcessName` / `ParentImage` | `win.eventdata.parentImage` | File Path |
| `ParentCommandLine` | Sysmon EID 1 | `ParentCommandLine` | `win.eventdata.parentCommandLine` | String |
| `TargetFilename` | Sysmon EID 11 | `TargetFilename` | `win.eventdata.targetFilename` | File Path |
| `TargetObject` | Sysmon EID 13 | `TargetObject` | `win.eventdata.targetObject` | Registry Key |
| `Details` | Sysmon EID 13 | `Details` | `win.eventdata.details` | String |
| `SourceImage` | Sysmon EID 8, 10 | `SourceImage` | `win.eventdata.sourceImage` | File Path |
| `TargetImage` | Sysmon EID 10 | `TargetImage` | `win.eventdata.targetImage` | File Path |
| `GrantedAccess` | Sysmon EID 10 | `GrantedAccess` | `win.eventdata.grantedAccess` | Hex Mask |
| `CallTrace` | Sysmon EID 10 | `CallTrace` | `win.eventdata.callTrace` | String |
| `Properties` | Sec EID 4662 | `Properties` | `win.eventdata.properties` | GUID String |
| `ShareName` | Sec EID 5140 | `ShareName` | `win.eventdata.shareName` | UNC Path |
| `IpAddress` | Sec EID 4624, 5140 | `IpAddress` | `win.eventdata.ipAddress` | IPv4/IPv6 |
| `ScriptBlockText` | PS EID 4104 | `ScriptBlockText` | `win.eventdata.scriptBlockText` | Text Block |
| `DestinationPort` | Sysmon EID 3 | `DestinationPort` | `win.eventdata.destinationPort` | Numeric |

---

## 4. Parent Rule Scoping (`<if_sid>`)

In Wazuh, child rules are only evaluated if a parent decoder rule has already matched the incoming log line. When transpiling Sigma rules to Wazuh, each rule must explicitly include the appropriate `<if_sid>` to ensure it is evaluated against the correct event stream:

| Telemetry Channel | Windows Event ID | Wazuh Parent SID | Description |
|---|---|---|---|
| `Microsoft-Windows-Sysmon/Operational` | EID 1 (Process Create) | `60103` | Generic Sysmon Process Creation root rule |
| `Microsoft-Windows-Sysmon/Operational` | EID 3 (Network Connect) | `60105` | Generic Sysmon Network Connection root rule |
| `Microsoft-Windows-Sysmon/Operational` | EID 8 (CreateRemoteThread) | `60110` | Generic Sysmon CreateRemoteThread root rule |
| `Microsoft-Windows-Sysmon/Operational` | EID 10 (ProcessAccess) | `60112` | Generic Sysmon Process Access root rule |
| `Microsoft-Windows-Sysmon/Operational` | EID 11 (FileCreate) | `60113` | Generic Sysmon File Creation root rule |
| `Microsoft-Windows-Sysmon/Operational` | EID 13 (RegistryEvent) | `60115` | Generic Sysmon Registry Event root rule |
| `Security` | EID 4624 (Logon) | `60106` | Generic Windows Successful Logon root rule |
| `Security` | EID 4662 (DS Access) | `60100` | Generic Windows Security Auditing root rule |
| `Security` | EID 5140 (Share Access) | `60100` | Generic Windows Security Auditing root rule |
| `Security` | EID 4688 (Process Create) | `60156` | Windows Native Process Creation root rule |
| `Microsoft-Windows-PowerShell/Operational` | EID 4104 (Script Block) | `91800` | Generic PowerShell Operational root rule |

---

## 5. Structural Transpilation Rules

### 5.1 Modifier Translation
Sigma field modifiers define string matching behaviors. The transpiler converts them to regex constructs within `<field type="pcre2">`:

- **`contains`**:  
  Sigma: `CommandLine|contains: 'mimikatz'`  
  Wazuh: `<field name="win.eventdata.commandLine" type="pcre2">(?i)mimikatz</field>`

- **`endswith`**:  
  Sigma: `Image|endswith: '\net.exe'`  
  Wazuh: `<field name="win.eventdata.image" type="pcre2">(?i)\\net\.exe$</field>`

- **`startswith`**:  
  Sigma: `TargetFilename|startswith: 'C:\Users\Public\'`  
  Wazuh: `<field name="win.eventdata.targetFilename" type="pcre2">(?i)^C:\\Users\\Public\\</field>`

- **List of Values (OR Logic)**:  
  Sigma:
  ```yaml
  Image|endswith:
    - '\net.exe'
    - '\net1.exe'
  ```
  Wazuh:
  ```xml
  <field name="win.eventdata.image" type="pcre2">(?i)(\\net\.exe|\\net1\.exe)$</field>
  ```

### 5.2 Filter / Exclusion Logic
Sigma rules frequently use `and not filter` clauses. In Wazuh, negative matching within the same rule can be achieved using `negate="yes"` on `<field>` or `<match>` tags:
```xml
<field name="win.eventdata.subjectUserName" negate="yes" type="pcre2">.*\$</field>
```

### 5.3 Wazuh Rule ID Management
Wazuh reserves rule IDs `1` through `99999` for official default rules. Custom rules created by security teams must use IDs **`100000` or higher**. The transpiler deterministically assigns custom rule IDs in the range `100100`–`100999` based on rule indexing and persists them in the output XML.

---

## 6. Interview & Portfolio Talking Points

> *"When implementing our Detection-as-Code pipeline, I identified that no official pySigma backend exists for Wazuh due to architectural differences between query-based SIEMs and Wazuh's ingestion-time XML engine. I engineered a custom Jinja2-based transpiler that parses Sigma YAML definitions, maps fields to Wazuh's decoded JSON schema (`win.eventdata.*`), and anchors them to appropriate parent SIDs (`<if_sid>`). To maintain multi-SIEM portability, our pipeline simultaneously compiles all rules to Microsoft Sentinel KQL and Splunk SPL."*
