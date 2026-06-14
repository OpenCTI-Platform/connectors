"""
Complete MITRE ATT&CK TTP Mapping for OpenCTI
Includes technique names, tactics (kill chain phases), and descriptions
"""

# Kill Chain Phase definitions for MITRE ATT&CK
MITRE_KILL_CHAIN = "mitre-attack"

# TTP Database: technique_id -> {name, tactic, description}
TTP_DATABASE = {
    # ============= RECONNAISSANCE =============
    "T1595": {
        "name": "Active Scanning",
        "tactic": "reconnaissance",
        "description": "Adversaries may execute active reconnaissance scans to gather information.",
    },
    "T1595.001": {
        "name": "Scanning IP Blocks",
        "tactic": "reconnaissance",
        "description": "Adversaries may scan victim IP blocks to gather information.",
    },
    "T1595.002": {
        "name": "Vulnerability Scanning",
        "tactic": "reconnaissance",
        "description": "Adversaries may scan victims for vulnerabilities.",
    },
    "T1592": {
        "name": "Gather Victim Host Information",
        "tactic": "reconnaissance",
        "description": "Adversaries may gather information about victim hosts.",
    },
    "T1589": {
        "name": "Gather Victim Identity Information",
        "tactic": "reconnaissance",
        "description": "Adversaries may gather information about victim identities.",
    },
    # ============= RESOURCE DEVELOPMENT =============
    "T1583": {
        "name": "Acquire Infrastructure",
        "tactic": "resource-development",
        "description": "Adversaries may buy, lease, or rent infrastructure.",
    },
    "T1587": {
        "name": "Develop Capabilities",
        "tactic": "resource-development",
        "description": "Adversaries may build capabilities for use during targeting.",
    },
    "T1588": {
        "name": "Obtain Capabilities",
        "tactic": "resource-development",
        "description": "Adversaries may obtain capabilities for use during targeting.",
    },
    # ============= INITIAL ACCESS =============
    "T1189": {
        "name": "Drive-by Compromise",
        "tactic": "initial-access",
        "description": "Adversaries may gain access through a user visiting a website.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
        "description": "Adversaries may exploit vulnerabilities in internet-facing systems.",
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "initial-access",
        "description": "Adversaries may leverage external remote services for initial access.",
    },
    "T1200": {
        "name": "Hardware Additions",
        "tactic": "initial-access",
        "description": "Adversaries may introduce hardware into a system.",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "initial-access",
        "description": "Adversaries may send phishing messages to gain access.",
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "initial-access",
        "description": "Adversaries may send spearphishing emails with malicious attachments.",
    },
    "T1566.002": {
        "name": "Spearphishing Link",
        "tactic": "initial-access",
        "description": "Adversaries may send spearphishing emails with malicious links.",
    },
    "T1566.003": {
        "name": "Spearphishing via Service",
        "tactic": "initial-access",
        "description": "Adversaries may send spearphishing messages via third-party services.",
    },
    "T1091": {
        "name": "Replication Through Removable Media",
        "tactic": "initial-access",
        "description": "Adversaries may move onto systems via removable media.",
    },
    "T1195": {
        "name": "Supply Chain Compromise",
        "tactic": "initial-access",
        "description": "Adversaries may manipulate supply chain delivery mechanisms.",
    },
    "T1199": {
        "name": "Trusted Relationship",
        "tactic": "initial-access",
        "description": "Adversaries may breach trusted third parties.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "initial-access",
        "description": "Adversaries may use credentials of existing accounts.",
    },
    # ============= EXECUTION =============
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "description": "Adversaries may abuse command and script interpreters.",
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "execution",
        "description": "Adversaries may abuse PowerShell for execution.",
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "execution",
        "description": "Adversaries may abuse cmd.exe for execution.",
    },
    "T1059.005": {
        "name": "Visual Basic",
        "tactic": "execution",
        "description": "Adversaries may abuse VB/VBScript for execution.",
    },
    "T1059.006": {
        "name": "Python",
        "tactic": "execution",
        "description": "Adversaries may abuse Python for execution.",
    },
    "T1059.007": {
        "name": "JavaScript",
        "tactic": "execution",
        "description": "Adversaries may abuse JavaScript for execution.",
    },
    "T1203": {
        "name": "Exploitation for Client Execution",
        "tactic": "execution",
        "description": "Adversaries may exploit software vulnerabilities in client applications.",
    },
    "T1559": {
        "name": "Inter-Process Communication",
        "tactic": "execution",
        "description": "Adversaries may abuse IPC mechanisms for execution.",
    },
    "T1559.001": {
        "name": "Component Object Model",
        "tactic": "execution",
        "description": "Adversaries may abuse COM for execution.",
    },
    "T1559.002": {
        "name": "Dynamic Data Exchange",
        "tactic": "execution",
        "description": "Adversaries may abuse DDE for execution.",
    },
    "T1106": {
        "name": "Native API",
        "tactic": "execution",
        "description": "Adversaries may use native OS APIs for execution.",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "execution",
        "description": "Adversaries may abuse task scheduling functionality.",
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "tactic": "execution",
        "description": "Adversaries may abuse Windows Task Scheduler.",
    },
    "T1129": {
        "name": "Shared Modules",
        "tactic": "execution",
        "description": "Adversaries may execute via loading shared modules.",
    },
    "T1072": {
        "name": "Software Deployment Tools",
        "tactic": "execution",
        "description": "Adversaries may use software deployment tools.",
    },
    "T1569": {
        "name": "System Services",
        "tactic": "execution",
        "description": "Adversaries may abuse system services for execution.",
    },
    "T1569.002": {
        "name": "Service Execution",
        "tactic": "execution",
        "description": "Adversaries may execute via Windows services.",
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "execution",
        "description": "Adversaries may rely on user interaction for execution.",
    },
    "T1204.001": {
        "name": "Malicious Link",
        "tactic": "execution",
        "description": "Adversaries may rely on users clicking malicious links.",
    },
    "T1204.002": {
        "name": "Malicious File",
        "tactic": "execution",
        "description": "Adversaries may rely on users opening malicious files.",
    },
    "T1047": {
        "name": "Windows Management Instrumentation",
        "tactic": "execution",
        "description": "Adversaries may abuse WMI for execution.",
    },
    # ============= PERSISTENCE =============
    "T1098": {
        "name": "Account Manipulation",
        "tactic": "persistence",
        "description": "Adversaries may manipulate accounts to maintain access.",
    },
    "T1197": {
        "name": "BITS Jobs",
        "tactic": "persistence",
        "description": "Adversaries may abuse BITS for persistence.",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "persistence",
        "description": "Adversaries may configure autostart execution.",
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "persistence",
        "description": "Adversaries may use Run keys or Startup folder.",
    },
    "T1547.004": {
        "name": "Winlogon Helper DLL",
        "tactic": "persistence",
        "description": "Adversaries may abuse Winlogon helper DLLs.",
    },
    "T1547.009": {
        "name": "Shortcut Modification",
        "tactic": "persistence",
        "description": "Adversaries may modify shortcuts for persistence.",
    },
    "T1037": {
        "name": "Boot or Logon Initialization Scripts",
        "tactic": "persistence",
        "description": "Adversaries may use scripts during boot or logon.",
    },
    "T1176": {
        "name": "Browser Extensions",
        "tactic": "persistence",
        "description": "Adversaries may abuse browser extensions.",
    },
    "T1136": {
        "name": "Create Account",
        "tactic": "persistence",
        "description": "Adversaries may create accounts for persistence.",
    },
    "T1543": {
        "name": "Create or Modify System Process",
        "tactic": "persistence",
        "description": "Adversaries may create or modify system processes.",
    },
    "T1543.003": {
        "name": "Windows Service",
        "tactic": "persistence",
        "description": "Adversaries may create or modify Windows services.",
    },
    "T1546": {
        "name": "Event Triggered Execution",
        "tactic": "persistence",
        "description": "Adversaries may use event-triggered execution.",
    },
    "T1546.001": {
        "name": "Change Default File Association",
        "tactic": "persistence",
        "description": "Adversaries may change file associations.",
    },
    "T1546.003": {
        "name": "Windows Management Instrumentation Event Subscription",
        "tactic": "persistence",
        "description": "Adversaries may abuse WMI event subscriptions.",
    },
    "T1546.015": {
        "name": "Component Object Model Hijacking",
        "tactic": "persistence",
        "description": "Adversaries may hijack COM object references.",
    },
    "T1574": {
        "name": "Hijack Execution Flow",
        "tactic": "persistence",
        "description": "Adversaries may hijack execution flow.",
    },
    "T1574.001": {
        "name": "DLL Search Order Hijacking",
        "tactic": "persistence",
        "description": "Adversaries may hijack DLL search order.",
    },
    "T1574.002": {
        "name": "DLL Side-Loading",
        "tactic": "persistence",
        "description": "Adversaries may side-load malicious DLLs.",
    },
    "T1525": {
        "name": "Implant Internal Image",
        "tactic": "persistence",
        "description": "Adversaries may implant malicious images.",
    },
    "T1556": {
        "name": "Modify Authentication Process",
        "tactic": "persistence",
        "description": "Adversaries may modify authentication mechanisms.",
    },
    "T1137": {
        "name": "Office Application Startup",
        "tactic": "persistence",
        "description": "Adversaries may leverage Office startup features.",
    },
    "T1542": {
        "name": "Pre-OS Boot",
        "tactic": "persistence",
        "description": "Adversaries may abuse pre-OS boot mechanisms.",
    },
    "T1542.003": {
        "name": "Bootkit",
        "tactic": "persistence",
        "description": "Adversaries may use bootkits for persistence.",
    },
    "T1505": {
        "name": "Server Software Component",
        "tactic": "persistence",
        "description": "Adversaries may abuse server software components.",
    },
    "T1505.003": {
        "name": "Web Shell",
        "tactic": "persistence",
        "description": "Adversaries may install web shells.",
    },
    # ============= PRIVILEGE ESCALATION =============
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "privilege-escalation",
        "description": "Adversaries may bypass elevation control mechanisms.",
    },
    "T1548.002": {
        "name": "Bypass User Account Control",
        "tactic": "privilege-escalation",
        "description": "Adversaries may bypass UAC mechanisms.",
    },
    "T1134": {
        "name": "Access Token Manipulation",
        "tactic": "privilege-escalation",
        "description": "Adversaries may manipulate access tokens.",
    },
    "T1134.001": {
        "name": "Token Impersonation/Theft",
        "tactic": "privilege-escalation",
        "description": "Adversaries may impersonate or steal tokens.",
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "privilege-escalation",
        "description": "Adversaries may exploit vulnerabilities to escalate privileges.",
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "privilege-escalation",
        "description": "Adversaries may inject code into processes.",
    },
    "T1055.001": {
        "name": "Dynamic-link Library Injection",
        "tactic": "privilege-escalation",
        "description": "Adversaries may inject DLLs into processes.",
    },
    "T1055.002": {
        "name": "Portable Executable Injection",
        "tactic": "privilege-escalation",
        "description": "Adversaries may inject PE files into processes.",
    },
    "T1055.003": {
        "name": "Thread Execution Hijacking",
        "tactic": "privilege-escalation",
        "description": "Adversaries may hijack thread execution.",
    },
    "T1055.004": {
        "name": "Asynchronous Procedure Call",
        "tactic": "privilege-escalation",
        "description": "Adversaries may queue APCs to inject code.",
    },
    "T1055.012": {
        "name": "Process Hollowing",
        "tactic": "privilege-escalation",
        "description": "Adversaries may hollow out processes.",
    },
    # ============= DEFENSE EVASION =============
    "T1550": {
        "name": "Use Alternate Authentication Material",
        "tactic": "defense-evasion",
        "description": "Adversaries may use alternate authentication material.",
    },
    "T1550.002": {
        "name": "Pass the Hash",
        "tactic": "defense-evasion",
        "description": "Adversaries may pass NTLM hashes.",
    },
    "T1550.003": {
        "name": "Pass the Ticket",
        "tactic": "defense-evasion",
        "description": "Adversaries may pass Kerberos tickets.",
    },
    "T1140": {
        "name": "Deobfuscate/Decode Files or Information",
        "tactic": "defense-evasion",
        "description": "Adversaries may deobfuscate or decode data.",
    },
    "T1006": {
        "name": "Direct Volume Access",
        "tactic": "defense-evasion",
        "description": "Adversaries may directly access volumes.",
    },
    "T1484": {
        "name": "Domain Policy Modification",
        "tactic": "defense-evasion",
        "description": "Adversaries may modify domain policies.",
    },
    "T1480": {
        "name": "Execution Guardrails",
        "tactic": "defense-evasion",
        "description": "Adversaries may use execution guardrails.",
    },
    "T1211": {
        "name": "Exploitation for Defense Evasion",
        "tactic": "defense-evasion",
        "description": "Adversaries may exploit vulnerabilities to evade defenses.",
    },
    "T1222": {
        "name": "File and Directory Permissions Modification",
        "tactic": "defense-evasion",
        "description": "Adversaries may modify file/directory permissions.",
    },
    "T1564": {
        "name": "Hide Artifacts",
        "tactic": "defense-evasion",
        "description": "Adversaries may hide artifacts.",
    },
    "T1564.001": {
        "name": "Hidden Files and Directories",
        "tactic": "defense-evasion",
        "description": "Adversaries may hide files and directories.",
    },
    "T1564.003": {
        "name": "Hidden Window",
        "tactic": "defense-evasion",
        "description": "Adversaries may hide windows.",
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "defense-evasion",
        "description": "Adversaries may impair defensive capabilities.",
    },
    "T1562.001": {
        "name": "Disable or Modify Tools",
        "tactic": "defense-evasion",
        "description": "Adversaries may disable security tools.",
    },
    "T1562.004": {
        "name": "Disable or Modify System Firewall",
        "tactic": "defense-evasion",
        "description": "Adversaries may disable firewalls.",
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "defense-evasion",
        "description": "Adversaries may remove indicators.",
    },
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "tactic": "defense-evasion",
        "description": "Adversaries may clear event logs.",
    },
    "T1070.004": {
        "name": "File Deletion",
        "tactic": "defense-evasion",
        "description": "Adversaries may delete files.",
    },
    "T1202": {
        "name": "Indirect Command Execution",
        "tactic": "defense-evasion",
        "description": "Adversaries may use indirect command execution.",
    },
    "T1036": {
        "name": "Masquerading",
        "tactic": "defense-evasion",
        "description": "Adversaries may masquerade as legitimate entities.",
    },
    "T1036.004": {
        "name": "Masquerade Task or Service",
        "tactic": "defense-evasion",
        "description": "Adversaries may masquerade tasks or services.",
    },
    "T1036.005": {
        "name": "Match Legitimate Name or Location",
        "tactic": "defense-evasion",
        "description": "Adversaries may match legitimate names/locations.",
    },
    "T1112": {
        "name": "Modify Registry",
        "tactic": "defense-evasion",
        "description": "Adversaries may modify the registry.",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "defense-evasion",
        "description": "Adversaries may obfuscate files or information.",
    },
    "T1027.001": {
        "name": "Binary Padding",
        "tactic": "defense-evasion",
        "description": "Adversaries may pad binaries.",
    },
    "T1027.002": {
        "name": "Software Packing",
        "tactic": "defense-evasion",
        "description": "Adversaries may pack software.",
    },
    "T1027.003": {
        "name": "Steganography",
        "tactic": "defense-evasion",
        "description": "Adversaries may use steganography.",
    },
    "T1027.004": {
        "name": "Compile After Delivery",
        "tactic": "defense-evasion",
        "description": "Adversaries may compile code after delivery.",
    },
    "T1027.005": {
        "name": "Indicator Removal from Tools",
        "tactic": "defense-evasion",
        "description": "Adversaries may remove indicators from tools.",
    },
    "T1620": {
        "name": "Reflective Code Loading",
        "tactic": "defense-evasion",
        "description": "Adversaries may load code reflectively.",
    },
    "T1207": {
        "name": "Rogue Domain Controller",
        "tactic": "defense-evasion",
        "description": "Adversaries may register rogue domain controllers.",
    },
    "T1014": {
        "name": "Rootkit",
        "tactic": "defense-evasion",
        "description": "Adversaries may use rootkits.",
    },
    "T1218": {
        "name": "System Binary Proxy Execution",
        "tactic": "defense-evasion",
        "description": "Adversaries may use system binaries for proxy execution.",
    },
    "T1218.001": {
        "name": "Compiled HTML File",
        "tactic": "defense-evasion",
        "description": "Adversaries may abuse CHM files.",
    },
    "T1218.003": {
        "name": "CMSTP",
        "tactic": "defense-evasion",
        "description": "Adversaries may abuse CMSTP.",
    },
    "T1218.005": {
        "name": "Mshta",
        "tactic": "defense-evasion",
        "description": "Adversaries may abuse mshta.exe.",
    },
    "T1218.010": {
        "name": "Regsvr32",
        "tactic": "defense-evasion",
        "description": "Adversaries may abuse regsvr32.exe.",
    },
    "T1218.011": {
        "name": "Rundll32",
        "tactic": "defense-evasion",
        "description": "Adversaries may abuse rundll32.exe.",
    },
    "T1216": {
        "name": "System Script Proxy Execution",
        "tactic": "defense-evasion",
        "description": "Adversaries may use scripts for proxy execution.",
    },
    "T1221": {
        "name": "Template Injection",
        "tactic": "defense-evasion",
        "description": "Adversaries may inject malicious templates.",
    },
    "T1205": {
        "name": "Traffic Signaling",
        "tactic": "defense-evasion",
        "description": "Adversaries may use traffic signaling.",
    },
    "T1127": {
        "name": "Trusted Developer Utilities Proxy Execution",
        "tactic": "defense-evasion",
        "description": "Adversaries may use trusted dev utilities.",
    },
    "T1535": {
        "name": "Unused/Unsupported Cloud Regions",
        "tactic": "defense-evasion",
        "description": "Adversaries may use unsupported cloud regions.",
    },
    "T1497": {
        "name": "Virtualization/Sandbox Evasion",
        "tactic": "defense-evasion",
        "description": "Adversaries may detect virtualization/sandboxes.",
    },
    "T1497.001": {
        "name": "System Checks",
        "tactic": "defense-evasion",
        "description": "Adversaries may check for VM artifacts.",
    },
    "T1497.002": {
        "name": "User Activity Based Checks",
        "tactic": "defense-evasion",
        "description": "Adversaries may check for user activity.",
    },
    "T1497.003": {
        "name": "Time Based Evasion",
        "tactic": "defense-evasion",
        "description": "Adversaries may use time-based evasion.",
    },
    "T1600": {
        "name": "Weaken Encryption",
        "tactic": "defense-evasion",
        "description": "Adversaries may weaken encryption.",
    },
    "T1220": {
        "name": "XSL Script Processing",
        "tactic": "defense-evasion",
        "description": "Adversaries may abuse XSL script processing.",
    },
    # ============= CREDENTIAL ACCESS =============
    "T1557": {
        "name": "Adversary-in-the-Middle",
        "tactic": "credential-access",
        "description": "Adversaries may position themselves in the middle.",
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "credential-access",
        "description": "Adversaries may use brute force techniques.",
    },
    "T1555": {
        "name": "Credentials from Password Stores",
        "tactic": "credential-access",
        "description": "Adversaries may search password stores.",
    },
    "T1555.001": {
        "name": "Keychain",
        "tactic": "credential-access",
        "description": "Adversaries may access macOS Keychain.",
    },
    "T1555.003": {
        "name": "Credentials from Web Browsers",
        "tactic": "credential-access",
        "description": "Adversaries may access browser credentials.",
    },
    "T1212": {
        "name": "Exploitation for Credential Access",
        "tactic": "credential-access",
        "description": "Adversaries may exploit for credential access.",
    },
    "T1187": {
        "name": "Forced Authentication",
        "tactic": "credential-access",
        "description": "Adversaries may force authentication.",
    },
    "T1606": {
        "name": "Forge Web Credentials",
        "tactic": "credential-access",
        "description": "Adversaries may forge web credentials.",
    },
    "T1056": {
        "name": "Input Capture",
        "tactic": "credential-access",
        "description": "Adversaries may capture user input.",
    },
    "T1056.001": {
        "name": "Keylogging",
        "tactic": "credential-access",
        "description": "Adversaries may log keystrokes.",
    },
    "T1111": {
        "name": "Multi-Factor Authentication Interception",
        "tactic": "credential-access",
        "description": "Adversaries may intercept MFA.",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "credential-access",
        "description": "Adversaries may dump OS credentials.",
    },
    "T1003.001": {
        "name": "LSASS Memory",
        "tactic": "credential-access",
        "description": "Adversaries may access LSASS memory.",
    },
    "T1003.002": {
        "name": "Security Account Manager",
        "tactic": "credential-access",
        "description": "Adversaries may access SAM database.",
    },
    "T1003.003": {
        "name": "NTDS",
        "tactic": "credential-access",
        "description": "Adversaries may access NTDS.dit.",
    },
    "T1528": {
        "name": "Steal Application Access Token",
        "tactic": "credential-access",
        "description": "Adversaries may steal application tokens.",
    },
    "T1558": {
        "name": "Steal or Forge Kerberos Tickets",
        "tactic": "credential-access",
        "description": "Adversaries may steal or forge Kerberos tickets.",
    },
    "T1539": {
        "name": "Steal Web Session Cookie",
        "tactic": "credential-access",
        "description": "Adversaries may steal session cookies.",
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "credential-access",
        "description": "Adversaries may search for unsecured credentials.",
    },
    "T1552.001": {
        "name": "Credentials In Files",
        "tactic": "credential-access",
        "description": "Adversaries may search files for credentials.",
    },
    # ============= DISCOVERY =============
    "T1087": {
        "name": "Account Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover accounts.",
    },
    "T1010": {
        "name": "Application Window Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover application windows.",
    },
    "T1217": {
        "name": "Browser Information Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover browser information.",
    },
    "T1580": {
        "name": "Cloud Infrastructure Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover cloud infrastructure.",
    },
    "T1538": {
        "name": "Cloud Service Dashboard",
        "tactic": "discovery",
        "description": "Adversaries may access cloud dashboards.",
    },
    "T1526": {
        "name": "Cloud Service Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover cloud services.",
    },
    "T1613": {
        "name": "Container and Resource Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover containers.",
    },
    "T1482": {
        "name": "Domain Trust Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover domain trusts.",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "discovery",
        "description": "Adversaries may enumerate files and directories.",
    },
    "T1615": {
        "name": "Group Policy Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover group policies.",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover network services.",
    },
    "T1135": {
        "name": "Network Share Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover network shares.",
    },
    "T1040": {
        "name": "Network Sniffing",
        "tactic": "discovery",
        "description": "Adversaries may sniff network traffic.",
    },
    "T1201": {
        "name": "Password Policy Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover password policies.",
    },
    "T1120": {
        "name": "Peripheral Device Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover peripheral devices.",
    },
    "T1069": {
        "name": "Permission Groups Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover permission groups.",
    },
    "T1057": {
        "name": "Process Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover running processes.",
    },
    "T1012": {
        "name": "Query Registry",
        "tactic": "discovery",
        "description": "Adversaries may query the registry.",
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover remote systems.",
    },
    "T1518": {
        "name": "Software Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover installed software.",
    },
    "T1518.001": {
        "name": "Security Software Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover security software.",
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover system information.",
    },
    "T1614": {
        "name": "System Location Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover system location.",
    },
    "T1016": {
        "name": "System Network Configuration Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover network configuration.",
    },
    "T1049": {
        "name": "System Network Connections Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover network connections.",
    },
    "T1033": {
        "name": "System Owner/User Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover system owner/user.",
    },
    "T1007": {
        "name": "System Service Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover system services.",
    },
    "T1124": {
        "name": "System Time Discovery",
        "tactic": "discovery",
        "description": "Adversaries may discover system time.",
    },
    # ============= LATERAL MOVEMENT =============
    "T1210": {
        "name": "Exploitation of Remote Services",
        "tactic": "lateral-movement",
        "description": "Adversaries may exploit remote services.",
    },
    "T1534": {
        "name": "Internal Spearphishing",
        "tactic": "lateral-movement",
        "description": "Adversaries may spearphish internally.",
    },
    "T1570": {
        "name": "Lateral Tool Transfer",
        "tactic": "lateral-movement",
        "description": "Adversaries may transfer tools laterally.",
    },
    "T1563": {
        "name": "Remote Service Session Hijacking",
        "tactic": "lateral-movement",
        "description": "Adversaries may hijack remote sessions.",
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "lateral-movement",
        "description": "Adversaries may use remote services.",
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "tactic": "lateral-movement",
        "description": "Adversaries may use RDP.",
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "tactic": "lateral-movement",
        "description": "Adversaries may use SMB admin shares.",
    },
    "T1021.003": {
        "name": "Distributed Component Object Model",
        "tactic": "lateral-movement",
        "description": "Adversaries may use DCOM.",
    },
    "T1021.004": {
        "name": "SSH",
        "tactic": "lateral-movement",
        "description": "Adversaries may use SSH.",
    },
    "T1021.006": {
        "name": "Windows Remote Management",
        "tactic": "lateral-movement",
        "description": "Adversaries may use WinRM.",
    },
    "T1080": {
        "name": "Taint Shared Content",
        "tactic": "lateral-movement",
        "description": "Adversaries may taint shared content.",
    },
    # ============= COLLECTION =============
    "T1560": {
        "name": "Archive Collected Data",
        "tactic": "collection",
        "description": "Adversaries may archive collected data.",
    },
    "T1560.001": {
        "name": "Archive via Utility",
        "tactic": "collection",
        "description": "Adversaries may archive using utilities.",
    },
    "T1123": {
        "name": "Audio Capture",
        "tactic": "collection",
        "description": "Adversaries may capture audio.",
    },
    "T1119": {
        "name": "Automated Collection",
        "tactic": "collection",
        "description": "Adversaries may automate collection.",
    },
    "T1115": {
        "name": "Clipboard Data",
        "tactic": "collection",
        "description": "Adversaries may collect clipboard data.",
    },
    "T1530": {
        "name": "Data from Cloud Storage",
        "tactic": "collection",
        "description": "Adversaries may access cloud storage.",
    },
    "T1602": {
        "name": "Data from Configuration Repository",
        "tactic": "collection",
        "description": "Adversaries may collect configuration data.",
    },
    "T1213": {
        "name": "Data from Information Repositories",
        "tactic": "collection",
        "description": "Adversaries may collect from info repositories.",
    },
    "T1005": {
        "name": "Data from Local System",
        "tactic": "collection",
        "description": "Adversaries may collect local data.",
    },
    "T1039": {
        "name": "Data from Network Shared Drive",
        "tactic": "collection",
        "description": "Adversaries may collect from network shares.",
    },
    "T1025": {
        "name": "Data from Removable Media",
        "tactic": "collection",
        "description": "Adversaries may collect from removable media.",
    },
    "T1074": {
        "name": "Data Staged",
        "tactic": "collection",
        "description": "Adversaries may stage collected data.",
    },
    "T1114": {
        "name": "Email Collection",
        "tactic": "collection",
        "description": "Adversaries may collect email.",
    },
    "T1185": {
        "name": "Browser Session Hijacking",
        "tactic": "collection",
        "description": "Adversaries may hijack browser sessions.",
    },
    "T1113": {
        "name": "Screen Capture",
        "tactic": "collection",
        "description": "Adversaries may capture screenshots.",
    },
    "T1125": {
        "name": "Video Capture",
        "tactic": "collection",
        "description": "Adversaries may capture video.",
    },
    # ============= COMMAND AND CONTROL =============
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "command-and-control",
        "description": "Adversaries may communicate via application layer protocols.",
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "command-and-control",
        "description": "Adversaries may use web protocols for C2.",
    },
    "T1071.002": {
        "name": "File Transfer Protocols",
        "tactic": "command-and-control",
        "description": "Adversaries may use FTP for C2.",
    },
    "T1071.003": {
        "name": "Mail Protocols",
        "tactic": "command-and-control",
        "description": "Adversaries may use mail protocols for C2.",
    },
    "T1071.004": {
        "name": "DNS",
        "tactic": "command-and-control",
        "description": "Adversaries may use DNS for C2.",
    },
    "T1092": {
        "name": "Communication Through Removable Media",
        "tactic": "command-and-control",
        "description": "Adversaries may use removable media for C2.",
    },
    "T1132": {
        "name": "Data Encoding",
        "tactic": "command-and-control",
        "description": "Adversaries may encode C2 data.",
    },
    "T1001": {
        "name": "Data Obfuscation",
        "tactic": "command-and-control",
        "description": "Adversaries may obfuscate C2 data.",
    },
    "T1568": {
        "name": "Dynamic Resolution",
        "tactic": "command-and-control",
        "description": "Adversaries may dynamically resolve C2 addresses.",
    },
    "T1568.002": {
        "name": "Domain Generation Algorithms",
        "tactic": "command-and-control",
        "description": "Adversaries may use DGAs.",
    },
    "T1573": {
        "name": "Encrypted Channel",
        "tactic": "command-and-control",
        "description": "Adversaries may encrypt C2 communications.",
    },
    "T1573.001": {
        "name": "Symmetric Cryptography",
        "tactic": "command-and-control",
        "description": "Adversaries may use symmetric encryption.",
    },
    "T1573.002": {
        "name": "Asymmetric Cryptography",
        "tactic": "command-and-control",
        "description": "Adversaries may use asymmetric encryption.",
    },
    "T1008": {
        "name": "Fallback Channels",
        "tactic": "command-and-control",
        "description": "Adversaries may use fallback C2 channels.",
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "command-and-control",
        "description": "Adversaries may transfer tools into the environment.",
    },
    "T1104": {
        "name": "Multi-Stage Channels",
        "tactic": "command-and-control",
        "description": "Adversaries may use multi-stage C2.",
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "tactic": "command-and-control",
        "description": "Adversaries may use non-application layer protocols.",
    },
    "T1571": {
        "name": "Non-Standard Port",
        "tactic": "command-and-control",
        "description": "Adversaries may use non-standard ports.",
    },
    "T1572": {
        "name": "Protocol Tunneling",
        "tactic": "command-and-control",
        "description": "Adversaries may tunnel protocols.",
    },
    "T1090": {
        "name": "Proxy",
        "tactic": "command-and-control",
        "description": "Adversaries may use proxies.",
    },
    "T1090.001": {
        "name": "Internal Proxy",
        "tactic": "command-and-control",
        "description": "Adversaries may use internal proxies.",
    },
    "T1090.002": {
        "name": "External Proxy",
        "tactic": "command-and-control",
        "description": "Adversaries may use external proxies.",
    },
    "T1090.003": {
        "name": "Multi-hop Proxy",
        "tactic": "command-and-control",
        "description": "Adversaries may use multi-hop proxies.",
    },
    "T1219": {
        "name": "Remote Access Software",
        "tactic": "command-and-control",
        "description": "Adversaries may use remote access software.",
    },
    "T1102": {
        "name": "Web Service",
        "tactic": "command-and-control",
        "description": "Adversaries may use web services for C2.",
    },
    # ============= EXFILTRATION =============
    "T1020": {
        "name": "Automated Exfiltration",
        "tactic": "exfiltration",
        "description": "Adversaries may automate exfiltration.",
    },
    "T1030": {
        "name": "Data Transfer Size Limits",
        "tactic": "exfiltration",
        "description": "Adversaries may limit data transfer sizes.",
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "exfiltration",
        "description": "Adversaries may exfiltrate over alternative protocols.",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "exfiltration",
        "description": "Adversaries may exfiltrate over C2.",
    },
    "T1011": {
        "name": "Exfiltration Over Other Network Medium",
        "tactic": "exfiltration",
        "description": "Adversaries may exfiltrate over other networks.",
    },
    "T1052": {
        "name": "Exfiltration Over Physical Medium",
        "tactic": "exfiltration",
        "description": "Adversaries may exfiltrate over physical media.",
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": "exfiltration",
        "description": "Adversaries may exfiltrate to web services.",
    },
    "T1029": {
        "name": "Scheduled Transfer",
        "tactic": "exfiltration",
        "description": "Adversaries may schedule data transfers.",
    },
    "T1537": {
        "name": "Transfer Data to Cloud Account",
        "tactic": "exfiltration",
        "description": "Adversaries may transfer data to cloud accounts.",
    },
    # ============= IMPACT =============
    "T1531": {
        "name": "Account Access Removal",
        "tactic": "impact",
        "description": "Adversaries may remove account access.",
    },
    "T1485": {
        "name": "Data Destruction",
        "tactic": "impact",
        "description": "Adversaries may destroy data.",
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "impact",
        "description": "Adversaries may encrypt data for impact (ransomware).",
    },
    "T1565": {
        "name": "Data Manipulation",
        "tactic": "impact",
        "description": "Adversaries may manipulate data.",
    },
    "T1491": {
        "name": "Defacement",
        "tactic": "impact",
        "description": "Adversaries may deface systems.",
    },
    "T1561": {
        "name": "Disk Wipe",
        "tactic": "impact",
        "description": "Adversaries may wipe disks.",
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic": "impact",
        "description": "Adversaries may cause endpoint DoS.",
    },
    "T1495": {
        "name": "Firmware Corruption",
        "tactic": "impact",
        "description": "Adversaries may corrupt firmware.",
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "impact",
        "description": "Adversaries may inhibit system recovery.",
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "impact",
        "description": "Adversaries may cause network DoS.",
    },
    "T1496": {
        "name": "Resource Hijacking",
        "tactic": "impact",
        "description": "Adversaries may hijack resources (cryptomining).",
    },
    "T1489": {
        "name": "Service Stop",
        "tactic": "impact",
        "description": "Adversaries may stop services.",
    },
    "T1529": {
        "name": "System Shutdown/Reboot",
        "tactic": "impact",
        "description": "Adversaries may shutdown or reboot systems.",
    },
}


def get_ttp_info(ttp_id: str) -> dict:
    """Get TTP information by ID."""
    return TTP_DATABASE.get(
        ttp_id,
        {
            "name": f"ATT&CK Technique {ttp_id}",
            "tactic": "unknown",
            "description": f"MITRE ATT&CK technique {ttp_id}",
        },
    )


def get_kill_chain_phase(tactic: str) -> dict:
    """Create kill chain phase object for STIX."""
    return {"kill_chain_name": MITRE_KILL_CHAIN, "phase_name": tactic}
