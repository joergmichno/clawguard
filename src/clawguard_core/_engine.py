"""
ClawGuard Core Engine — Pattern matching and scanning logic.

This module contains all detection patterns and the scan_text() function.
It is the heart of the ClawGuard security scanner.

(c) 2026 Joerg Michno
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List
from datetime import datetime, timezone


# --- Severity Levels ---

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def score(self) -> int:
        return {"LOW": 1, "MEDIUM": 3, "HIGH": 6, "CRITICAL": 10}[self.value]


# --- Data Structures ---

@dataclass
class Finding:
    severity: Severity
    category: str
    pattern_name: str
    matched_text: str
    line_number: int
    context: str
    recommendation: str


@dataclass
class ScanReport:
    timestamp: str
    source: str
    total_lines: int
    total_findings: int = 0
    risk_score: int = 0
    risk_level: str = "CLEAN"
    findings: List[Finding] = field(default_factory=list)


# --- Pattern Database ---
# Each pattern: (name, regex, severity, category, recommendation)

PROMPT_INJECTION_PATTERNS = [
    (
        "Direct Override (EN)",
        r"(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompts?|guidelines?)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCK this input immediately. This is a classic prompt injection attempting to override the agent's system instructions.",
    ),
    (
        "Direct Override (DE)",
        r"(?i)ignoriere?\s+(alle\s+)?(vorherigen?|bisherigen?|obigen?)\s+(Anweisungen?|Regeln?|Instruktionen?|Befehle?)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN. Klassische Prompt-Injection die versucht, die Systemanweisungen zu ueberschreiben.",
    ),
    (
        "New Instructions Override",
        r"(?i)(you\s+are\s+now|ab\s+jetzt\s+bist\s+du|from\s+now\s+on\s+you\s+are|your\s+new\s+(role|instructions?|task)\s+(is|are))",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCK. Attempt to redefine the agent's identity or role mid-conversation.",
    ),
    (
        "System Prompt Extraction",
        r"(?i)(show|reveal|print|display|output|repeat|give\s+me|zeig|nenne|wiederhole)\s+(your|the|deine?n?|die)\s+(system\s*prompt|instructions?|initial\s*prompt|rules?|Anweisungen?|Systemprompt)",
        Severity.HIGH,
        "Prompt Injection",
        "This input attempts to extract the agent's system prompt. Sensitive internal instructions could be leaked.",
    ),
    (
        "Role-Play Escape",
        r"(?i)(pretend|act\s+as\s+if|imagine|tu\s+so\s+als|stell\s+dir\s+vor).{0,50}(no\s+rules?|no\s+restrictions?|keine\s+Regeln?|without\s+limits?|ohne\s+Einschraenkungen?)",
        Severity.HIGH,
        "Prompt Injection",
        "Jailbreak attempt via role-play scenario to bypass safety constraints.",
    ),
    (
        "Delimiter Injection",
        r"(```system|<\|im_start\|>|<\|im_end\|>|\[INST\]|\[\/INST\]|<<SYS>>|<\/SYS>|<\|system\|>|<\|user\|>|<\|assistant\|>)",
        Severity.CRITICAL,
        "Prompt Injection",
        "CRITICAL: Injection of model-specific delimiters to manipulate the conversation structure.",
    ),
    (
        "Encoded Bypass (Base64 hint)",
        r"(?i)(decode|base64|atob|eval)\s*\(.{0,100}\)",
        Severity.HIGH,
        "Prompt Injection",
        "Possible attempt to smuggle encoded payloads past text filters.",
    ),
    (
        "Token Smuggling",
        r"(?i)(ignore|bypass|skip|disable)\s+(safety|filter|guard|moderation|content\s*policy|Sicherheit|Schutz)",
        Severity.HIGH,
        "Prompt Injection",
        "Attempt to explicitly disable or bypass security filters.",
    ),
    (
        "Synonym Override (EN)",
        r"(?i)(disregard|forget|dismiss|override|overrule|nullify|void|abandon|drop|suppress|set\s+aside|throw\s+out)\s+(all\s+)?(previous|prior|above|earlier|preceding|antecedent|foregoing|existing|current|original)\s+(instructions?|rules?|prompts?|guidelines?|directives?|regulations?|constraints?|policies?|orders?|commands?)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCK: Synonym-based prompt injection detected. Uses alternative vocabulary to bypass basic keyword filters.",
    ),
    (
        "Synonym Override (DE)",
        r"(?i)(vergiss|verwirf|uebergehe?|ueberschreibe?|missachte|setze?\s+ausser\s+Kraft|hebe?\s+auf)\s+(alle\s+)?(vorherigen?|bisherigen?|obigen?|bestehenden?|aktuellen?|urspruenglichen?)\s+(Anweisungen?|Regeln?|Instruktionen?|Befehle?|Richtlinien?|Vorgaben?|Vorschriften?)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCKIEREN: Synonym-basierte Prompt-Injection auf Deutsch erkannt.",
    ),
    (
        "Indirect Instruction Reset",
        r"(?i)(start\s+(fresh|over|anew|from\s+scratch)|begin\s+a\s+new\s+(session|context|conversation)|reset\s+(your|all)\s+(memory|context|instructions?)|fang\s+(neu|von\s+vorne)\s+an)",
        Severity.HIGH,
        "Prompt Injection",
        "Attempt to reset the agent's instruction context via indirect phrasing.",
    ),
    (
        "System/Admin Tag Injection",
        r"(?i)\[\s*(?:SYSTEM|ADMIN|IMPORTANT|PRIORITY|OVERRIDE|EMERGENCY|ROOT|SUPERUSER|MODERATOR)\s*\]",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCK: Fake authority tag detected (e.g., [SYSTEM], [ADMIN]).",
    ),
    (
        "Agent-Worm Propagation",
        r"(?i)(all\s+agents?\s+must|forward\s+this\s+to\s+all|spread\s+this\s+(message|instruction)|automated\s+instruction|replicate\s+this\s+(to|across)|inject\s+into\s+(all|every)\s+(?:other\s+)?(agents?|conversations?|sessions?)|inject\s+into\s+other\s+(agents?|conversations?|sessions?))",
        Severity.CRITICAL,
        "Prompt Injection",
        "CRITICAL: Agent-worm propagation pattern detected.",
    ),
    (
        "Base64 Encoded Payload",
        r"(?i)(?:base64[:\s]+[A-Za-z0-9+/]{20,}={0,2}|decode\s+(?:this|the\s+following)\s*:\s*[A-Za-z0-9+/]{20,}={0,2}|(?:execute|run|eval)\s+(?:the\s+)?(?:base64|encoded)\s+(?:string|payload|command|instruction)|(?:execute|run|eval)\s+(?:the\s+)?(?:base64)\s+encoded\s+\w+)",
        Severity.HIGH,
        "Prompt Injection",
        "Base64-encoded payload or decode instruction detected.",
    ),
]

DANGEROUS_COMMAND_PATTERNS = [
    (
        "Destructive Shell Command",
        r"(?:rm\s+-[rRf]{1,3}\s+[\\/]|mkfs\s|dd\s+if=|format\s+[A-Z]:|\:\(\)\s*\{\s*\:\|\:\s*\&\s*\})",
        Severity.CRITICAL,
        "Dangerous Command",
        "CRITICAL: Destructive system command detected.",
    ),
    (
        "Remote Code Execution",
        r"(?:curl\s+.{0,100}\|\s*(?:ba)?sh|wget\s+.{0,100}\|\s*(?:ba)?sh|python[3]?\s+-c\s+['\"].*(?:exec|eval|import\s+os))",
        Severity.CRITICAL,
        "Dangerous Command",
        "CRITICAL: Pipe-to-shell pattern detected.",
    ),
    (
        "Reverse Shell",
        r"(?:(?:bash|sh|nc|ncat)\s+.{0,50}(?:\/dev\/tcp|mkfifo|nc\s+-[elp])|python[3]?\s+-c\s+['\"].*socket.*connect)",
        Severity.CRITICAL,
        "Dangerous Command",
        "CRITICAL: Reverse shell pattern detected.",
    ),
    (
        "Privilege Escalation",
        r"(?:sudo\s+(?:su|chmod\s+[0-7]*777|chown\s+root)|chmod\s+[0-7]*4[0-7]{3}\s|SUID|setuid)",
        Severity.HIGH,
        "Dangerous Command",
        "Privilege escalation attempt detected.",
    ),
    (
        "Package / Dependency Install",
        r"(?:pip\s+install|npm\s+install|apt\s+install|yum\s+install|brew\s+install)\s+(?!--help)",
        Severity.MEDIUM,
        "Dangerous Command",
        "Software installation command detected. Verify the package source.",
    ),
]

PYTHON_OBFUSCATION_PATTERNS = [
    (
        "Python getattr Obfuscation",
        r"(?:getattr\s*\(\s*\w+\s*,\s*['\"].+['\"]\s*\))",
        Severity.CRITICAL,
        "Code Obfuscation",
        "CRITICAL: Python getattr() used to dynamically resolve functions.",
    ),
    (
        "Python eval/exec",
        r"(?:(?:eval|exec|compile)\s*\(\s*(?:['\"]|[a-zA-Z_]))",
        Severity.CRITICAL,
        "Code Obfuscation",
        "CRITICAL: Dynamic code execution via eval()/exec()/compile().",
    ),
    (
        "Python __import__",
        r"(?:__import__\s*\(|importlib\.import_module\s*\()",
        Severity.HIGH,
        "Code Obfuscation",
        "Dynamic module import detected.",
    ),
    (
        "Python String Concatenation Bypass",
        r"(?:['\"][a-z]{1,6}['\"]\s*\+\s*['\"][a-z]{1,6}['\"])",
        Severity.MEDIUM,
        "Code Obfuscation",
        "String concatenation pattern detected.",
    ),
    (
        "Python Dangerous File I/O",
        r"(?:open\s*\(\s*['\"]?\/(?:etc|proc|sys|dev|root|home|tmp|var|data)[\/'\"]|open\s*\(\s*['\"].*(?:shadow|passwd|id_rsa|authorized_keys|\.env|config|secret|token|key))",
        Severity.CRITICAL,
        "Code Obfuscation",
        "CRITICAL: Python file read targeting sensitive system paths.",
    ),
    (
        "Python subprocess/os.system",
        r"(?:(?:subprocess|os)\s*\.\s*(?:system|popen|call|run|Popen|exec[lv]?[pe]?)\s*\()",
        Severity.CRITICAL,
        "Code Obfuscation",
        "CRITICAL: Direct OS command execution via Python.",
    ),
    (
        "Python Socket Connection",
        r"(?:socket\.(?:socket|create_connection|connect)\s*\(|from\s+socket\s+import)",
        Severity.HIGH,
        "Code Obfuscation",
        "Network socket creation detected.",
    ),
    (
        "Python Magic Attributes",
        r"(?:__builtins__|__globals__|__subclasses__|__class__|__bases__|__mro__|__dict__)",
        Severity.CRITICAL,
        "Code Obfuscation",
        "CRITICAL: Access to Python magic attributes detected.",
    ),
    (
        "Python setattr/delattr Reflection",
        r"(?:(?:setattr|delattr)\s*\(\s*\w+\s*,\s*['\"])",
        Severity.HIGH,
        "Code Obfuscation",
        "Dynamic attribute manipulation via setattr/delattr.",
    ),
    (
        "Suspicious open() in Agent Input",
        r"(?:open\s*\(\s*['\"]|open\s*\(\s*[a-zA-Z_]+\s*[,\)]|\['open'\]|\[\"open\"\])",
        Severity.HIGH,
        "Code Obfuscation",
        "File open() call detected in agent input.",
    ),
    (
        "Multi-Part String Assembly",
        r"(?:['\"][^'\"]{1,8}['\"]\s*\+\s*['\"][^'\"]{1,8}['\"]\s*\+\s*['\"][^'\"]{1,8}['\"])",
        Severity.HIGH,
        "Code Obfuscation",
        "Three or more short string fragments concatenated.",
    ),
]

DATA_EXFILTRATION_PATTERNS = [
    (
        "API Key Leak",
        r"(?:(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,})",
        Severity.CRITICAL,
        "Data Exfiltration",
        "CRITICAL: Hardcoded API key or access token found.",
    ),
    (
        "Private Key Material",
        r"(?:-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----)",
        Severity.CRITICAL,
        "Data Exfiltration",
        "CRITICAL: Private key material detected in text.",
    ),
    (
        "Password in Cleartext",
        r"(?i)(?:password|passwort|passwd|kennwort|pwd)\s*[:=]\s*['\"]?[^\s'\"]{4,}",
        Severity.HIGH,
        "Data Exfiltration",
        "Cleartext password detected.",
    ),
    (
        "Database Connection String",
        r"(?:(?:mongodb|postgres|mysql|redis|sqlite):\/\/[^\s]+|Data\s+Source=[^\s;]+)",
        Severity.HIGH,
        "Data Exfiltration",
        "Database connection string with potential credentials detected.",
    ),
    (
        "Email Harvesting Pattern",
        r"(?:(?:send|forward|mail|email|sende?n?)\s+(?:to|an|nach)\s+[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,})",
        Severity.MEDIUM,
        "Data Exfiltration",
        "Instruction to send data to an external email address.",
    ),
    (
        "Webhook Exfiltration",
        r"(?:(?:https?:\/\/)?(?:hooks\.slack\.com|discord(?:app)?\.com\/api\/webhooks|webhook\.site|requestbin|pipedream)\/[^\s]+)",
        Severity.HIGH,
        "Data Exfiltration",
        "Outbound webhook URL detected.",
    ),
    (
        "Markdown Image Exfiltration",
        r"!\[[^\]]*\]\(\s*https?:\/\/[^\s\)]+(?:\?[^\s\)]*(?:data|token|key|secret|password|api|session|cookie|auth|user|content|exfil|steal|leak)[^\s\)]*)\)",
        Severity.CRITICAL,
        "Data Exfiltration",
        "CRITICAL: Markdown image tag with suspicious query parameters detected.",
    ),
]

SOCIAL_ENGINEERING_PATTERNS = [
    (
        "Urgency Manipulation",
        r"(?i)(urgent|immediately|right\s+now|sofort|dringend|jetzt\s+sofort|without\s+delay|ohne\s+Verzoegerung).{0,80}(send|execute|run|delete|pay|transfer|sende?n?|ausfuehren|loeschen|zahlen|ueberweisen)",
        Severity.MEDIUM,
        "Social Engineering",
        "Urgency + action pattern detected.",
    ),
    (
        "Authority Impersonation",
        r"(?i)(i\s+am\s+(?:your|the)\s+(?:\w+\s+)?(?:admin(?:istrator)?|owner|creator|developer|boss|CEO|moderator|supervisor|manager)|ich\s+bin\s+(?:dein|der)\s+(?:\w+\s+)?(?:Admin(?:istrator)?|Besitzer|Ersteller|Entwickler|Chef|Moderator))",
        Severity.HIGH,
        "Social Engineering",
        "Authority impersonation detected.",
    ),
    (
        "Confidentiality Trap",
        r"(?i)(don't\s+tell|do\s+not\s+share|keep\s+this\s+(secret|private|between\s+us)|sag\s+(das\s+)?niemandem|behalte?\s+(das\s+)?fuer\s+dich)",
        Severity.MEDIUM,
        "Social Engineering",
        "Secrecy instruction detected.",
    ),
    (
        "Authority Claim",
        r"(?i)(as\s+(?:the|an?|your)\s+(?:\w+\s+)?(?:administrator|moderator|supervisor|manager|authorized\s+(?:user|person|agent))|i\s+(?:am|have\s+been)\s+authorized\s+(?:to|by)|with\s+(?:admin|root|elevated)\s+(?:access|privileges?|permissions?)|speaking\s+(?:as|on\s+behalf\s+of)\s+(?:the\s+)?(?:system|admin|management))",
        Severity.HIGH,
        "Social Engineering",
        "Authority claim detected.",
    ),
    (
        "Credential Phishing",
        r"(?i)(your\s+(?:API\s+key|password|token|credentials?|account|session)\s+(?:has\s+)?(?:expired|been\s+(?:compromised|revoked|suspended|locked|disabled|reset))|(?:verify|confirm|re-?enter|provide|update)\s+your\s+(?:password|credentials?|API\s+key|token|login)|(?:click\s+here|visit\s+this\s+link|go\s+to)\s+to\s+(?:verify|restore|unlock|reactivate)\s+your\s+account)",
        Severity.HIGH,
        "Social Engineering",
        "Credential phishing pattern detected.",
    ),
]

ALL_PATTERNS = (
    PROMPT_INJECTION_PATTERNS
    + DANGEROUS_COMMAND_PATTERNS
    + PYTHON_OBFUSCATION_PATTERNS
    + DATA_EXFILTRATION_PATTERNS
    + SOCIAL_ENGINEERING_PATTERNS
)


# --- Scanner Engine ---

def scan_text(text: str, source: str = "stdin") -> ScanReport:
    """Scan a block of text against all security patterns."""
    lines = text.splitlines()
    report = ScanReport(
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        source=source,
        total_lines=len(lines),
    )

    for line_num, line in enumerate(lines, start=1):
        for name, pattern, severity, category, recommendation in ALL_PATTERNS:
            for match in re.finditer(pattern, line):
                matched = match.group(0)
                start = max(0, match.start() - 30)
                end = min(len(line), match.end() + 30)
                context = ("..." if start > 0 else "") + line[start:end] + ("..." if end < len(line) else "")

                report.findings.append(Finding(
                    severity=severity,
                    category=category,
                    pattern_name=name,
                    matched_text=matched[:120],
                    line_number=line_num,
                    context=context.strip(),
                    recommendation=recommendation,
                ))

    # Deduplicate findings (same pattern on the same line)
    seen = set()
    unique_findings = []
    for f in report.findings:
        key = (f.pattern_name, f.line_number, f.matched_text)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)
    report.findings = unique_findings
    report.total_findings = len(report.findings)

    # Calculate risk score (0-10 scale)
    raw = sum(f.severity.score() for f in report.findings)
    report.risk_score = min(10, raw)

    # Determine risk level
    if report.risk_score == 0:
        report.risk_level = "CLEAN"
    elif report.risk_score <= 3:
        report.risk_level = "LOW"
    elif report.risk_score <= 6:
        report.risk_level = "MEDIUM"
    elif report.risk_score <= 8:
        report.risk_level = "HIGH"
    else:
        report.risk_level = "CRITICAL"

    return report
