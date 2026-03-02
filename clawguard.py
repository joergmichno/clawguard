#!/usr/bin/env python3
"""
ClawGuard v0.3.0 – The Firewall for Autonomous AI Agents.
A CLI tool that scans text for prompt injections, dangerous commands,
and social engineering patterns.

Usage:
    python3 clawguard.py <file>          Scan a text file
    python3 clawguard.py --stdin         Scan from standard input
    echo "text" | python3 clawguard.py   Pipe text directly

Exit Codes:
    0 = Clean (no threats found)
    1 = Threats detected
    2 = Error (file not found, etc.)

(c) 2026 Jörg Michno
"""

import re
import sys
import json
import argparse
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List
from datetime import datetime, timezone


# ─── Severity Levels ─────────────────────────────────────────────────────────

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def score(self) -> int:
        return {"LOW": 1, "MEDIUM": 3, "HIGH": 6, "CRITICAL": 10}[self.value]


# ─── Data Structures ─────────────────────────────────────────────────────────

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


# ─── Pattern Database ─────────────────────────────────────────────────────────
# Each pattern: (name, regex, severity, category, recommendation)

PROMPT_INJECTION_PATTERNS = [
    # --- Direct Instruction Override (EN + DE) ---
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
        "BLOCKIEREN. Klassische Prompt-Injection die versucht, die Systemanweisungen zu überschreiben.",
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
        r"(?i)(pretend|act\s+as\s+if|imagine|tu\s+so\s+als|stell\s+dir\s+vor).{0,50}(no\s+rules?|no\s+restrictions?|keine\s+Regeln?|without\s+limits?|ohne\s+Einschränkungen?)",
        Severity.HIGH,
        "Prompt Injection",
        "Jailbreak attempt via role-play scenario to bypass safety constraints.",
    ),
    (
        "Delimiter Injection",
        r"(```system|<\|im_start\|>|<\|im_end\|>|\[INST\]|\[\/INST\]|<<SYS>>|<\/SYS>|<\|system\|>|<\|user\|>|<\|assistant\|>)",
        Severity.CRITICAL,
        "Prompt Injection",
        "CRITICAL: Injection of model-specific delimiters to manipulate the conversation structure. This is a sophisticated attack.",
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
    # --- v0.2.0: Synonym Bypass Defense ---
    (
        "Synonym Override (EN)",
        r"(?i)(disregard|forget|dismiss|override|overrule|nullify|void|abandon|drop|suppress|set\s+aside|throw\s+out)\s+(all\s+)?(previous|prior|above|earlier|preceding|antecedent|foregoing|existing|current|original)\s+(instructions?|rules?|prompts?|guidelines?|directives?|regulations?|constraints?|policies?|orders?|commands?)",
        Severity.CRITICAL,
        "Prompt Injection",
        "BLOCK: Synonym-based prompt injection detected. Uses alternative vocabulary to bypass basic keyword filters.",
    ),
    (
        "Synonym Override (DE)",
        r"(?i)(vergiss|verwirf|übergehe?|überschreibe?|missachte|setze?\s+außer\s+Kraft|hebe?\s+auf)\s+(alle\s+)?(vorherigen?|bisherigen?|obigen?|bestehenden?|aktuellen?|ursprünglichen?)\s+(Anweisungen?|Regeln?|Instruktionen?|Befehle?|Richtlinien?|Vorgaben?|Vorschriften?)",
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
]

DANGEROUS_COMMAND_PATTERNS = [
    # --- Shell / System Commands ---
    (
        "Destructive Shell Command",
        r"(?:rm\s+-[rRf]{1,3}\s+[\\/]|mkfs\s|dd\s+if=|format\s+[A-Z]:|\:\(\)\s*\{\s*\:\|\:\s*\&\s*\})",
        Severity.CRITICAL,
        "Dangerous Command",
        "CRITICAL: Destructive system command detected (disk wipe, fork bomb, or recursive delete).",
    ),
    (
        "Remote Code Execution",
        r"(?:curl\s+.{0,100}\|\s*(?:ba)?sh|wget\s+.{0,100}\|\s*(?:ba)?sh|python[3]?\s+-c\s+['\"].*(?:exec|eval|import\s+os))",
        Severity.CRITICAL,
        "Dangerous Command",
        "CRITICAL: Pipe-to-shell pattern detected. This downloads and executes remote code without inspection.",
    ),
    (
        "Reverse Shell",
        r"(?:(?:bash|sh|nc|ncat)\s+.{0,50}(?:\/dev\/tcp|mkfifo|nc\s+-[elp])|python[3]?\s+-c\s+['\"].*socket.*connect)",
        Severity.CRITICAL,
        "Dangerous Command",
        "CRITICAL: Reverse shell pattern detected. An attacker is attempting to gain remote command access.",
    ),
    (
        "Privilege Escalation",
        r"(?:sudo\s+(?:su|chmod\s+[0-7]*777|chown\s+root)|chmod\s+[0-7]*4[0-7]{3}\s|SUID|setuid)",
        Severity.HIGH,
        "Dangerous Command",
        "Privilege escalation attempt detected. The command tries to elevate system permissions.",
    ),
    (
        "Package / Dependency Install",
        r"(?:pip\s+install|npm\s+install|apt\s+install|yum\s+install|brew\s+install)\s+(?!--help)",
        Severity.MEDIUM,
        "Dangerous Command",
        "Software installation command detected. Verify the package source for supply-chain safety.",
    ),
]

# --- v0.2.0: Python Code Obfuscation Patterns ---
PYTHON_OBFUSCATION_PATTERNS = [
    (
        "Python getattr Obfuscation",
        r"(?:getattr\s*\(\s*\w+\s*,\s*['\"].+['\"]\s*\))",
        Severity.CRITICAL,
        "Code Obfuscation",
        "CRITICAL: Python getattr() used to dynamically resolve functions. This is a common technique to bypass static code analysis (e.g., getattr(os, 'sys'+'tem')).",
    ),
    (
        "Python eval/exec",
        r"(?:(?:eval|exec|compile)\s*\(\s*(?:['\"]|[a-zA-Z_]))",
        Severity.CRITICAL,
        "Code Obfuscation",
        "CRITICAL: Dynamic code execution via eval()/exec()/compile(). This can execute arbitrary obfuscated payloads.",
    ),
    (
        "Python __import__",
        r"(?:__import__\s*\(|importlib\.import_module\s*\()",
        Severity.HIGH,
        "Code Obfuscation",
        "Dynamic module import detected. Used to load dangerous modules (os, subprocess, socket) at runtime.",
    ),
    (
        "Python String Concatenation Bypass",
        r"(?:['\"][a-z]{1,6}['\"]\s*\+\s*['\"][a-z]{1,6}['\"])",
        Severity.MEDIUM,
        "Code Obfuscation",
        "String concatenation pattern detected (e.g., 'sys'+'tem'). Often used to evade keyword-based filters.",
    ),
    (
        "Python Dangerous File I/O",
        r"(?:open\s*\(\s*['\"]?\/(?:etc|proc|sys|dev|root|home|tmp|var|data)[\/'\"]|open\s*\(\s*['\"].*(?:shadow|passwd|id_rsa|authorized_keys|\.env|config|secret|token|key))",
        Severity.CRITICAL,
        "Code Obfuscation",
        "CRITICAL: Python file read targeting sensitive system paths or credential files.",
    ),
    (
        "Python subprocess/os.system",
        r"(?:(?:subprocess|os)\s*\.\s*(?:system|popen|call|run|Popen|exec[lv]?[pe]?)\s*\()",
        Severity.CRITICAL,
        "Code Obfuscation",
        "CRITICAL: Direct OS command execution via Python subprocess/os module.",
    ),
    (
        "Python Socket Connection",
        r"(?:socket\.(?:socket|create_connection|connect)\s*\(|from\s+socket\s+import)",
        Severity.HIGH,
        "Code Obfuscation",
        "Network socket creation detected. Could be used for reverse shells or data exfiltration.",
    ),
    # --- v0.3.0: Ghost Exploit Defense ---
    (
        "Python Magic Attributes",
        r"(?:__builtins__|__globals__|__subclasses__|__class__|__bases__|__mro__|__dict__)",
        Severity.CRITICAL,
        "Code Obfuscation",
        "CRITICAL: Access to Python magic attributes detected. This is a reflection-based attack to bypass import restrictions and access dangerous builtins.",
    ),
    (
        "Python setattr/delattr Reflection",
        r"(?:(?:setattr|delattr)\s*\(\s*\w+\s*,\s*['\"])",
        Severity.HIGH,
        "Code Obfuscation",
        "Dynamic attribute manipulation via setattr/delattr. Can be used to inject malicious functions at runtime.",
    ),
    (
        "Suspicious open() in Agent Input",
        r"(?:open\s*\(\s*['\"]|open\s*\(\s*[a-zA-Z_]+\s*[,\)]|\['open'\]|\[\"open\"\])",
        Severity.HIGH,
        "Code Obfuscation",
        "File open() call detected in agent input. In an agent context, direct file operations are suspicious and should be reviewed.",
    ),
    (
        "Multi-Part String Assembly",
        r"(?:['\"][^'\"]{1,8}['\"]\s*\+\s*['\"][^'\"]{1,8}['\"]\s*\+\s*['\"][^'\"]{1,8}['\"])",
        Severity.HIGH,
        "Code Obfuscation",
        "Three or more short string fragments concatenated. Classic obfuscation technique to hide API keys, commands, or module names from static analysis.",
    ),
]

DATA_EXFILTRATION_PATTERNS = [
    # --- Secrets & API Keys ---
    (
        "API Key Leak",
        r"(?:(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,})",
        Severity.CRITICAL,
        "Data Exfiltration",
        "CRITICAL: Hardcoded API key or access token found. This credential should be rotated immediately.",
    ),
    (
        "Private Key Material",
        r"(?:-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----)",
        Severity.CRITICAL,
        "Data Exfiltration",
        "CRITICAL: Private key material detected in text. This key is compromised and must be revoked.",
    ),
    (
        "Password in Cleartext",
        r"(?i)(?:password|passwort|passwd|kennwort|pwd)\s*[:=]\s*['\"]?[^\s'\"]{4,}",
        Severity.HIGH,
        "Data Exfiltration",
        "Cleartext password detected. Never store or transmit passwords in plain text.",
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
        "Instruction to send data to an external email address. Verify recipient before proceeding.",
    ),
    (
        "Webhook Exfiltration",
        r"(?:(?:https?:\/\/)?(?:hooks\.slack\.com|discord(?:app)?\.com\/api\/webhooks|webhook\.site|requestbin|pipedream)\/[^\s]+)",
        Severity.HIGH,
        "Data Exfiltration",
        "Outbound webhook URL detected. Data may be exfiltrated to an external service.",
    ),
]

SOCIAL_ENGINEERING_PATTERNS = [
    (
        "Urgency Manipulation",
        r"(?i)(urgent|immediately|right\s+now|sofort|dringend|jetzt\s+sofort|without\s+delay|ohne\s+Verzögerung).{0,80}(send|execute|run|delete|pay|transfer|sende?n?|ausführen|löschen|zahlen|überweisen)",
        Severity.MEDIUM,
        "Social Engineering",
        "Urgency + action pattern detected. Pressure tactics are a common social engineering technique.",
    ),
    (
        "Authority Impersonation",
        r"(?i)(i\s+am\s+(your|the)\s+(admin|owner|creator|developer|boss|CEO)|ich\s+bin\s+(dein|der)\s+(Admin|Besitzer|Ersteller|Entwickler|Chef))",
        Severity.HIGH,
        "Social Engineering",
        "Authority impersonation detected. Verify the claimed identity through a separate channel.",
    ),
    (
        "Confidentiality Trap",
        r"(?i)(don't\s+tell|do\s+not\s+share|keep\s+this\s+(secret|private|between\s+us)|sag\s+(das\s+)?niemandem|behalte?\s+(das\s+)?für\s+dich)",
        Severity.MEDIUM,
        "Social Engineering",
        "Secrecy instruction detected. Legitimate requests don't require concealment from the system owner.",
    ),
]

ALL_PATTERNS = (
    PROMPT_INJECTION_PATTERNS
    + DANGEROUS_COMMAND_PATTERNS
    + PYTHON_OBFUSCATION_PATTERNS
    + DATA_EXFILTRATION_PATTERNS
    + SOCIAL_ENGINEERING_PATTERNS
)


# ─── Scanner Engine ──────────────────────────────────────────────────────────

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
                # Build context: show a snippet around the match
                start = max(0, match.start() - 30)
                end = min(len(line), match.end() + 30)
                context = ("..." if start > 0 else "") + line[start:end] + ("..." if end < len(line) else "")

                report.findings.append(Finding(
                    severity=severity,
                    category=category,
                    pattern_name=name,
                    matched_text=matched[:120],  # Truncate very long matches
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


# ─── Output Formatters ───────────────────────────────────────────────────────

SEVERITY_ICONS = {
    "LOW": "🟢",
    "MEDIUM": "🟡",
    "HIGH": "🟠",
    "CRITICAL": "🔴",
}

RISK_ICONS = {
    "CLEAN": "✅",
    "LOW": "🟢",
    "MEDIUM": "🟡",
    "HIGH": "🟠",
    "CRITICAL": "🔴",
}


def format_human(report: ScanReport) -> str:
    """Format the report for human-readable terminal output."""
    icon = RISK_ICONS.get(report.risk_level, "❓")
    lines = [
        "",
        "═" * 64,
        f"  🛡️  ClawGuard v0.3.0 – Security Scan Report",
        "═" * 64,
        f"  Timestamp : {report.timestamp}",
        f"  Source    : {report.source}",
        f"  Lines     : {report.total_lines}",
        f"  Findings  : {report.total_findings}",
        f"  Risk Score: {report.risk_score}/10  {icon} {report.risk_level}",
        "─" * 64,
    ]

    if not report.findings:
        lines.append("  ✅ No threats detected. Input appears safe.")
    else:
        for i, f in enumerate(report.findings, start=1):
            sev_icon = SEVERITY_ICONS.get(f.severity.value, "❓")
            lines.append(f"\n  [{i}] {sev_icon} {f.severity.value} – {f.pattern_name}")
            lines.append(f"      Category : {f.category}")
            lines.append(f"      Line     : {f.line_number}")
            lines.append(f"      Match    : \"{f.matched_text}\"")
            lines.append(f"      Context  : {f.context}")
            lines.append(f"      Action   : {f.recommendation}")

    lines.append("")
    lines.append("═" * 64)

    if report.risk_score >= 7:
        lines.append("  ⛔ RECOMMENDATION: BLOCK this input. Do NOT forward to agent.")
    elif report.risk_score >= 4:
        lines.append("  ⚠️  RECOMMENDATION: Review manually before forwarding.")
    elif report.risk_score >= 1:
        lines.append("  ℹ️  RECOMMENDATION: Low risk. Monitor but likely safe.")
    else:
        lines.append("  ✅ RECOMMENDATION: Input is clean. Safe to process.")

    lines.append("═" * 64)
    lines.append("")
    return "\n".join(lines)


def format_json(report: ScanReport) -> str:
    """Format the report as machine-readable JSON."""
    data = {
        "clawguard_version": "0.3.0",
        "timestamp": report.timestamp,
        "source": report.source,
        "total_lines": report.total_lines,
        "total_findings": report.total_findings,
        "risk_score": report.risk_score,
        "risk_level": report.risk_level,
        "findings": [
            {
                "severity": f.severity.value,
                "category": f.category,
                "pattern_name": f.pattern_name,
                "matched_text": f.matched_text,
                "line_number": f.line_number,
                "context": f.context,
                "recommendation": f.recommendation,
            }
            for f in report.findings
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


# ─── CLI Entry Point ─────────────────────────────────────────────────────────

def main():
    # Fix emoji output on Windows (cp1252 can't encode Unicode symbols)
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="🛡️  ClawGuard – The Firewall for Autonomous AI Agents",
        epilog="(c) 2026 Jörg Michno. Zero dependencies. Zero cost. Maximum security.",
    )
    parser.add_argument("file", nargs="?", help="Text file to scan")
    parser.add_argument("--stdin", action="store_true", help="Read from standard input")
    parser.add_argument("--json", action="store_true", help="Output report as JSON (for automation)")
    parser.add_argument("--version", action="version", version="ClawGuard v0.3.0")

    args = parser.parse_args()

    # Determine input source
    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="replace") as f:
                text = f.read()
            source = args.file
        except FileNotFoundError:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
            sys.exit(2)
        except PermissionError:
            print(f"Error: Permission denied: {args.file}", file=sys.stderr)
            sys.exit(2)
    elif args.stdin or not sys.stdin.isatty():
        text = sys.stdin.read()
        source = "stdin"
    else:
        parser.print_help()
        sys.exit(2)

    # Run the scan
    report = scan_text(text, source=source)

    # Output the report
    if args.json:
        print(format_json(report))
    else:
        print(format_human(report))

    # Exit code: 0 = clean, 1 = threats found
    sys.exit(0 if report.total_findings == 0 else 1)


if __name__ == "__main__":
    main()
