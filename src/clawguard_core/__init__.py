"""
ClawGuard Core — Security Scanner for AI Agents.

42+ regex patterns detecting prompt injections, jailbreaks, data exfiltration,
social engineering, and encoding tricks. Zero dependencies, <10ms per scan.

Usage:
    from clawguard_core import Scanner

    scanner = Scanner()
    result = scanner.scan("Ignore all previous instructions")
    print(result.detected)     # True
    print(result.risk_score)   # 10
    print(result.severity)     # "CRITICAL"
    print(result.categories)   # ["Prompt Injection"]
"""

from importlib.metadata import version as _version

__version__ = _version("clawguard-core")

# Re-export core types from the engine module
from clawguard_core._engine import (
    scan_text,
    ScanReport,
    Finding,
    Severity,
    ALL_PATTERNS,
)


class ScanResult:
    """Friendly wrapper around ScanReport for library usage."""

    def __init__(self, report: ScanReport):
        self._report = report

    @property
    def detected(self) -> bool:
        return self._report.total_findings > 0

    @property
    def clean(self) -> bool:
        return not self.detected

    @property
    def risk_score(self) -> int:
        return self._report.risk_score

    @property
    def severity(self) -> str:
        return self._report.risk_level

    @property
    def findings_count(self) -> int:
        return self._report.total_findings

    @property
    def findings(self) -> list:
        return [
            {
                "pattern_name": f.pattern_name,
                "severity": f.severity.value,
                "category": f.category,
                "matched_text": f.matched_text,
                "line_number": f.line_number,
                "recommendation": f.recommendation,
            }
            for f in self._report.findings
        ]

    @property
    def categories(self) -> list:
        seen = []
        for f in self._report.findings:
            if f.category not in seen:
                seen.append(f.category)
        return seen

    @property
    def report(self) -> ScanReport:
        return self._report

    def __repr__(self):
        if self.detected:
            return f"ScanResult(detected=True, risk_score={self.risk_score}, severity='{self.severity}', findings={self.findings_count})"
        return "ScanResult(detected=False, clean=True)"

    def __bool__(self):
        return self.detected


class Scanner:
    """Main entry point for scanning text."""

    def scan(self, text: str, source: str = "input") -> ScanResult:
        """Scan text for security threats. Returns a ScanResult."""
        report = scan_text(text, source=source)
        return ScanResult(report)

    def scan_batch(self, texts: list, source: str = "batch") -> list:
        """Scan multiple texts. Returns a list of ScanResults."""
        return [self.scan(t, source=f"{source}[{i}]") for i, t in enumerate(texts)]
