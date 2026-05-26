from dataclasses import dataclass, asdict, field
from typing import Optional, List, Dict, Any

@dataclass
class Finding:
    rule_id: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    message: str
    file_path: str
    line: int
    column: int
    code_snippet: str
    suggested_fix: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class AuditReport:
    scanned_files: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    framework_detected: str = "unknown"
    scan_time_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanned_files": self.scanned_files,
            "findings": [f.to_dict() for f in self.findings],
            "framework_detected": self.framework_detected,
            "scan_time_seconds": self.scan_time_seconds
        }
