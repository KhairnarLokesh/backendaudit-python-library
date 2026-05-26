import ast
import time
from pathlib import Path
from typing import List, Set, Optional, Tuple

from .models import Finding, AuditReport
from .rules import ErrorHandlingRule, SecurityRule, RestValidationRule
from .utils.comments import get_ignored_lines

# Directories and files to exclude from scanning
EXCLUDE_DIRS = {
    "__pycache__", "venv", ".venv", "env", ".env", "migrations", 
    "tests", "dist", "build", ".git", ".github", ".pytest_cache", 
    "node_modules", "static", "media"
}

EXCLUDE_FILES = {
    "setup.py", "wsgi.py", "asgi.py", "conftest.py"
}

def is_excluded(path: Path, root_path: Path) -> bool:
    """Checks if a file path matches any of the exclude criteria."""
    try:
        relative = path.relative_to(root_path)
    except ValueError:
        relative = path

    # Check parts of the relative path
    for part in relative.parts:
        if part in EXCLUDE_DIRS:
            return True
        if part.startswith(".") and part != ".":
            return True

    if path.name in EXCLUDE_FILES:
        return True

    return False

def discover_files(target_path: Path) -> List[Path]:
    """Recursively finds all Python files in target path, applying exclusions."""
    files = []
    if target_path.is_file():
        if target_path.suffix == ".py":
            return [target_path]
        return []

    # If it is a directory
    for path in target_path.rglob("*.py"):
        if not is_excluded(path, target_path):
            files.append(path)
    return files

def detect_framework(files: List[Path], root_path: Path) -> str:
    """
    Analyzes imports in files and directory structure to auto-detect
    the framework: flask, fastapi, django, sanic, or plain.
    """
    # 1. Django: check if manage.py exists in the root path
    if (root_path / "manage.py").exists() or (root_path / "settings.py").exists():
        return "django"

    flask_score = 0
    fastapi_score = 0
    django_score = 0
    sanic_score = 0

    for file_path in files:
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            # Simple fast search for imports
            if "flask" in content or "Flask" in content:
                flask_score += 1
            if "fastapi" in content or "FastAPI" in content:
                fastapi_score += 1
            if "django" in content:
                django_score += 1
            if "sanic" in content or "Sanic" in content:
                sanic_score += 1
        except Exception:
            continue

    scores = {
        "flask": flask_score,
        "fastapi": fastapi_score,
        "django": django_score,
        "sanic": sanic_score
    }

    max_score_framework = max(scores, key=scores.get)
    if scores[max_score_framework] > 0:
        return max_score_framework

    return "plain"

def run_scan(target_path: str, framework_override: Optional[str] = None) -> AuditReport:
    """
    Runs the complete static analysis scanning suite on the target path.
    """
    start_time = time.time()
    path = Path(target_path).resolve()
    
    if not path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    # Discover files
    files = discover_files(path)
    
    # Framework detection
    framework = framework_override
    if not framework:
        framework = detect_framework(files, path)

    # Instantiate rules
    rules = [
        ErrorHandlingRule(),
        SecurityRule(),
        RestValidationRule()
    ]

    findings: List[Finding] = []
    scanned_file_paths: List[str] = []

    for file_path in files:
        rel_path = str(file_path.relative_to(path) if path.is_dir() else file_path.name)
        scanned_file_paths.append(rel_path)

        try:
            code = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            # File read error finding
            findings.append(Finding(
                rule_id="file-read-error",
                severity="high",
                message=f"Failed to read file: {str(e)}",
                file_path=rel_path,
                line=0,
                column=0,
                code_snippet=""
            ))
            continue

        # Parse AST
        try:
            tree = ast.parse(code, filename=str(file_path))
        except SyntaxError as e:
            # Syntax error finding - very useful!
            findings.append(Finding(
                rule_id="python-syntax-error",
                severity="critical",
                message=f"Python syntax error prevents parsing: {e.msg}",
                file_path=rel_path,
                line=e.lineno or 1,
                column=e.offset or 0,
                code_snippet=f"Line {e.lineno}: {e.text.strip() if e.text else ''}"
            ))
            continue

        # Extract comments for backend-audit:ignore
        ignored_lines = get_ignored_lines(code)

        # Run rules
        for rule in rules:
            try:
                rule_findings = rule.run(
                    tree=tree,
                    code=code,
                    file_path=rel_path,
                    ignored_lines=ignored_lines,
                    framework=framework
                )
                
                # Double-check comment muting for robust filtering
                for finding in rule_findings:
                    if finding.line not in ignored_lines:
                        findings.append(finding)
            except Exception as e:
                # Rule execution crash finding
                findings.append(Finding(
                    rule_id="rule-execution-error",
                    severity="high",
                    message=f"Static analysis rule '{rule.rule_id}' crashed: {str(e)}",
                    file_path=rel_path,
                    line=1,
                    column=0,
                    code_snippet=""
                ))

    scan_time = time.time() - start_time
    
    return AuditReport(
        scanned_files=scanned_file_paths,
        findings=findings,
        framework_detected=framework,
        scan_time_seconds=round(scan_time, 3)
    )
