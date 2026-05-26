# backend-audit

An offline-first, local backend security, error handling, and code quality auditing tool for Python web applications (Flask, FastAPI, Django, Sanic, and plain HTTP servers).

## Features

- **Automatic Error Handling Detection**:
  - Uncaught exception hazards in route handlers
  - Missing global exception handlers
  - Route handlers with `print()` or standard logging without returning HTTP responses
- **Backend Security Scanner**:
  - Hardcoded secrets and credentials detection using regex & high-entropy Shannon Analysis
  - Route protection analysis (sensitive endpoints like `/admin` missing authentication/authorization)
  - Weak JWT practices (algorithm: 'none', missing expiration parameter, hardcoded keys)
  - Code injection vectors (SQL, NoSQL, and Command Injection via unsafe f-strings)
  - Critical security patterns like `eval()` and `exec()`
- **HTTP Status Code & REST Validation**:
  - Catches `200 OK` status returned in error pathways
  - Warns about inappropriate status codes for validation/lookup failures
  - Integrates standardized HTTP status descriptions automatically
- **Comment-Based Ignores**:
  - Supports inline annotations (`# backend-audit:ignore` or `# nosec`) to mute specific warnings

## Installation

Install in editable mode:
```bash
pip install -e .
```

## CLI Usage

```bash
# Scan a directory (auto-detects framework)
backend-audit scan .

# Scan specific directories or files
backend-audit scan app/

# Specify a framework override
backend-audit scan . --framework fastapi

# Format output as JSON and export to a file
backend-audit scan . --format json --output report.json
```
