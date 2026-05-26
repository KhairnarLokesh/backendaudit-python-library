import ast
from typing import List, Set
from ..models import Finding

class BaseRule:
    def __init__(self, rule_id: str, name: str, description: str):
        self.rule_id = rule_id
        self.name = name
        self.description = description

    def run(self, tree: ast.AST, code: str, file_path: str, ignored_lines: Set[int], framework: str) -> List[Finding]:
        """
        Runs the rule on the parsed AST.
        :param tree: The Python AST module.
        :param code: Raw source code string.
        :param file_path: Path to the scanned file.
        :param ignored_lines: Set of line numbers ignored via # backend-audit:ignore or # nosec comments.
        :param framework: Framework name ('flask', 'fastapi', 'django', 'sanic', 'plain', or 'unknown').
        :return: List of Findings.
        """
        raise NotImplementedError("Subclasses must implement run()")

    def get_line_snippet(self, code: str, line_no: int) -> str:
        """Helper to get a code snippet around the target line number."""
        lines = code.splitlines()
        if not lines:
            return ""
        # 1-based indexing for line numbers
        start = max(0, line_no - 2)
        end = min(len(lines), line_no + 1)
        snippet_lines = []
        for i in range(start, end):
            prefix = "> " if i == line_no - 1 else "  "
            snippet_lines.append(f"{i + 1}: {prefix}{lines[i]}")
        return "\n".join(snippet_lines)
