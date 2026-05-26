import re
from typing import Set
import libcst as cst
from libcst.metadata import PositionProvider

class CommentCollector(cst.CSTVisitor):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self):
        super().__init__()
        self.ignored_lines: Set[int] = set()

    def visit_Comment(self, node: cst.Comment) -> None:
        pos = self.get_metadata(PositionProvider, node)
        line = pos.start.line
        text = node.value.lower()
        if "backend-audit:ignore" in text or "nosec" in text:
            self.ignored_lines.add(line)

def get_ignored_lines(code: str) -> Set[int]:
    """
    Parses the source code using libcst to extract line numbers containing
    '# backend-audit:ignore' or '# nosec' comments.
    Falls back gracefully to a regex line-by-line check if CST parsing fails.
    """
    try:
        wrapper = cst.MetadataWrapper(cst.parse_module(code))
        collector = CommentCollector()
        wrapper.visit(collector)
        return collector.ignored_lines
    except Exception:
        # Resilient fallback: simple regex matching for ignore patterns
        ignored = set()
        for idx, line in enumerate(code.splitlines(), start=1):
            cleaned = line.strip().lower()
            if "#" in cleaned:
                comment_part = cleaned.split("#", 1)[1]
                if "backend-audit:ignore" in comment_part or "nosec" in comment_part:
                    ignored.add(idx)
        return ignored
