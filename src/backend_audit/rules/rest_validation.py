import ast
import re
from typing import List, Set, Dict, Any, Tuple
from .base import BaseRule
from ..models import Finding

HTTP_STATUS_DESCRIPTIONS = {
    200: "200 - OK",
    400: "400 - Bad Request",
    401: "401 - Unauthorized",
    403: "403 - Forbidden",
    404: "404 - Not Found",
    500: "500 - Internal Server Error"
}

class RestValidationRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="rest-validation",
            name="HTTP Status Code & REST Validation",
            description="Validates that error responses and exception paths return appropriate 4xx/5xx HTTP error codes with standard descriptions instead of 200 OK."
        )

    def run(self, tree: ast.AST, code: str, file_path: str, ignored_lines: Set[int], framework: str) -> List[Finding]:
        findings: List[Finding] = []

        class RestVisitor(ast.NodeVisitor):
            def __init__(self, rule_ref):
                self.rule = rule_ref
                self.findings = []

            def find_trigger_info(self, path_node: ast.AST) -> Tuple[str, str]:
                """Traces condition checks to determine semantic purpose (auth, validation, not found)."""
                # Check for input validation, auth checks, or not found lookups
                check_type = None
                var_name = "input"

                # If test is a UnaryOp (e.g., if not token:) or Name/Compare
                if isinstance(path_node, ast.UnaryOp) and isinstance(path_node.op, ast.Not):
                    operand = path_node.operand
                    if isinstance(operand, ast.Name):
                        name_lower = operand.id.lower()
                        var_name = operand.id
                        if any(k in name_lower for k in ["token", "auth", "jwt", "session", "role", "admin"]):
                            check_type = "auth"
                        elif any(k in name_lower for k in ["user", "item", "product", "post", "record", "data", "entity"]):
                            check_type = "notFound"
                        elif any(k in name_lower for k in ["username", "password", "email", "body", "input", "payload"]):
                            check_type = "validation"
                elif isinstance(path_node, ast.Compare):
                    # e.g., if role != 'admin' or if user is None
                    left = path_node.left
                    if isinstance(left, ast.Name):
                        name_lower = left.id.lower()
                        var_name = left.id
                        if any(k in name_lower for k in ["role", "admin", "token", "jwt", "user_id"]):
                            check_type = "auth"
                        elif any(k in name_lower for k in ["user", "item", "product", "post", "record"]):
                            # user is None check
                            check_type = "notFound"
                elif isinstance(path_node, ast.Name):
                    name_lower = path_node.id.lower()
                    var_name = path_node.id
                    if any(k in name_lower for k in ["token", "auth", "jwt", "session", "role", "admin"]):
                        check_type = "auth"
                
                return check_type, var_name

            def visit_Try(self, node: ast.Try):
                # Analyze Return statements inside except blocks
                for handler in node.handlers:
                    for stmt in handler.body:
                        # If a return statement is found inside an except block, let's examine what it returns
                        if isinstance(stmt, ast.Return):
                            val = stmt.value
                            self.check_error_pathway_response(val, handler.lineno, "except block")
                self.generic_visit(node)

            def visit_If(self, node: ast.If):
                # Check if this If condition represents validation, auth, or entity lookup
                check_type, checked_var = self.find_trigger_info(node.test)
                if check_type:
                    # Trailing returns or raises in the consequent (then) block
                    for stmt in node.body:
                        if isinstance(stmt, ast.Return):
                            self.check_conditional_response(stmt.value, node.lineno, stmt.lineno, check_type, checked_var)
                        elif isinstance(stmt, ast.Raise):
                            # In FastAPI/Django, raise HTTPException(status_code=...)
                            self.check_conditional_raise(stmt, node.lineno, stmt.lineno, check_type, checked_var)
                self.generic_visit(node)

            def check_error_pathway_response(self, val_node: ast.AST, line_no: int, context: str):
                """Flags returning implicit or explicit 200 OK in an error pathway/catch block."""
                if line_no in ignored_lines:
                    return

                status_code, has_explicit = self.extract_status_code(val_node)

                # If status is 200 or omitted (which defaults to 200)
                if status_code == 200 or status_code is None:
                    status_desc_200 = HTTP_STATUS_DESCRIPTIONS[200]
                    status_desc_500 = HTTP_STATUS_DESCRIPTIONS[500]
                    
                    snippet = self.rule.get_line_snippet(code, line_no)
                    self.findings.append(Finding(
                        rule_id="error-response-status-200",
                        severity="high",
                        message=f"HTTP status {status_desc_200} returned inside an error/catch block. Error responses must return an appropriate error status code like {status_desc_500}.",
                        file_path=file_path,
                        line=line_no,
                        column=0,
                        code_snippet=snippet,
                        suggested_fix="Flask: return jsonify(error='Internal error'), 500\nFastAPI: raise HTTPException(status_code=500, detail='Internal error')"
                    ))

            def check_conditional_response(self, val_node: ast.AST, trigger_line: int, action_line: int, check_type: str, var_name: str):
                """Flags conditional error branches returning implicit/explicit 200 instead of 4xx."""
                if action_line in ignored_lines:
                    return

                status_code, has_explicit = self.extract_status_code(val_node)

                if status_code == 200 or status_code is None:
                    # Let's map target codes
                    if check_type == "validation":
                        target_code = 400
                        rule_name = "rest-missing-status-400"
                    elif check_type == "auth":
                        target_code = 403 if "role" in var_name.lower() or "admin" in var_name.lower() else 401
                        rule_name = f"rest-missing-status-{target_code}"
                    elif check_type == "notFound":
                        target_code = 404
                        rule_name = "rest-missing-status-404"
                    else:
                        return

                    target_desc = HTTP_STATUS_DESCRIPTIONS[target_code]
                    current_desc = HTTP_STATUS_DESCRIPTIONS[200]

                    snippet = self.rule.get_line_snippet(code, action_line)
                    self.findings.append(Finding(
                        rule_id=rule_name,
                        severity="high" if check_type == "auth" else "medium",
                        message=f"{check_type.capitalize()} failure for '{var_name}' (checked at Line {trigger_line}) returns HTTP status {current_desc} instead of {target_desc}.",
                        file_path=file_path,
                        line=action_line,
                        column=0,
                        code_snippet=snippet,
                        suggested_fix=f"Return an appropriate {target_desc} HTTP response."
                    ))

            def check_conditional_raise(self, raise_node: ast.Raise, trigger_line: int, action_line: int, check_type: str, var_name: str):
                """Checks raised exceptions for REST status code compliance (e.g. HTTPException(status_code=...))."""
                if action_line in ignored_lines:
                    return

                # Check if it raises HTTPException
                exc = raise_node.exc
                if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name) and exc.func.id in ["HTTPException", "APIException"]:
                    status_code = None
                    # Find status_code arg or keyword arg
                    if exc.args:
                        # first arg could be status_code (FastAPI: HTTPException(status_code, detail))
                        if isinstance(exc.args[0], ast.Constant) and isinstance(exc.args[0].value, int):
                            status_code = exc.args[0].value
                    for kw in exc.keywords:
                        if kw.arg == "status_code" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                            status_code = kw.value.value

                    # If status_code is set, let's validate it
                    if status_code:
                        if check_type == "validation" and status_code != 400:
                            self.add_raise_mismatch_finding(action_line, trigger_line, 400, status_code, var_name, check_type)
                        elif check_type == "auth" and status_code not in [401, 403]:
                            rec = 403 if "role" in var_name.lower() or "admin" in var_name.lower() else 401
                            self.add_raise_mismatch_finding(action_line, trigger_line, rec, status_code, var_name, check_type)
                        elif check_type == "notFound" and status_code != 404:
                            self.add_raise_mismatch_finding(action_line, trigger_line, 404, status_code, var_name, check_type)

            def add_raise_mismatch_finding(self, line: int, trigger_line: int, expected: int, found: int, var_name: str, check_type: str):
                expected_desc = HTTP_STATUS_DESCRIPTIONS.get(expected, f"{expected} - Unknown")
                found_desc = HTTP_STATUS_DESCRIPTIONS.get(found, f"{found} - Unknown")
                
                snippet = self.rule.get_line_snippet(code, line)
                self.findings.append(Finding(
                    rule_id=f"rest-incorrect-status-{expected}",
                    severity="medium",
                    message=f"{check_type.capitalize()} failure for '{var_name}' (checked at Line {trigger_line}) raises HTTP status {found_desc} instead of {expected_desc}.",
                    file_path=file_path,
                    line=line,
                    column=0,
                    code_snippet=snippet,
                    suggested_fix=f"raise HTTPException(status_code={expected}, detail='...')"
                ))

            def extract_status_code(self, val_node: ast.AST) -> Tuple[Any, bool]:
                """Attempts to parse returned expression to extract status code (implicit vs explicit)."""
                if val_node is None:
                    return None, False

                # A. Tuple: return jsonify(...), 400
                if isinstance(val_node, ast.Tuple):
                    if len(val_node.elts) >= 2:
                        last_elt = val_node.elts[-1]
                        if isinstance(last_elt, ast.Constant) and isinstance(last_elt.value, int):
                            return last_elt.value, True

                # B. Call expression: JsonResponse(..., status=400) or Response(..., status_code=400)
                if isinstance(val_node, ast.Call):
                    # Check keywords
                    for kw in val_node.keywords:
                        if kw.arg in ["status", "status_code"] and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                            return kw.value.value, True

                # C. Constant integer (direct response)
                if isinstance(val_node, ast.Constant) and isinstance(val_node.value, int):
                    return val_node.value, True

                return None, False

        visitor = RestVisitor(self)
        visitor.visit(tree)
        findings.extend(visitor.findings)
        return findings
