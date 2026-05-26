import ast
import re
from typing import List, Set
from .base import BaseRule
from ..models import Finding
from ..utils.entropy import calculate_entropy

class SecurityRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="security",
            name="Backend Security Scanner",
            description="Detects hardcoded secrets, unprotected sensitive routes, weak JWT implementations, injection risks, and dangerous patterns."
        )
        # Regex for sensitive variable names
        self.secret_name_pattern = re.compile(
            r"(?i)(key|secret|password|passwd|token|credential|api_key|jwt_secret|private_key|auth_token|db_pass|aws_key)"
        )
        # Regex for sensitive paths
        self.sensitive_path_pattern = re.compile(r"/(admin|api/private|private|secure|internal|auth/config)")

    def run(self, tree: ast.AST, code: str, file_path: str, ignored_lines: Set[int], framework: str) -> List[Finding]:
        findings: List[Finding] = []

        class SecurityVisitor(ast.NodeVisitor):
            def __init__(self, rule_ref):
                self.rule = rule_ref
                self.findings = []

            def visit_Assign(self, node: ast.Assign):
                # Detect hardcoded secrets: e.g. api_key = "AIzaSy..."
                for target in node.targets:
                    # Check variable name
                    target_name = ""
                    if isinstance(target, ast.Name):
                        target_name = target.id
                    elif isinstance(target, ast.Attribute):
                        target_name = target.attr

                    if target_name and self.rule.secret_name_pattern.search(target_name):
                        # Check value
                        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                            val = node.value.value
                            entropy = calculate_entropy(val)
                            # High-entropy string literal assigned to a sensitive variable name
                            # Secrets usually have high entropy and reasonable length
                            if len(val) >= 8 and (entropy > 3.0 or len(val) > 16):
                                if node.lineno not in ignored_lines:
                                    snippet = self.rule.get_line_snippet(code, node.lineno)
                                    self.findings.append(Finding(
                                        rule_id="hardcoded-secret",
                                        severity="critical",
                                        message=f"Hardcoded secret detected in variable '{target_name}'. Entropy: {entropy:.2f}.",
                                        file_path=file_path,
                                        line=node.lineno,
                                        column=node.col_offset,
                                        code_snippet=snippet,
                                        suggested_fix=f"{target_name} = os.environ.get('{target_name.upper()}')"
                                    ))
                self.generic_visit(node)

            def visit_FunctionDef(self, node: ast.FunctionDef):
                self.check_unprotected_route(node)
                self.generic_visit(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
                self.check_unprotected_route(node)
                self.generic_visit(node)

            def check_unprotected_route(self, node):
                # Find if this function represents a sensitive route
                is_route = False
                route_path = ""
                has_auth = False

                for dec in node.decorator_list:
                    # Extract route path if possible
                    if isinstance(dec, ast.Call):
                        func = dec.func
                        dec_name = ""
                        if isinstance(func, ast.Attribute):
                            dec_name = func.attr
                        elif isinstance(func, ast.Name):
                            dec_name = func.id

                        if dec_name in ["route", "get", "post", "put", "delete", "patch"]:
                            is_route = True
                            if dec.args:
                                arg = dec.args[0]
                                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                                    route_path = arg.value
                            elif dec.keywords:
                                for kw in dec.keywords:
                                    if kw.arg in ["rule", "path"] and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                                        route_path = kw.value.value

                        # Check for Flask/Django auth decorators
                        if dec_name in ["login_required", "jwt_required", "requires_auth", "auth_required", "permission_required"]:
                            has_auth = True
                    elif isinstance(dec, ast.Name):
                        if dec.id in ["login_required", "jwt_required", "requires_auth", "auth_required"]:
                            has_auth = True

                # FastAPI auth check via Depends in arguments
                if not has_auth and (is_route or framework == "fastapi"):
                    # Check arguments for Depends
                    for arg in node.args.args:
                        # Check defaults (e.g. current_user: User = Depends(get_current_user))
                        pass
                    # Iterate through defaults
                    for df in node.args.defaults:
                        if isinstance(df, ast.Call) and isinstance(df.func, ast.Name) and df.func.id == "Depends":
                            # Check if the dependecy name contains auth, login, user, token
                            if df.args:
                                dep_func = df.args[0]
                                dep_name = ""
                                if isinstance(dep_func, ast.Name):
                                    dep_name = dep_func.id
                                elif isinstance(dep_func, ast.Attribute):
                                    dep_name = dep_func.attr
                                if dep_name and any(k in dep_name.lower() for k in ["auth", "login", "user", "token", "verify"]):
                                    has_auth = True
                                    break

                # DRF Class/Function permission check
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name) and dec.func.id == "permission_classes":
                        has_auth = True

                if is_route and route_path and self.rule.sensitive_path_pattern.search(route_path):
                    if not has_auth and node.lineno not in ignored_lines:
                        snippet = self.rule.get_line_snippet(code, node.lineno)
                        self.findings.append(Finding(
                            rule_id="unprotected-route",
                            severity="high",
                            message=f"Sensitive route '{route_path}' lacks authentication or authorization decorators.",
                            file_path=file_path,
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=snippet,
                            suggested_fix="Apply auth middleware, login_required decorator, or FastAPI Depends() dependency."
                        ))

            def visit_Call(self, node: ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                # 1. Dangerous code executions (eval, exec)
                if func_name in ["eval", "exec"]:
                    if node.lineno not in ignored_lines:
                        snippet = self.rule.get_line_snippet(code, node.lineno)
                        self.findings.append(Finding(
                            rule_id="dangerous-pattern",
                            severity="critical",
                            message=f"Use of dangerous built-in function '{func_name}'. This enables remote code execution (RCE) vulnerabilities.",
                            file_path=file_path,
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=snippet,
                            suggested_fix="Avoid using eval() or exec() on untrusted user inputs. Parse inputs using json.loads() or safe AST evaluation."
                        ))

                # 2. Command Injection detection
                if func_name in ["system", "popen", "run", "call", "check_output"]:
                    # Check if subprocess or os is used
                    is_cmd = False
                    if isinstance(node.func, ast.Name) and func_name in ["system", "popen"]:
                        is_cmd = True
                    elif isinstance(node.func, ast.Attribute):
                        if isinstance(node.func.value, ast.Name) and node.func.value.id in ["subprocess", "os"]:
                            is_cmd = True

                    if is_cmd:
                        # Check if shell=True is passed as keyword argument
                        shell_true = False
                        for kw in node.keywords:
                            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                shell_true = True
                        
                        # Command injection risk is high if shell=True and f-strings / string concatenation are used
                        if shell_true or func_name in ["system", "popen"]:
                            # Look at the first argument
                            if node.args:
                                first_arg = node.args[0]
                                if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
                                    if node.lineno not in ignored_lines:
                                        snippet = self.rule.get_line_snippet(code, node.lineno)
                                        self.findings.append(Finding(
                                            rule_id="command-injection",
                                            severity="critical",
                                            message=f"Possible OS command injection. Calling '{func_name}' with dynamically built command string using shell=True.",
                                            file_path=file_path,
                                            line=node.lineno,
                                            column=node.col_offset,
                                            code_snippet=snippet,
                                            suggested_fix="Pass commands as lists and set shell=False. E.g., subprocess.run(['ls', '-l'])"
                                        ))

                # 3. SQL Injection detection
                if func_name in ["execute", "raw"]:
                    # Check database / ORM / cursor execution calls
                    if node.args:
                        sql_arg = node.args[0]
                        if isinstance(sql_arg, (ast.JoinedStr, ast.BinOp)):
                            # Check if the string pattern resembles SQL keywords
                            is_sql = False
                            sql_text = ""
                            if isinstance(sql_arg, ast.JoinedStr):
                                for val in sql_arg.values:
                                    if isinstance(val, ast.Constant) and isinstance(val.value, str):
                                        sql_text += val.value
                            elif isinstance(sql_arg, ast.BinOp) and isinstance(sql_arg.op, ast.Mod):
                                # string formatting % val
                                if isinstance(sql_arg.left, ast.Constant) and isinstance(sql_arg.left.value, str):
                                    sql_text = sql_arg.left.value
                            
                            # Simple SQL keywords regex
                            if re.search(r"(?i)(select|insert|update|delete|from|where|join)", sql_text) or not sql_text:
                                is_sql = True

                            if is_sql and node.lineno not in ignored_lines:
                                snippet = self.rule.get_line_snippet(code, node.lineno)
                                self.findings.append(Finding(
                                    rule_id="sql-injection",
                                    severity="critical",
                                    message="Possible SQL injection vulnerability. Unescaped input query parameter built dynamically using f-string or % formatting.",
                                    file_path=file_path,
                                    line=node.lineno,
                                    column=node.col_offset,
                                    code_snippet=snippet,
                                    suggested_fix="Use parameterized queries instead. E.g., cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
                                ))

                # 4. Weak JWT Implementations
                if func_name in ["encode", "decode"]:
                    # Check if imported from jwt or jose
                    is_jwt = False
                    if isinstance(node.func, ast.Name):
                        is_jwt = True
                    elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in ["jwt", "jose"]:
                        is_jwt = True

                    if is_jwt:
                        # Check A: algorithm='none'
                        algo_none = False
                        algo_val = ""
                        for kw in node.keywords:
                            if kw.arg in ["algorithm", "algorithms"]:
                                if isinstance(kw.value, ast.Constant):
                                    algo_val = str(kw.value.value)
                                elif isinstance(kw.value, ast.List):
                                    # algorithms=['none']
                                    if kw.value.elts and isinstance(kw.value.elts[0], ast.Constant):
                                        algo_val = str(kw.value.elts[0].value)

                        if algo_val.lower() == "none":
                            if node.lineno not in ignored_lines:
                                snippet = self.rule.get_line_snippet(code, node.lineno)
                                self.findings.append(Finding(
                                    rule_id="weak-jwt-algorithm",
                                    severity="critical",
                                    message="Weak JWT configuration. 'none' algorithm is permitted or explicitly selected, allowing signature bypass.",
                                    file_path=file_path,
                                    line=node.lineno,
                                    column=node.col_offset,
                                    code_snippet=snippet,
                                    suggested_fix="Configure JWT to only accept strong algorithms like 'HS256' or 'RS256'."
                                ))

                        # Check B: Hardcoded secret key in JWT call
                        # In jwt.encode(payload, key) or jwt.decode(token, key)
                        if node.args and len(node.args) >= 2:
                            key_arg = node.args[1]
                            if isinstance(key_arg, ast.Constant) and isinstance(key_arg.value, str):
                                # hardcoded string
                                if node.lineno not in ignored_lines:
                                    snippet = self.rule.get_line_snippet(code, node.lineno)
                                    self.findings.append(Finding(
                                        rule_id="weak-jwt-secret",
                                        severity="critical",
                                        message="Hardcoded secret key used directly in JWT signature call.",
                                        file_path=file_path,
                                        line=node.lineno,
                                        column=node.col_offset,
                                        code_snippet=snippet,
                                        suggested_fix="Load the JWT signature key from environment variables or safe secret vaults."
                                    ))

                        # Check C: Missing expiration parameter ('exp') in payload
                        # Usually inside jwt.encode(payload, key)
                        if func_name == "encode" and node.args:
                            payload_arg = node.args[0]
                            if isinstance(payload_arg, ast.Dict):
                                has_exp = False
                                for k in payload_arg.keys:
                                    if isinstance(k, ast.Constant) and k.value == "exp":
                                        has_exp = True
                                
                                if not has_exp and node.lineno not in ignored_lines:
                                    snippet = self.rule.get_line_snippet(code, node.lineno)
                                    self.findings.append(Finding(
                                        rule_id="weak-jwt-missing-exp",
                                        severity="high",
                                        message="JWT token payload is missing the 'exp' (expiration time) claim, enabling replay attacks.",
                                        file_path=file_path,
                                        line=node.lineno,
                                        column=node.col_offset,
                                        code_snippet=snippet,
                                        suggested_fix="Include 'exp': datetime.utcnow() + timedelta(hours=1) in the token payload."
                                    ))

                self.generic_visit(node)

        visitor = SecurityVisitor(self)
        visitor.visit(tree)
        findings.extend(visitor.findings)
        return findings
