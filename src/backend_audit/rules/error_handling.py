import ast
from typing import List, Set
from .base import BaseRule
from ..models import Finding

class ErrorHandlingRule(BaseRule):
    def __init__(self):
        super().__init__(
            rule_id="error-handling",
            name="Automatic Error Handling Detector",
            description="Scans route handlers for try/except blocks, checks for print-only exception swallowing, and detects global/404 exception handler presence."
        )

    def run(self, tree: ast.AST, code: str, file_path: str, ignored_lines: Set[int], framework: str) -> List[Finding]:
        findings: List[Finding] = []
        has_global_handler = False
        has_404_handler = False

        # Framework detection imports or decorators
        is_flask = framework == "flask"
        is_fastapi = framework == "fastapi"
        is_django = framework == "django"

        # Check imports to refine framework identification
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "flask":
                        is_flask = True
                    elif alias.name == "fastapi":
                        is_fastapi = True
                    elif alias.name == "django":
                        is_django = True
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    if "flask" in node.module:
                        is_flask = True
                    elif "fastapi" in node.module:
                        is_fastapi = True
                    elif "django" in node.module:
                        is_django = True

        class ErrorHandlingVisitor(ast.NodeVisitor):
            def __init__(self, rule_ref):
                self.rule = rule_ref
                self.findings = []
                self.has_global_handler = False
                self.has_404_handler = False

            def visit_FunctionDef(self, node: ast.FunctionDef):
                self.check_route_handler(node)
                self.generic_visit(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
                self.check_route_handler(node)
                self.generic_visit(node)

            def check_route_handler(self, node):
                # Is it a route handler?
                is_route = False
                route_decorator_line = node.lineno

                for dec in node.decorator_list:
                    # Detect route decorators: @app.route, @app.get, @router.post, etc.
                    dec_name = ""
                    if isinstance(dec, ast.Call):
                        func = dec.func
                        if isinstance(func, ast.Attribute):
                            dec_name = func.attr
                            # check if parent object is app, router, bp etc.
                            if isinstance(func.value, ast.Name):
                                if func.value.id in ["app", "router", "bp", "blueprint", "api_router"]:
                                    is_route = True
                        elif isinstance(func, ast.Name):
                            dec_name = func.id
                    elif isinstance(dec, ast.Attribute):
                        dec_name = dec.attr
                    elif isinstance(dec, ast.Name):
                        dec_name = dec.id

                    # Check for popular routing decorator names
                    if dec_name in ["route", "get", "post", "put", "delete", "patch", "api_view", "view"]:
                        is_route = True
                    
                    # Detect Flask errorhandler: @app.errorhandler or @bp.app_errorhandler
                    if dec_name in ["errorhandler", "app_errorhandler"]:
                        self.has_global_handler = True
                        is_route = False  # Exception handlers don't need outer try-except themselves
                        # Check if 404 is registered
                        if isinstance(dec, ast.Call) and dec.args:
                            arg = dec.args[0]
                            if isinstance(arg, ast.Constant) and arg.value == 404:
                                self.has_404_handler = True
                            elif isinstance(arg, ast.Name) and "NotFound" in arg.id:
                                self.has_404_handler = True

                    # Detect FastAPI exception_handler: @app.exception_handler
                    if dec_name == "exception_handler":
                        self.has_global_handler = True
                        is_route = False
                        if isinstance(dec, ast.Call) and dec.args:
                            arg = dec.args[0]
                            if isinstance(arg, ast.Name) and "StarletteHTTPException" in arg.id:
                                self.has_404_handler = True

                # Django views usually don't have route decorators, but are functions in views.py
                # containing a 'request' parameter
                if not is_route and is_django:
                    if node.name.startswith("view_") or "view" in file_path.lower():
                        # Check if the first argument is named request
                        if node.args.args and node.args.args[0].arg in ["request", "req"]:
                            is_route = True

                if is_route:
                    # Let's inspect the body of the route handler
                    # Does it have any try-except block at the top level or inside the main execution flow?
                    has_try = False
                    for stmt in node.body:
                        if isinstance(stmt, ast.Try):
                            has_try = True
                            break
                        # Also look inside with blocks or if statements for simple try/except wraps
                        if isinstance(stmt, ast.With):
                            for sub_stmt in stmt.body:
                                if isinstance(sub_stmt, ast.Try):
                                    has_try = True
                                    break
                    
                    if not has_try and node.lineno not in ignored_lines:
                        snippet = self.rule.get_line_snippet(code, node.lineno)
                        self.findings.append(Finding(
                            rule_id="missing-try-except",
                            severity="medium",
                            message=f"Route handler '{node.name}' lacks a try/except block. Uncaught exceptions will cause 500 crashes or leak internal details.",
                            file_path=file_path,
                            line=node.lineno,
                            column=node.col_offset,
                            code_snippet=snippet,
                            suggested_fix=f"def {node.name}(...):\n    try:\n        # route logic\n    except Exception as e:\n        # return appropriate HTTP 500 response"
                        ))

            def visit_Try(self, node: ast.Try):
                # Analyze except blocks inside try-except
                for handler in node.handlers:
                    # Check if the except block only prints or logs without returning or raising
                    has_return_or_raise = False
                    has_logging_or_print = False
                    
                    # We will inspect statements inside the except block
                    for stmt in handler.body:
                        if isinstance(stmt, (ast.Raise, ast.Return)):
                            has_return_or_raise = True
                        
                        # Look for print() or logger calls
                        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                            call = stmt.value
                            func_name = ""
                            if isinstance(call.func, ast.Name):
                                func_name = call.func.id
                            elif isinstance(call.func, ast.Attribute):
                                func_name = call.func.attr
                                
                            if func_name in ["print", "error", "exception", "warning", "info", "log"]:
                                has_logging_or_print = True
                        
                        # Support nested raise/return
                        for sub in ast.walk(stmt):
                            if isinstance(sub, (ast.Raise, ast.Return)):
                                has_return_or_raise = True

                    if has_logging_or_print and not has_return_or_raise and handler.lineno not in ignored_lines:
                        snippet = self.rule.get_line_snippet(code, handler.lineno)
                        self.findings.append(Finding(
                            rule_id="error-only-logged",
                            severity="high",
                            message="Exception is caught and logged/printed, but not re-raised or returned as a proper HTTP error response. This causes the API to swallow errors and implicitly return status 200 OK or null.",
                            file_path=file_path,
                            line=handler.lineno,
                            column=handler.col_offset,
                            code_snippet=snippet,
                            suggested_fix="raise HTTPException(status_code=500, detail='Internal Server Error') or return proper HTTP response"
                        ))
                
                self.generic_visit(node)

            def visit_Assign(self, node: ast.Assign):
                # Detect Django custom error handlers in urls.py
                # e.g., handler404 = 'myapp.views.custom_404'
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if target.id == "handler500":
                            self.has_global_handler = True
                        elif target.id == "handler404":
                            self.has_404_handler = True
                self.generic_visit(node)

        visitor = ErrorHandlingVisitor(self)
        visitor.visit(tree)
        findings.extend(visitor.findings)

        # Global findings checked at the file level
        # If we detect that this is a main app configuration file (e.g. app.py, main.py, urls.py)
        # and it lacks exception handlers
        file_lower = file_path.lower()
        if ("app.py" in file_lower or "main.py" in file_lower or "urls.py" in file_lower) and (is_flask or is_fastapi or is_django):
            if not visitor.has_global_handler and 1 not in ignored_lines:
                findings.append(Finding(
                    rule_id="missing-global-error-handler",
                    severity="high",
                    message="Missing a global exception handler. Uncaught exceptions will leak sensitive raw traceback details or cause unhandled service crashes.",
                    file_path=file_path,
                    line=1,
                    column=0,
                    code_snippet=self.get_line_snippet(code, 1),
                    suggested_fix="@app.errorhandler(Exception)\ndef handle_exception(e):\n    return jsonify(error='Internal Server Error'), 500" if is_flask else "Use FastAPI @app.exception_handler(Exception) to catch and format errors cleanly."
                ))
            if not visitor.has_404_handler and 1 not in ignored_lines:
                findings.append(Finding(
                    rule_id="missing-404-handler",
                    severity="medium",
                    message="Missing a custom 404 (Not Found) handler. Standard default handlers leak internal library structures or route structures.",
                    file_path=file_path,
                    line=1,
                    column=0,
                    code_snippet=self.get_line_snippet(code, 1),
                    suggested_fix="@app.errorhandler(404)\ndef not_found(e):\n    return jsonify(error='Resource Not Found'), 404" if is_flask else "Implement custom exception handler or APIRouter handler for 404 (Not Found)."
                ))

        return findings
