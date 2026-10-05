import ast
import sys

# This is a simplified representation of a "Vericore" validation layer.
# In a real-world scenario, this would involve much more sophisticated static analysis,
# dynamic testing, and potentially AI-driven security checks.

def validate_code(code_string):
    """Validates the provided Python code string for basic safety and correctness."""
    try:
        # Attempt to parse the code into an Abstract Syntax Tree (AST).
        # This catches syntax errors.
        tree = ast.parse(code_string)

        # Basic check: disallow potentially dangerous built-in functions.
        # In a real Vericore, this would be a comprehensive list and more nuanced.
        dangerous_builtins = {"eval", "exec", "open"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in dangerous_builtins:
                    raise ValueError(f"Potentially dangerous function call: {node.func.id}")
                # Also check for attribute access on builtins, e.g., __import__
                if isinstance(node.func, ast.Attribute) and node.func.attr in dangerous_builtins:
                    raise ValueError(f"Potentially dangerous attribute access: {node.func.attr}")

        # Further checks could include:
        # - Type checking (if using type hints)
        # - Linting rules (PEP 8, etc.)
        # - Security vulnerability scanning (e.g., common injection patterns)
        # - Performance analysis

        return True, "Code is syntactically correct and passes basic safety checks."

    except SyntaxError as e:
        return False, f"Syntax error: {e}"
    except ValueError as e:
        return False, f"Validation error: {e}"
    except Exception as e:
        return False, f"An unexpected error occurred during validation: {e}"

if __name__ == "__main__":
    # Example AI-generated code snippets (simulated)
    safe_code = """
def greet(name):
    return f"Hello, {name}!"

print(greet("World"))
"""

    unsafe_code_eval = """
print(eval("1 + 1"))
"""

    unsafe_code_open = """
with open("secret.txt", "r") as f:
    content = f.read()
print(content)
"""

    syntax_error_code = """
def broken_func(
    print("This is broken")
"""

    print("--- Validating Safe Code ---")
    is_valid, message = validate_code(safe_code)
    print(f"Result: {is_valid}, Message: {message}\n")

    print("--- Validating Unsafe Code (eval) ---")
    is_valid, message = validate_code(unsafe_code_eval)
    print(f"Result: {is_valid}, Message: {message}\n")

    print("--- Validating Unsafe Code (open) ---")
    is_valid, message = validate_code(unsafe_code_open)
    print(f"Result: {is_valid}, Message: {message}\n")

    print("--- Validating Code with Syntax Error ---")
    is_valid, message = validate_code(syntax_error_code)
    print(f"Result: {is_valid}, Message: {message}\n")
