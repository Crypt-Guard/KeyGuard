"""KeyGuard - Secure Password Manager."""

__version__ = "4.0.0"
__all__ = ["__version__"]


def check_dependencies():
    """Halt with a clear message if a critical dependency is missing."""
    import importlib.util
    import sys

    required = ["psutil", "ttkbootstrap", "cryptography", "argon2", "platformdirs"]
    missing = [pkg for pkg in required if importlib.util.find_spec(pkg) is None]
    if missing:
        print("ERROR: Missing dependencies ->", ", ".join(missing))
        print("Install with:  pip install " + " ".join(missing))
        sys.exit(1)
