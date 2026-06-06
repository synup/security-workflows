"""Check registry. Each module defines NAME and check(path, rel, text, lines)."""
from . import secrets, sensitive_files, malware, dangerous_code

# Order = report order. Add new check modules here to register them.
ALL = [secrets, sensitive_files, malware, dangerous_code]
REGISTRY = {m.NAME: m for m in ALL}
