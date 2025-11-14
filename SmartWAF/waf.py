import re

# Regex patterns and simple identification
PATTERNS = [
    (re.compile(r"(?:')|(?:--)|(/\*(?:.|[\r\n])*?\*/)", re.IGNORECASE), "SQL Injection"),
    (re.compile(r"<script.*?>.*?</script>", re.IGNORECASE), "XSS"),
    (re.compile(r"(\.\./)+", re.IGNORECASE), "Directory Traversal"),
    (re.compile(r"(;|\|&|\`|\$\(.*\))", re.IGNORECASE), "Command Injection / Shell"),
    (re.compile(r"(<img|onerror|onload)\s*=", re.IGNORECASE), "XSS"),
]

def detect_attack(text: str) -> bool:
    if not text:
        return False
    for pattern, _ in PATTERNS:
        if pattern.search(text):
            return True
    return False

def classify_attack(text: str) -> str:
    for pattern, label in PATTERNS:
        if pattern.search(text):
            return label
    return "Unknown"