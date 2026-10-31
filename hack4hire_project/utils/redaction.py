"""Secrets on a command line must not end up in stored telemetry.

Live collection watches every process on this machine, so it sees API keys and passwords passed as
arguments. They are masked before storage. Uploaded files are never changed, so this is only for live data.
"""
import re

MASK = '[REDACTED]'

_PATTERNS = (
    re.compile(r'\b(?:gsk|ghp|gho|ghs|xox[abprs]|glpat)[_-][A-Za-z0-9_-]{16,}'),
    re.compile(r'\bsk-(?:ant-)?[A-Za-z0-9_-]{16,}'),
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    re.compile(r'\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
)
# Keeps the name, so that the log still shows what was passed
_NAMED = (
    re.compile(r'(\bBearer\s+)\S+', re.IGNORECASE),
    re.compile(r'(\bBasic\s+)[A-Za-z0-9+/=]{8,}', re.IGNORECASE),
    re.compile(r'((?:--?|\b)(?:password|passwd|pwd|token|api[_-]?key|secret|client[_-]secret|access[_-]key)(?:\s*[=:]\s*|\s+))(?!/)\S+', re.IGNORECASE),
    re.compile(r'(://[^/\s:@]+:)[^/\s@]+(?=@)'),
)


def redact_secrets(text):
    if not text:
        return text
    text = str(text)
    for pattern in _PATTERNS:
        text = pattern.sub(MASK, text)
    for pattern in _NAMED:
        text = pattern.sub(lambda match: match.group(1) + MASK, text)
    return text
