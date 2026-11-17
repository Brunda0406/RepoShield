
import re
from pathlib import Path

SECRET_PATTERNS = [
    (
        "Possible hardcoded API key",
        re.compile(
            r"""(?i)\b(api[_-]?key)\b\s*[:=]\s*['"]?([A-Za-z0-9_\-]{8,})"""
        ),
        "High",
    ),
    (
        "Possible hardcoded password",
        re.compile(
            r"""(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['"]([^'"]{4,})['"]"""
        ),
        "High",
    ),
    (
        "Possible access token",
        re.compile(
            r"""(?i)\b(access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['"]?([A-Za-z0-9._\-]{8,})"""
        ),
        "High",
    ),
    (
        "Possible AWS access key",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "Critical",
    ),
]

IGNORED_DIRS = {
    ".git", "node_modules", "venv",
    ".venv", "__pycache__", ".idea"
}

IGNORED_FILES = {
    ".env.example", ".env.sample"
}


def mask_secret(value):
    """Hide most of a detected secret."""
    if len(value) <= 4:
        return "****"

    return value[:2] + "****" + value[-2:]


def scan_file(file_path):
    """Scan one file for possible hardcoded secrets."""
    findings = []

    try:
        if file_path.stat().st_size > 1_000_000:
            return findings

        content = file_path.read_text(
            encoding="utf-8",
            errors="ignore"
        )

    except OSError:
        return findings

    for line_number, line in enumerate(content.splitlines(), start=1):

        for issue, pattern, severity in SECRET_PATTERNS:
            match = pattern.search(line)

            if not match:
                continue

            secret = match.group(1) if issue == "Possible AWS access key" else match.group(2)

            findings.append({
                "scanner": "Secret Scanner",
                "file": str(file_path),
                "line": line_number,
                "issue": issue,
                "severity": severity,
                "evidence_masked": mask_secret(secret),
                "recommendation": (
                    "Remove the hardcoded secret and store it "
                    "in an environment variable. Rotate it if exposed."
                )
            })

    return findings


def scan_directory(folder_path):
    """Scan a project folder without executing its code."""
    root = Path(folder_path)
    findings = []

    for file_path in root.rglob("*"):

        if not file_path.is_file():
            continue

        if any(part in IGNORED_DIRS for part in file_path.parts):
            continue

        if file_path.name in IGNORED_FILES:
            continue

        if file_path.name == ".env":
            findings.append({
                "scanner": "Secret Scanner",
                "file": str(file_path),
                "line": 1,
                "issue": "Sensitive .env file included in project",
                "severity": "High",
                "evidence_masked": "[file name only]",
                "recommendation": (
                    "Add .env to .gitignore and never commit "
                    "real environment files."
                )
            })
            continue

        findings.extend(scan_file(file_path))

    return findings
