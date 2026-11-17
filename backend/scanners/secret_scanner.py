
import re
from pathlib import Path

# Maximum file size: 1 MB
MAX_FILE_SIZE = 1_000_000

# Directories that should not be scanned
IGNORED_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".idea",
    ".pytest_cache"
}

# Example environment files are safe to keep as templates
IGNORED_FILES = {
    ".env.example",
    ".env.sample"
}

# Common binary file extensions to skip
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".pdf", ".zip", ".exe", ".dll", ".so",
    ".mp3", ".mp4", ".pyc", ".class",
    ".woff", ".woff2", ".ttf"
}

# Secret detection patterns
# Each pattern captures the suspected secret in group 1.
SECRET_PATTERNS = [

    (
        "Possible hardcoded API key",
        re.compile(
            r"""(?i)\bapi[_-]?key\b\s*[:=]\s*['"]?([A-Za-z0-9_\-]{8,})"""
        ),
        "High"
    ),

    (
        "Possible hardcoded password",
        re.compile(
            r"""(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*['"]([^'"]{4,})['"]"""
        ),
        "High"
    ),

    (
        "Possible access token",
        re.compile(
            r"""(?i)\b(?:access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['"]?([A-Za-z0-9._\-]{8,})"""
        ),
        "High"
    ),

    (
        "Possible AWS access key",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "Critical"
    ),

    (
        "Possible GitHub token",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{20,})\b"),
        "Critical"
    ),

    (
        "Possible private key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        ),
        "Critical"
    )
]


def mask_secret(value):
    """Hide most of the detected secret value."""

    if len(value) <= 4:
        return "****"

    return value[:2] + "****" + value[-2:]


def scan_file(file_path, root=None):
    """Scan a single text file for possible hardcoded secrets."""

    findings = []

    try:
        # Skip files that are too large
        if file_path.stat().st_size > MAX_FILE_SIZE:
            return findings

        # Skip known binary files
        if file_path.suffix.lower() in BINARY_EXTENSIONS:
            return findings

        raw_content = file_path.read_bytes()

        # Skip files containing null bytes (usually binary)
        if b"\x00" in raw_content:
            return findings

        content = raw_content.decode("utf-8", errors="ignore")

    except OSError:
        return findings

    # Use relative file paths in the report
    if root:
        display_path = str(file_path.relative_to(root))
    else:
        display_path = file_path.name

    for line_number, line in enumerate(content.splitlines(), start=1):

        for issue, pattern, severity in SECRET_PATTERNS:

            match = pattern.search(line)

            if not match:
                continue

            # Private key pattern identifies the header itself.
            # Never include actual private key contents in findings.
            if issue == "Possible private key":
                masked_value = "[private key header]"
            else:
                secret = match.group(1)
                masked_value = mask_secret(secret)

            findings.append({
                "scanner": "Secret Scanner",
                "file": display_path,
                "line": line_number,
                "issue": issue,
                "severity": severity,
                "evidence_masked": masked_value,
                "recommendation": (
                    "Remove the hardcoded secret and store it "
                    "in an environment variable or secure secret manager. "
                    "Rotate the credential if it may have been exposed."
                )
            })

    return findings


def scan_directory(folder_path):
    """Scan a project directory without executing its code."""

    root = Path(folder_path)
    findings = []

    if not root.exists() or not root.is_dir():
        return findings

    for file_path in root.rglob("*"):

        if not file_path.is_file():
            continue

        # Skip ignored directories
        if any(part in IGNORED_DIRS for part in file_path.relative_to(root).parts):
            continue

        # Skip safe example environment files
        if file_path.name in IGNORED_FILES:
            continue

        # Detect sensitive environment files without reading their contents
        if file_path.name.startswith(".env"):
            findings.append({
                "scanner": "Secret Scanner",
                "file": str(file_path.relative_to(root)),
                "line": 1,
                "issue": "Sensitive environment file included in project",
                "severity": "High",
                "evidence_masked": "[file name only]",
                "recommendation": (
                    "Do not commit real .env files. Add them to "
                    ".gitignore and use a safe .env.example template."
                )
            })
            continue

        findings.extend(scan_file(file_path, root))

    return findings
