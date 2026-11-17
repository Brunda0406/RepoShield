
import re
from pathlib import Path


def scan_dockerfile(file_path):
    findings = []

    path = Path(file_path)

    if not path.is_file():
        return findings

    lines = path.read_text(
        encoding="utf-8",
        errors="ignore"
    ).splitlines()

    has_user = False
    has_healthcheck = False

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Ignore comments and empty lines
        if not stripped or stripped.startswith("#"):
            continue

        upper_line = stripped.upper()

        # Check for floating latest image tags
        if upper_line.startswith("FROM "):
            image = stripped.split()[-1]

            if image.endswith(":latest"):
                findings.append({
                    "file": str(path),
                    "line": line_number,
                    "issue": "Docker image uses the latest tag",
                    "severity": "Medium",
                    "recommendation": "Pin the image to a specific version or digest."
                })

        # Check for root user
        if upper_line.startswith("USER "):
            has_user = True

            if stripped.split(maxsplit=1)[1].lower() == "root":
                findings.append({
                    "file": str(path),
                    "line": line_number,
                    "issue": "Container explicitly runs as root",
                    "severity": "High",
                    "recommendation": "Use a dedicated non-root user where possible."
                })

        # Check for HEALTHCHECK
        if upper_line.startswith("HEALTHCHECK "):
            has_healthcheck = True

        # Check for possible hardcoded secrets
        if upper_line.startswith(("ENV ", "ARG ")):
            if re.search(
                r"(PASSWORD|SECRET|API_KEY|TOKEN)\s*=\s*\S+",
                stripped,
                re.IGNORECASE
            ):
                findings.append({
                    "file": str(path),
                    "line": line_number,
                    "issue": "Possible hardcoded secret in ENV or ARG",
                    "severity": "High",
                    "recommendation": "Use a secure secret-management method."
                })

    if not has_user:
        findings.append({
            "file": str(path),
            "line": 0,
            "issue": "No explicit USER instruction detected",
            "severity": "Medium",
            "recommendation": "Review whether the container should run as a non-root user."
        })

    if not has_healthcheck:
        findings.append({
            "file": str(path),
            "line": 0,
            "issue": "No HEALTHCHECK instruction detected",
            "severity": "Low",
            "recommendation": "Consider adding a suitable health check."
        })

    return findings
