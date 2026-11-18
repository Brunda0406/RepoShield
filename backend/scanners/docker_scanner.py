
import re
from pathlib import Path


def scan_dockerfile(file_path):
    """Scan a Dockerfile for common security issues."""

    path = Path(file_path)

    if not path.is_file():
        return {
            "scanner": "docker_scanner",
            "status": "error",
            "total_findings": 0,
            "findings": [],
            "message": "Dockerfile not found."
        }

    try:
        content = path.read_text(
            encoding="utf-8",
            errors="ignore"
        )
    except OSError as error:
        return {
            "scanner": "docker_scanner",
            "status": "error",
            "total_findings": 0,
            "findings": [],
            "message": str(error)
        }

    findings = []
    lines = content.splitlines()
    has_user = False
    has_healthcheck = False

    for line_number, line in enumerate(lines, start=1):
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        upper = line.upper()

        # Check image tags
        if upper.startswith("FROM "):
            image = line.split()[1]

            if image.lower() == "scratch":
                continue

            if ":" not in image or image.endswith(":latest"):
                findings.append({
                    "type": "Unpinned Docker Image",
                    "severity": "MEDIUM",
                    "line": line_number,
                    "description": (
                        "Use a specific image version instead of "
                        "latest or an untagged image."
                    )
                })

        # Check USER instruction
        if upper.startswith("USER "):
            has_user = True
            user = line.split(maxsplit=1)[1].lower()

            if user in ("root", "0"):
                findings.append({
                    "type": "Root User",
                    "severity": "HIGH",
                    "line": line_number,
                    "description": "Container explicitly runs as root."
                })

        # Check HEALTHCHECK instruction
        if upper.startswith("HEALTHCHECK "):
            has_healthcheck = True

        # Check possible hardcoded secrets
        if upper.startswith(("ENV ", "ARG ")):
            if re.search(
                r"(PASSWORD|SECRET|API_KEY|TOKEN)\s*=\s*\S+",
                line,
                re.IGNORECASE
            ):
                findings.append({
                    "type": "Possible Hardcoded Secret",
                    "severity": "HIGH",
                    "line": line_number,
                    "description": (
                        "Possible hardcoded secret in ENV or ARG. "
                        "Use secure secret management."
                    )
                })

        # Check ADD instruction
        if upper.startswith("ADD "):
            findings.append({
                "type": "Use of ADD",
                "severity": "LOW",
                "line": line_number,
                "description": (
                    "Prefer COPY unless ADD archive extraction "
                    "or URL functionality is required."
                )
            })

        # Check sensitive exposed ports
        if upper.startswith("EXPOSE "):
            ports = re.findall(r"\b\d+\b", line)

            sensitive_ports = {
                "22", "2375", "2376", "3306",
                "5432", "6379", "27017"
            }

            for port in ports:
                if port in sensitive_ports:
                    findings.append({
                        "type": "Sensitive Port Exposed",
                        "severity": "MEDIUM",
                        "line": line_number,
                        "description": (
                            f"Potentially sensitive port {port} is exposed."
                        )
                    })

        # Check privileged execution
        if "--privileged" in line.lower():
            findings.append({
                "type": "Privileged Container",
                "severity": "HIGH",
                "line": line_number,
                "description": "Privileged container execution detected."
            })

        # Check remote scripts piped into a shell
        if "curl" in line.lower() and re.search(
            r"\|\s*(sh|bash)\b",
            line,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Unsafe Remote Script Execution",
                "severity": "HIGH",
                "line": line_number,
                "description": (
                    "Remote script is piped directly into a shell."
                )
            })

    if not has_user:
        findings.append({
            "type": "Missing USER Instruction",
            "severity": "MEDIUM",
            "line": None,
            "description": (
                "No USER instruction found. Review whether the "
                "container should run as a non-root user."
            )
        })

    # HEALTHCHECK is tracked but is not counted as a security finding.
    healthcheck_recommendation = (
        None if has_healthcheck
        else "Consider adding a suitable HEALTHCHECK instruction."
    )

    return {
        "scanner": "docker_scanner",
        "status": "completed",
        "total_findings": len(findings),
        "findings": findings,
        "healthcheck_recommendation": healthcheck_recommendation
    }
