
import re
from pathlib import Path


def scan_workflow(file_path):
    """Scan a GitHub Actions workflow for security issues."""

    path = Path(file_path)

    if not path.is_file():
        return {
            "scanner": "workflow_scanner",
            "status": "error",
            "findings": [],
            "message": "Workflow file not found."
        }

    try:
        lines = path.read_text(
            encoding="utf-8",
            errors="ignore"
        ).splitlines()
    except OSError as error:
        return {
            "scanner": "workflow_scanner",
            "status": "error",
            "findings": [],
            "message": str(error)
        }

    findings = []

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        # Detect pull_request_target
        if re.search(r"\bpull_request_target\s*:", stripped):
            findings.append({
                "type": "Dangerous Pull Request Trigger",
                "severity": "HIGH",
                "line": line_number,
                "description": (
                    "pull_request_target can expose privileged workflow "
                    "context to untrusted pull requests."
                )
            })

        # Detect unpinned GitHub Actions
        action_match = re.search(
            r"\buses:\s*([^\s#]+)",
            stripped
        )

        if action_match:
            action = action_match.group(1)

            if "@" in action:
                version = action.rsplit("@", 1)[1]

                if not re.fullmatch(r"[a-fA-F0-9]{40}", version):
                    findings.append({
                        "type": "Unpinned GitHub Action",
                        "severity": "MEDIUM",
                        "line": line_number,
                        "description": (
                            f"Action '{action}' is not pinned "
                            "to a full commit SHA."
                        )
                    })

        # Detect excessive write permissions
        if re.search(r"\bpermissions\s*:\s*write-all\b", stripped):
            findings.append({
                "type": "Excessive Permissions",
                "severity": "HIGH",
                "line": line_number,
                "description": (
                    "Workflow grants write access to all "
                    "available permissions."
                )
            })

        if re.fullmatch(r"write-all\s*", stripped):
            findings.append({
                "type": "Excessive Permissions",
                "severity": "HIGH",
                "line": line_number,
                "description": (
                    "Workflow grants write access to all "
                    "available permissions."
                )
            })

        # Detect individual write permissions
        if re.search(
            r"^\s*(contents|packages|actions|pull-requests|issues):\s*write\s*$",
            line,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Write Permission",
                "severity": "MEDIUM",
                "line": line_number,
                "description": (
                    "Workflow grants write permissions. "
                    "Check whether they are necessary."
                )
            })

        # Detect persistent checkout credentials
        if re.search(
            r"\bpersist-credentials\s*:\s*true\b",
            stripped,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Persistent Git Credentials",
                "severity": "MEDIUM",
                "line": line_number,
                "description": (
                    "Checkout credentials remain configured "
                    "in the local Git repository."
                )
            })

        # Detect possible secret exposure in shell commands
        if re.search(r"\brun\s*:", stripped) and re.search(
            r"\$\{\{\s*secrets\.",
            stripped,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Potential Secret Exposure",
                "severity": "HIGH",
                "line": line_number,
                "description": (
                    "A GitHub secret is referenced directly in a "
                    "shell command. Review quoting and exposure risks."
                )
            })

        # Detect secrets printed using echo
        if re.search(r"\becho\s+.*\$\{\{\s*secrets\.", stripped):
            findings.append({
                "type": "Possible Secret Printed",
                "severity": "HIGH",
                "line": line_number,
                "description": (
                    "A possible secret is printed in workflow logs."
                )
            })

        # Detect remote script execution
        if re.search(r"\brun\s*:", stripped) and re.search(
            r"curl\s+.*\|\s*(?:sh|bash)\b",
            stripped,
            re.IGNORECASE
        ):
            findings.append({
                "type": "Unsafe Script Execution",
                "severity": "HIGH",
                "line": line_number,
                "description": (
                    "A remote script is piped directly into a shell."
                )
            })

    return {
        "scanner": "workflow_scanner",
        "status": "completed",
        "total_findings": len(findings),
        "findings": findings
    }


def scan_workflow_directory(directory):
    """Scan all YAML workflow files in a directory."""

    root = Path(directory)

    if not root.is_dir():
        return {
            "scanner": "workflow_scanner",
            "status": "error",
            "findings": [],
            "message": "Invalid workflow directory."
        }

    findings = []

    for file_path in root.rglob("*"):
        if file_path.is_file() and file_path.suffix.lower() in {
            ".yml", ".yaml"
        }:
            result = scan_workflow(file_path)

            if result.get("status") == "completed":
                findings.extend(result.get("findings", []))
            else:
                return result

    return {
        "scanner": "workflow_scanner",
        "status": "completed",
        "total_findings": len(findings),
        "findings": findings
    }
