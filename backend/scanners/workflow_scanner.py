
import re
from pathlib import Path


def scan_workflow(file_path):
    findings = []
    path = Path(file_path)

    if not path.is_file():
        return [{
            "file": str(path),
            "line": 0,
            "issue": "Workflow file not found",
            "severity": "Error",
            "recommendation": "Check the file path."
        }]

    try:
        lines = path.read_text(
            encoding="utf-8",
            errors="ignore"
        ).splitlines()
    except OSError:
        return [{
            "file": str(path),
            "line": 0,
            "issue": "Unable to read workflow file",
            "severity": "Error",
            "recommendation": "Check file permissions."
        }]

    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        # Check for overly broad permissions
        if re.search(r"permissions\s*:\s*write-all\b", stripped):
            findings.append({
                "file": str(path),
                "line": line_number,
                "issue": "Workflow uses write-all permissions",
                "severity": "High",
                "recommendation": "Grant only the minimum permissions required."
            })

        # Check for pull_request_target
        if re.search(r"pull_request_target\s*:", stripped):
            findings.append({
                "file": str(path),
                "line": line_number,
                "issue": "Workflow uses pull_request_target",
                "severity": "Medium",
                "recommendation": "Review permissions and handling of untrusted contributions."
            })

        # Check for possible secret exposure
        if re.search(
            r"echo\s+.*\$\{\{\s*secrets\.",
            stripped,
            re.IGNORECASE
        ):
            findings.append({
                "file": str(path),
                "line": line_number,
                "issue": "Possible secret printed in workflow",
                "severity": "High",
                "recommendation": "Avoid printing secrets in workflow logs."
            })

        # Check whether actions are pinned to a full commit SHA
        match = re.search(r"\buses:\s*([^\s#]+)", stripped)

        if match:
            action_reference = match.group(1)

            if "@" in action_reference:
                version = action_reference.rsplit("@", 1)[1]

                if not re.fullmatch(r"[0-9a-fA-F]{40}", version):
                    findings.append({
                        "file": str(path),
                        "line": line_number,
                        "issue": "GitHub Action is not pinned to a full commit SHA",
                        "severity": "Medium",
                        "recommendation": "Pin the action to a verified full 40-character commit SHA."
                    })

    return findings
