
import json
import subprocess
import shutil
from pathlib import Path


def scan_dependencies(requirements_file):
    """
    Scan Python dependencies using pip-audit.
    """

    requirements = Path(requirements_file)

    if not requirements.is_file():
        return {
            "scanner": "dependency_scanner",
            "status": "error",
            "findings": [],
            "message": "Requirements file not found."
        }

    if shutil.which("pip-audit") is None:
        return {
            "scanner": "dependency_scanner",
            "status": "error",
            "findings": [],
            "message": "pip-audit is not installed. Run: pip install pip-audit"
        }

    try:
        result = subprocess.run(
            [
                "pip-audit",
                "--requirement", str(requirements),
                "--format", "json"
            ],
            capture_output=True,
            text=True,
            timeout=180
        )

        if not result.stdout.strip():
            return {
                "scanner": "dependency_scanner",
                "status": "error",
                "findings": [],
                "message": result.stderr.strip() or
                           "pip-audit returned no output."
            }

        data = json.loads(result.stdout)
        findings = []

        for dependency in data.get("dependencies", []):

            for vulnerability in dependency.get("vulns", []):

                findings.append({
                    "package": dependency.get("name"),
                    "installed_version": dependency.get("version"),
                    "vulnerability_id": vulnerability.get("id"),
                    "severity": "UNKNOWN",
                    "description": vulnerability.get("description", ""),
                    "fixed_versions": vulnerability.get("fix_versions", [])
                })

        return {
            "scanner": "dependency_scanner",
            "status": "completed",
            "total_findings": len(findings),
            "findings": findings
        }

    except subprocess.TimeoutExpired:
        return {
            "scanner": "dependency_scanner",
            "status": "error",
            "findings": [],
            "message": "Dependency scan timed out."
        }

    except json.JSONDecodeError:
        return {
            "scanner": "dependency_scanner",
            "status": "error",
            "findings": [],
            "message": "Unable to parse pip-audit output."
        }

    except OSError as error:
        return {
            "scanner": "dependency_scanner",
            "status": "error",
            "findings": [],
            "message": str(error)
        }
