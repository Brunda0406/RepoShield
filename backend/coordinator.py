
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# Scanner modules will be imported when they are available.
SCANNER_MODULES = [
    ("Secret Scanner", "backend.scanners.secret_scanner"),
    ("Dependency Scanner", "backend.scanners.dependency_scanner"),
    ("Docker Scanner", "backend.scanners.docker_scanner"),
    ("Workflow Scanner", "backend.scanners.workflow_scanner"),
]


def run_all_scanners(root: Path):
    """
    Run all available security scanners on an extracted repository.

    Returns findings and scanner execution errors separately.
    """

    all_findings = []
    scanner_errors = []

    for scanner_name, module_name in SCANNER_MODULES:
        try:
            import importlib

            scanner_module = importlib.import_module(module_name)

            scan_function = getattr(scanner_module, "scan")

            findings = scan_function(root)

            if not isinstance(findings, list):
                raise TypeError("Scanner must return a list of findings")

            for finding in findings:
                if not isinstance(finding, dict):
                    raise TypeError("Each finding must be a dictionary")

                finding.setdefault("scanner", scanner_name)

            all_findings.extend(findings)

        except Exception as error:
            logger.exception("%s failed", scanner_name)

            scanner_errors.append({
                "scanner": scanner_name,
                "error": str(error)
            })

    return {
        "findings": all_findings,
        "scanner_errors": scanner_errors
    }


def calculate_security_score(findings):
    """
    Calculate a simple security score from 0 to 100.
    Higher severity findings reduce the score.
    """

    deductions = {
        "Critical": 20,
        "High": 10,
        "Medium": 5,
        "Low": 2
    }

    score = 100

    for finding in findings:
        severity = finding.get("severity", "").capitalize()
        score -= deductions.get(severity, 0)

    return max(0, min(100, score))
