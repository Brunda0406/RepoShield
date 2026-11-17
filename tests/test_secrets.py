
from pathlib import Path
from backend.scanners.secret_scanner import scan_directory


def test_detects_hardcoded_secrets():
    sample_folder = Path("tests/sample_secret_project")

    findings = scan_directory(sample_folder)

    print(findings)

    assert len(findings) >= 3

    assert all(
        item["scanner"] == "Secret Scanner"
        for item in findings
    )

    assert all(
        "evidence_masked" in item
        for item in findings
    )

    assert all(
        item["line"] > 0
        for item in findings
    )
