
from pathlib import Path
from backend.scanners.secret_scanner import scan_directory


def test_detects_hardcoded_secrets():
    sample_folder = Path("tests/sample_secret_project")

    findings = scan_directory(sample_folder)

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


def test_detects_github_tokens():
    sample_folder = Path("tests/sample_secret_project")
    findings = scan_directory(sample_folder)

    assert any(
        "github" in str(item).lower()
        or "ghp_" in str(item).lower()
        for item in findings
    )


def test_detects_private_keys():
    sample_folder = Path("tests/sample_secret_project")
    findings = scan_directory(sample_folder)

    assert any(
        "private" in str(item).lower()
        or "private key" in str(item).lower()
        for item in findings
    )


def test_detects_env_files():
    sample_folder = Path("tests/sample_secret_project")
    findings = scan_directory(sample_folder)

    assert any(
        ".env" in str(item).lower()
        for item in findings
    )
