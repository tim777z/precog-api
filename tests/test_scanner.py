import pytest
from app.scanner import SecurityScanner


@pytest.fixture
def scanner():
    return SecurityScanner()


def test_scanner_init(scanner):
    assert scanner.findings == []
    assert scanner.score == 100


def test_invalid_url():
    scanner = SecurityScanner()
    result = scanner.scan_repo("https://not-github.com/user/repo")
    assert "error" in result


def test_generate_summary_high_score():
    scanner = SecurityScanner()
    results = {"score": 95, "findings": [], "files_scanned": 10}
    summary = scanner._generate_summary(results)
    assert "A" in summary
    assert "Excellent" in summary


def test_generate_summary_low_score():
    scanner = SecurityScanner()
    results = {"score": 20, "findings": [{"severity": "critical"}] * 5, "files_scanned": 10}
    summary = scanner._generate_summary(results)
    assert "F" in summary


def test_check_dependencies_unpinned(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("flask\nrequests==2.28.0\n")
    scanner = SecurityScanner()
    findings = scanner._check_dependencies(str(tmp_path))
    assert len(findings) == 1
    assert "flask" in findings[0]["message"]


def test_check_dependencies_pinned(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("flask==2.3.0\nrequests==2.28.0\n")
    scanner = SecurityScanner()
    findings = scanner._check_dependencies(str(tmp_path))
    assert len(findings) == 0
