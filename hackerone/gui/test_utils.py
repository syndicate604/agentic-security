import pytest
import json
from pathlib import Path
from datetime import datetime
import utils
from config import REPORTS_DIR, CACHE_DIR

# Sample test data
SAMPLE_REPORT = {
    "title": "Test Vulnerability Report",
    "vulnerability_details": "Test vulnerability details",
    "impact": "Test impact description",
    "steps": "Test reproduction steps",
    "poc": "Test proof of concept",
    "fix": "Test recommended fix",
    "severity": "medium",
    "vulnerability_type": "SQL Injection"
}

@pytest.fixture
def setup_test_dirs(tmp_path):
    """Setup test directories"""
    # Create test directories
    reports_dir = tmp_path / "reports"
    cache_dir = tmp_path / "cache"
    reports_dir.mkdir()
    cache_dir.mkdir()
    
    # Temporarily override directory paths
    original_reports_dir = utils.REPORTS_DIR
    original_cache_dir = utils.CACHE_DIR
    utils.REPORTS_DIR = reports_dir
    utils.CACHE_DIR = cache_dir
    
    yield reports_dir, cache_dir
    
    # Restore original paths
    utils.REPORTS_DIR = original_reports_dir
    utils.CACHE_DIR = original_cache_dir

def test_sanitize_filename():
    """Test filename sanitization"""
    test_cases = [
        ("Test File.txt", "test_file.txt"),
        ("Test/File", "testfile"),
        ('Test:File*', "testfile"),
        ("Test\\File", "testfile"),
        ("Test?File", "testfile")
    ]
    
    for input_name, expected in test_cases:
        assert utils.sanitize_filename(input_name) == expected

def test_save_load_report(setup_test_dirs):
    """Test saving and loading reports"""
    reports_dir, _ = setup_test_dirs
    
    # Save report
    report_id = utils.save_report(SAMPLE_REPORT)
    assert (reports_dir / f"{report_id}.json").exists()
    
    # Load report
    loaded_report = utils.load_report(report_id)
    assert loaded_report == SAMPLE_REPORT

def test_list_reports(setup_test_dirs):
    """Test listing reports"""
    reports_dir, _ = setup_test_dirs
    
    # Save multiple reports
    report_ids = []
    for i in range(3):
        report_id = utils.save_report(SAMPLE_REPORT)
        report_ids.append(report_id)
    
    # List reports
    listed_reports = utils.list_reports()
    assert len(listed_reports) == 3
    assert all(id in listed_reports for id in report_ids)

def test_calculate_cvss_score():
    """Test CVSS score calculation"""
    score = utils.calculate_cvss_score(
        attack_vector="Network",
        attack_complexity="Low",
        privileges_required="None",
        user_interaction="None",
        scope="Unchanged",
        confidentiality="High",
        integrity="High",
        availability="None"
    )
    
    assert isinstance(score, float)
    assert 0 <= score <= 10

def test_get_severity_from_cvss():
    """Test severity level determination from CVSS score"""
    test_cases = [
        (9.5, "critical"),
        (7.5, "high"),
        (5.5, "medium"),
        (2.5, "low")
    ]
    
    for score, expected_severity in test_cases:
        assert utils.get_severity_from_cvss(score) == expected_severity

def test_format_report():
    """Test report formatting"""
    formatted = utils.format_report(SAMPLE_REPORT)
    assert isinstance(formatted, str)
    assert SAMPLE_REPORT["title"] in formatted
    assert SAMPLE_REPORT["vulnerability_details"] in formatted

def test_markdown_to_html():
    """Test markdown to HTML conversion"""
    markdown_text = """
    # Test Title
    
    ```python
    def test():
        pass
    ```
    """
    
    html = utils.markdown_to_html(markdown_text)
    assert "<h1>Test Title</h1>" in html
    assert "<code>" in html

def test_cache_operations(setup_test_dirs):
    """Test caching operations"""
    _, cache_dir = setup_test_dirs
    
    test_data = {"test": "data"}
    test_key = "test_key"
    
    # Cache data
    utils.cache_result(test_key, test_data)
    assert (cache_dir / f"{test_key}.json").exists()
    
    # Retrieve cached data
    cached = utils.get_cached_result(test_key)
    assert cached == test_data
    
    # Test non-existent cache
    assert utils.get_cached_result("nonexistent") is None

def test_validate_report():
    """Test report validation"""
    # Test valid report
    errors = utils.validate_report(SAMPLE_REPORT)
    assert len(errors) == 0
    
    # Test invalid report
    invalid_report = SAMPLE_REPORT.copy()
    del invalid_report["impact"]
    errors = utils.validate_report(invalid_report)
    assert len(errors) > 0
    assert "Missing required field: impact" in errors
    
    # Test invalid severity
    invalid_report = SAMPLE_REPORT.copy()
    invalid_report["severity"] = "invalid"
    errors = utils.validate_report(invalid_report)
    assert len(errors) > 0
    assert "Invalid severity level" in errors

def test_clean_cache(setup_test_dirs):
    """Test cache cleaning"""
    _, cache_dir = setup_test_dirs
    
    # Create test cache files
    test_data = {"test": "data"}
    utils.cache_result("test1", test_data)
    utils.cache_result("test2", test_data)
    
    # Clean cache
    utils.clean_cache()
    
    # Verify files are still there (they're new)
    assert len(list(cache_dir.glob("*.json"))) == 2

def test_export_report():
    """Test report export"""
    # Test markdown export
    md_export = utils.export_report(SAMPLE_REPORT, 'md')
    assert isinstance(md_export, str)
    assert SAMPLE_REPORT["title"] in md_export
    
    # Test HTML export
    html_export = utils.export_report(SAMPLE_REPORT, 'html')
    assert isinstance(html_export, str)
    assert "<h1>" in html_export
    
    # Test invalid format
    with pytest.raises(ValueError):
        utils.export_report(SAMPLE_REPORT, 'invalid')

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
