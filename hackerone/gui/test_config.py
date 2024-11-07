import pytest
from pathlib import Path
import os
from config import (
    BASE_DIR, REPORTS_DIR, CACHE_DIR,
    UI_CONFIG, THEME_CONFIG, VULNERABILITY_TYPES,
    SEVERITY_LEVELS, LITELLM_CONFIG, API_RATE_LIMITS,
    CACHE_CONFIG, ENV_CONFIG, LOGGING_CONFIG
)

def test_directory_structure():
    """Test that required directories exist and are writable"""
    assert BASE_DIR.exists()
    assert REPORTS_DIR.exists()
    assert CACHE_DIR.exists()
    
    # Test directory permissions
    assert os.access(REPORTS_DIR, os.W_OK)
    assert os.access(CACHE_DIR, os.W_OK)

def test_ui_config():
    """Test UI configuration settings"""
    assert isinstance(UI_CONFIG, dict)
    assert "page_title" in UI_CONFIG
    assert "page_icon" in UI_CONFIG
    assert "layout" in UI_CONFIG
    assert UI_CONFIG["layout"] == "wide"

def test_theme_config():
    """Test theme configuration"""
    assert isinstance(THEME_CONFIG, dict)
    assert "base" in THEME_CONFIG
    assert THEME_CONFIG["base"] == "dark"
    assert "primaryColor" in THEME_CONFIG
    assert "backgroundColor" in THEME_CONFIG

def test_vulnerability_types():
    """Test vulnerability type definitions"""
    assert isinstance(VULNERABILITY_TYPES, list)
    assert len(VULNERABILITY_TYPES) > 0
    assert "SQL Injection" in VULNERABILITY_TYPES
    assert "Cross-Site Scripting (XSS)" in VULNERABILITY_TYPES

def test_severity_levels():
    """Test severity level definitions"""
    assert isinstance(SEVERITY_LEVELS, dict)
    
    # Test required severity levels
    required_levels = ["critical", "high", "medium", "low"]
    for level in required_levels:
        assert level in SEVERITY_LEVELS
        assert "range" in SEVERITY_LEVELS[level]
        assert "color" in SEVERITY_LEVELS[level]
        assert "description" in SEVERITY_LEVELS[level]
    
    # Test CVSS ranges
    assert SEVERITY_LEVELS["critical"]["range"][0] > SEVERITY_LEVELS["high"]["range"][1]
    assert SEVERITY_LEVELS["high"]["range"][0] > SEVERITY_LEVELS["medium"]["range"][1]
    assert SEVERITY_LEVELS["medium"]["range"][0] > SEVERITY_LEVELS["low"]["range"][1]

def test_litellm_config():
    """Test LiteLLM configuration"""
    assert isinstance(LITELLM_CONFIG, dict)
    assert "model" in LITELLM_CONFIG
    assert "temperature" in LITELLM_CONFIG
    assert 0 <= LITELLM_CONFIG["temperature"] <= 1
    assert "max_tokens" in LITELLM_CONFIG

def test_api_rate_limits():
    """Test API rate limit settings"""
    assert isinstance(API_RATE_LIMITS, dict)
    assert "read" in API_RATE_LIMITS
    assert "write" in API_RATE_LIMITS
    
    # Test rate limit structure
    for limit_type in ["read", "write"]:
        assert "requests" in API_RATE_LIMITS[limit_type]
        assert "window" in API_RATE_LIMITS[limit_type]
        assert isinstance(API_RATE_LIMITS[limit_type]["requests"], int)
        assert isinstance(API_RATE_LIMITS[limit_type]["window"], int)

def test_cache_config():
    """Test cache configuration"""
    assert isinstance(CACHE_CONFIG, dict)
    assert "ttl" in CACHE_CONFIG
    assert "max_size" in CACHE_CONFIG
    assert CACHE_CONFIG["ttl"] > 0
    assert CACHE_CONFIG["max_size"] > 0

def test_env_config():
    """Test environment configuration"""
    assert isinstance(ENV_CONFIG, dict)
    required_vars = [
        "HACKERONE_API_USERNAME",
        "HACKERONE_API_TOKEN",
        "OPENAI_API_KEY",
        "LOG_LEVEL",
        "ENVIRONMENT"
    ]
    for var in required_vars:
        assert var in ENV_CONFIG

def test_logging_config():
    """Test logging configuration"""
    assert isinstance(LOGGING_CONFIG, dict)
    assert "version" in LOGGING_CONFIG
    assert "formatters" in LOGGING_CONFIG
    assert "handlers" in LOGGING_CONFIG
    assert "loggers" in LOGGING_CONFIG
    
    # Test log handlers
    assert "default" in LOGGING_CONFIG["handlers"]
    assert "file" in LOGGING_CONFIG["handlers"]
    
    # Test log file path
    log_path = Path(LOGGING_CONFIG["handlers"]["file"]["filename"])
    assert log_path.parent.exists()

def test_custom_css():
    """Test custom CSS configuration"""
    from config import CUSTOM_CSS
    assert isinstance(CUSTOM_CSS, str)
    assert CUSTOM_CSS.startswith("<style>")
    assert CUSTOM_CSS.endswith("</style>")
    
    # Test required CSS elements
    required_elements = [
        ".stApp",
        ".stSidebar",
        ".stTabs",
        ".stButton",
        ".stTextInput",
        ".stCodeBlock",
        ".stAlert"
    ]
    for element in required_elements:
        assert element in CUSTOM_CSS

def test_report_template():
    """Test report template structure"""
    from config import REPORT_TEMPLATE
    assert isinstance(REPORT_TEMPLATE, str)
    
    # Test required sections
    required_sections = [
        "{title}",
        "{vulnerability_details}",
        "{impact}",
        "{steps}",
        "{poc}",
        "{fix}",
        "{cvss_score}",
        "{cvss_vector}"
    ]
    for section in required_sections:
        assert section in REPORT_TEMPLATE

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
