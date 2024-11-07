"""
Shared pytest fixtures for AI Hacker Fix GUI tests.
"""

import pytest
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
import streamlit as st
import json

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

@pytest.fixture(scope="session")
def test_env():
    """Setup test environment variables"""
    original_env = os.environ.copy()
    os.environ.update({
        "HACKERONE_API_USERNAME": "test_user",
        "HACKERONE_API_TOKEN": "test_token",
        "OPENAI_API_KEY": "test_key",
        "STREAMLIT_BROWSER_GATHER_USAGE_STATS": "false",
        "STREAMLIT_SERVER_HEADLESS": "true"
    })
    yield
    os.environ.clear()
    os.environ.update(original_env)

@pytest.fixture(scope="function")
def temp_dir():
    """Create temporary directory for test files"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)

@pytest.fixture(scope="function")
def mock_streamlit():
    """Mock Streamlit components"""
    with patch.object(st, "title") as mock_title, \
         patch.object(st, "sidebar") as mock_sidebar, \
         patch.object(st, "text_input") as mock_input, \
         patch.object(st, "text_area") as mock_textarea, \
         patch.object(st, "button") as mock_button, \
         patch.object(st, "success") as mock_success, \
         patch.object(st, "error") as mock_error:
        
        yield {
            "title": mock_title,
            "sidebar": mock_sidebar,
            "text_input": mock_input,
            "text_area": mock_textarea,
            "button": mock_button,
            "success": mock_success,
            "error": mock_error
        }

@pytest.fixture(scope="function")
def mock_litellm():
    """Mock LiteLLM responses"""
    with patch('litellm.completion') as mock:
        response = Mock()
        response.choices = [
            Mock(message=Mock(content="Test AI response"))
        ]
        mock.return_value = response
        yield mock

@pytest.fixture(scope="function")
def mock_hackerone_api():
    """Mock HackerOne API client"""
    with patch('submit_reports.HackerOneAPI') as mock:
        mock.return_value.submit_report.return_value = {
            "data": {
                "id": "1337",
                "type": "report",
                "attributes": {
                    "title": "Test Report",
                    "state": "new"
                }
            }
        }
        yield mock

@pytest.fixture(scope="function")
def sample_report_file(temp_dir):
    """Create a sample report file"""
    report_path = temp_dir / "test_report.json"
    with open(report_path, 'w') as f:
        json.dump(SAMPLE_REPORT, f)
    yield report_path

@pytest.fixture(scope="function")
def mock_session_state():
    """Mock Streamlit session state"""
    if not hasattr(st, "session_state"):
        setattr(st, "session_state", {})
    original_state = getattr(st, "session_state", {}).copy()
    st.session_state.clear()
    yield st.session_state
    st.session_state.clear()
    st.session_state.update(original_state)

@pytest.fixture(scope="function")
def mock_file_uploader():
    """Mock Streamlit file uploader"""
    class MockUploadedFile:
        def __init__(self, content):
            self.content = content
            
        def read(self):
            return self.content
    
    with patch.object(st, "file_uploader") as mock:
        mock.return_value = MockUploadedFile(b"Test file content")
        yield mock

@pytest.fixture(scope="function")
def mock_markdown():
    """Mock markdown conversion"""
    with patch('markdown.markdown') as mock:
        mock.return_value = "<h1>Test HTML</h1>"
        yield mock

@pytest.fixture(scope="function")
def mock_cache():
    """Mock Streamlit caching"""
    @st.cache_data
    def mock_cached_function():
        return "cached_result"
    
    yield mock_cached_function

@pytest.fixture(scope="function")
def mock_progress_bar():
    """Mock Streamlit progress bar"""
    class MockProgressBar:
        def __init__(self):
            self.progress = 0
            
        def progress(self, value):
            self.progress = value
    
    with patch.object(st, "progress") as mock:
        mock.return_value = MockProgressBar()
        yield mock

@pytest.fixture(scope="function")
def mock_config():
    """Mock configuration settings"""
    from config import UI_CONFIG, THEME_CONFIG
    
    original_ui = UI_CONFIG.copy()
    original_theme = THEME_CONFIG.copy()
    
    UI_CONFIG.update({
        "page_title": "Test App",
        "page_icon": "🧪"
    })
    
    THEME_CONFIG.update({
        "primaryColor": "#ff0000",
        "backgroundColor": "#ffffff"
    })
    
    yield
    
    UI_CONFIG.clear()
    THEME_CONFIG.clear()
    UI_CONFIG.update(original_ui)
    THEME_CONFIG.update(original_theme)

def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "streamlit: mark test as requiring streamlit components"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )

def pytest_collection_modifyitems(items):
    """Add markers to test items based on naming conventions"""
    for item in items:
        if "test_app" in item.nodeid:
            item.add_marker(pytest.mark.streamlit)
        if "test_integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        if "test_slow" in item.nodeid:
            item.add_marker(pytest.mark.slow)
