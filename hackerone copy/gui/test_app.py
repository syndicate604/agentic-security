import pytest
from unittest.mock import Mock, patch
import streamlit as st
from app import AIHackerFix
import litellm
import json
from datetime import datetime

# Sample test data
MOCK_CODE = """
def process_user_input(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    cursor.execute(query)
"""

MOCK_ANALYSIS = {
    "analysis": """
1. Vulnerability Description
SQL Injection vulnerability in user input processing.

2. Security Impact
Allows unauthorized database access and manipulation.

3. Steps to Reproduce
1. Submit malicious input like "1 OR 1=1"
2. Observe full table contents returned

4. Recommended Fix
Use parameterized queries:
```python
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_input,))
```

5. CVSS Score: 7.5 (High)
Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
""",
    "timestamp": datetime.now().isoformat()
}

MOCK_REPORT = {
    "title": "Security Vulnerability: SQL Injection in User Input",
    "vulnerability_information": "Detailed markdown content...",
    "impact": "Allows unauthorized database access",
    "severity": "high",
    "weakness_id": 89
}

@pytest.fixture
def app():
    """Create AIHackerFix instance for testing"""
    return AIHackerFix()

@pytest.fixture
def mock_litellm():
    """Mock LiteLLM responses"""
    with patch('litellm.completion') as mock:
        response = Mock()
        response.choices = [
            Mock(message=Mock(content=MOCK_ANALYSIS["analysis"]))
        ]
        mock.return_value = response
        yield mock

@pytest.fixture
def mock_hackerone_api():
    """Mock HackerOne API client"""
    with patch('submit_reports.HackerOneAPI') as mock:
        yield mock

def test_init_api_client(app, mock_hackerone_api):
    """Test API client initialization"""
    app.init_api_client("test_user", "test_token")
    mock_hackerone_api.assert_called_once_with("test_user", "test_token")
    assert app.api_client is not None

def test_analyze_vulnerability(app, mock_litellm):
    """Test vulnerability analysis with AI"""
    result = app.analyze_vulnerability(MOCK_CODE, "SQL Injection")
    
    # Verify LiteLLM was called correctly
    mock_litellm.assert_called_once()
    call_args = mock_litellm.call_args[1]
    
    assert call_args["model"] == "gpt-4"
    assert "SQL Injection" in call_args["messages"][0]["content"]
    assert MOCK_CODE in call_args["messages"][0]["content"]
    
    # Verify response format
    assert "analysis" in result
    assert "timestamp" in result
    assert isinstance(result["timestamp"], str)

def test_generate_report(app):
    """Test report generation from analysis"""
    report = app.generate_report(MOCK_ANALYSIS)
    
    assert isinstance(report, dict)
    assert "title" in report
    assert "vulnerability_information" in report
    assert "impact" in report
    assert "severity" in report
    assert report["severity"] == "medium"  # Default severity

@pytest.mark.streamlit
def test_streamlit_settings_page():
    """Test Streamlit settings page"""
    with patch('streamlit.text_input') as mock_input:
        mock_input.side_effect = ["test_user", "test_token", "test_key"]
        
        # Run main app with settings page
        with patch('streamlit.sidebar.radio') as mock_radio:
            mock_radio.return_value = "Settings"
            
            # Mock session state
            if 'app' not in st.session_state:
                st.session_state.app = AIHackerFix()
            
            # Verify inputs are created
            assert mock_input.call_count == 3
            calls = mock_input.call_args_list
            assert calls[0][0][0] == "API Username"
            assert calls[1][0][0] == "API Token"
            assert calls[2][0][0] == "OpenAI API Key"

@pytest.mark.streamlit
def test_streamlit_analyze_page(mock_litellm):
    """Test Streamlit analyze page"""
    with patch('streamlit.text_area') as mock_text_area:
        mock_text_area.return_value = MOCK_CODE
        
        with patch('streamlit.selectbox') as mock_select:
            mock_select.return_value = "SQL Injection"
            
            # Run main app with analyze page
            with patch('streamlit.sidebar.radio') as mock_radio:
                mock_radio.return_value = "Analyze"
                
                # Mock session state
                if 'app' not in st.session_state:
                    st.session_state.app = AIHackerFix()
                
                # Verify inputs are created
                assert mock_text_area.call_count == 1
                assert mock_select.call_count == 1
                
                # Verify analysis is performed
                if hasattr(st.session_state, 'last_analysis'):
                    assert "analysis" in st.session_state.last_analysis
                    assert "timestamp" in st.session_state.last_analysis

@pytest.mark.streamlit
def test_streamlit_submit_page(mock_hackerone_api):
    """Test Streamlit submit page"""
    with patch('streamlit.checkbox') as mock_checkbox:
        mock_checkbox.return_value = True
        
        # Run main app with submit page
        with patch('streamlit.sidebar.radio') as mock_radio:
            mock_radio.return_value = "Submit"
            
            # Mock session state
            if 'app' not in st.session_state:
                st.session_state.app = AIHackerFix()
                st.session_state.app.api_client = mock_hackerone_api()
            if 'reports' not in st.session_state:
                st.session_state.reports = [MOCK_REPORT]
            
            # Verify submission is attempted
            assert mock_checkbox.call_count == 1
            if mock_checkbox.return_value:
                assert mock_hackerone_api.return_value.submit_report.call_count == 1

if __name__ == '__main__':
    pytest.main([__file__])
