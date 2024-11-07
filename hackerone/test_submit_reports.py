import pytest
import json
import time
import base64
import requests
from unittest.mock import Mock, patch
from pathlib import Path
from submit_reports import HackerOneAPI, RateLimiter

# Sample test data
MOCK_REPORT = {
    "title": "Test Vulnerability",
    "vulnerability_info": "Test description",
    "impact": "Test impact",
    "severity": "low",
    "weakness_id": 89
}

MOCK_API_RESPONSE = {
    "data": {
        "id": "1337",
        "type": "report",
        "attributes": {
            "title": "Test Vulnerability",
            "state": "new",
            "created_at": "2024-01-01T00:00:00Z"
        }
    }
}

@pytest.fixture
def api_client():
    """Create API client with mock credentials"""
    return HackerOneAPI("test_user", "test_token")

@pytest.fixture
def mock_response():
    """Create mock response"""
    mock = Mock()
    mock.json.return_value = MOCK_API_RESPONSE
    mock.raise_for_status.return_value = None
    return mock

def test_rate_limiter():
    """Test rate limiter functionality"""
    limiter = RateLimiter(2, 1)  # 2 requests per second
    
    # First two requests should not wait
    start_time = time.time()
    limiter.wait_if_needed()
    limiter.wait_if_needed()
    elapsed = time.time() - start_time
    assert elapsed < 0.1  # Should be near-instant
    
    # Third request should wait
    limiter.wait_if_needed()
    elapsed = time.time() - start_time
    assert elapsed >= 1.0  # Should wait for time window

@patch('requests.request')
def test_submit_report(mock_request, api_client, mock_response):
    """Test report submission"""
    mock_request.return_value = mock_response
    
    response = api_client.submit_report(
        title=MOCK_REPORT["title"],
        vulnerability_info=MOCK_REPORT["vulnerability_info"],
        impact=MOCK_REPORT["impact"],
        severity=MOCK_REPORT["severity"],
        weakness_id=MOCK_REPORT["weakness_id"]
    )
    
    # Verify API was called correctly
    mock_request.assert_called_once()
    call_args = mock_request.call_args
    
    # Check request method and endpoint
    assert call_args[1]["method"] == "POST"
    assert call_args[1]["url"] == "https://api.hackerone.com/v1/reports"
    
    # Check request data
    data = call_args[1]["json"]
    assert data["data"]["type"] == "report"
    assert data["data"]["attributes"]["title"] == MOCK_REPORT["title"]
    
    # Check response
    assert response == MOCK_API_RESPONSE

@patch('requests.request')
def test_check_report_status(mock_request, api_client, mock_response):
    """Test report status check"""
    mock_request.return_value = mock_response
    
    response = api_client.check_report_status("1337")
    
    # Verify API was called correctly
    mock_request.assert_called_once()
    call_args = mock_request.call_args
    
    # Check request method and endpoint
    assert call_args[1]["method"] == "GET"
    assert call_args[1]["url"] == "https://api.hackerone.com/v1/reports/1337"
    
    # Check response
    assert response == MOCK_API_RESPONSE

@patch('requests.request')
def test_add_attachment(mock_request, api_client, mock_response, tmp_path):
    """Test file attachment"""
    # Create test file
    test_file = tmp_path / "test.txt"
    test_content = "Test attachment content"
    test_file.write_text(test_content)
    
    mock_request.return_value = mock_response
    
    response = api_client.add_attachment("1337", str(test_file))
    
    # Verify API was called correctly
    mock_request.assert_called_once()
    call_args = mock_request.call_args
    
    # Check request method and endpoint
    assert call_args[1]["method"] == "POST"
    assert call_args[1]["url"] == "https://api.hackerone.com/v1/reports/1337/attachments"
    
    # Check file data
    data = call_args[1]["json"]
    assert data["data"]["type"] == "attachment"
    assert data["data"]["attributes"]["file_name"] == "test.txt"
    
    # Verify file content was base64 encoded
    file_content = base64.b64decode(data["data"]["attributes"]["file"]).decode()
    assert file_content == test_content

@patch('requests.request')
def test_error_handling(mock_request, api_client):
    """Test error handling"""
    # Test rate limit error
    mock_response = Mock()
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=Mock(status_code=429)
    )
    mock_request.return_value = mock_response
    
    with pytest.raises(requests.exceptions.HTTPError):
        api_client.submit_report(
            title="Test",
            vulnerability_info="Test",
            impact="Test"
        )
    
    # Test authentication error
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=Mock(status_code=401)
    )
    
    with pytest.raises(requests.exceptions.HTTPError):
        api_client.submit_report(
            title="Test",
            vulnerability_info="Test",
            impact="Test"
        )

def test_input_validation(api_client):
    """Test input validation"""
    # Test missing required fields
    with pytest.raises(ValueError, match="Title is required"):
        api_client.submit_report(
            title="",  # Empty title
            vulnerability_info="Test",
            impact="Test"
        )
    
    with pytest.raises(ValueError, match="Vulnerability information is required"):
        api_client.submit_report(
            title="Test",
            vulnerability_info="",  # Empty vulnerability info
            impact="Test"
        )
        
    with pytest.raises(ValueError, match="Impact description is required"):
        api_client.submit_report(
            title="Test",
            vulnerability_info="Test",
            impact=""  # Empty impact
        )
    
    # Test invalid severity values
    with pytest.raises(ValueError, match="Invalid severity"):
        api_client.submit_report(
            title="Test",
            vulnerability_info="Test",
            impact="Test",
            severity="invalid"  # Invalid severity
        )
        
    # Test valid severity values
    for severity in ['none', 'low', 'medium', 'high', 'critical']:
        response = api_client.submit_report(
            title="Test",
            vulnerability_info="Test",
            impact="Test",
            severity=severity
        )
        assert response == MOCK_API_RESPONSE
    
    # Test invalid weakness_id
    with pytest.raises(ValueError, match="weakness_id must be an integer"):
        api_client.submit_report(
            title="Test",
            vulnerability_info="Test",
            impact="Test",
            weakness_id="invalid"  # Should be integer
        )
        
    with pytest.raises(ValueError, match="weakness_id must be an integer"):
        api_client.submit_report(
            title="Test",
            vulnerability_info="Test",
            impact="Test",
            weakness_id=3.14  # Float not allowed
        )

if __name__ == '__main__':
    pytest.main([__file__])
