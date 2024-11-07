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

@patch('requests.request')
def test_input_validation(mock_request, api_client, mock_response):
    """Test input validation"""
    mock_request.return_value = mock_response
    
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

@patch('os.getenv')
def test_check_environment(mock_getenv):
    """Test environment variable checking"""
    # Test valid environment
    mock_getenv.side_effect = lambda x: {
        'HACKERONE_API_USERNAME': 'test_user',
        'HACKERONE_API_TOKEN': 'test_token'
    }.get(x)
    
    username, token = check_environment()
    assert username == 'test_user'
    assert token == 'test_token'
    
    # Test missing variables
    mock_getenv.side_effect = lambda x: None
    with pytest.raises(ConfigError, match="Missing required environment variables"):
        check_environment()

@patch('requests.post')
def test_notification_handler(mock_post):
    """Test notification sending"""
    # Test with webhook URL
    handler = NotificationHandler(webhook_url="http://test.com")
    mock_post.return_value.raise_for_status.return_value = None
    
    assert handler.send_notification("Test message") == True
    mock_post.assert_called_once()
    
    # Test without webhook URL
    handler = NotificationHandler(webhook_url=None)
    assert handler.send_notification("Test message") == False
    
    # Test with failed request
    handler = NotificationHandler(webhook_url="http://test.com")
    mock_post.side_effect = requests.exceptions.RequestException
    assert handler.send_notification("Test message") == False

@patch('submit_reports.check_environment')
@patch('submit_reports.NotificationHandler')
@patch('submit_reports.HackerOneAPI')
def test_main(mock_api, mock_notifier, mock_check_env, tmp_path):
    """Test main function"""
    # Setup mocks
    mock_check_env.return_value = ('test_user', 'test_token')
    mock_notifier.return_value.webhook_url = 'http://test.com'
    mock_api.return_value.submit_report.return_value = MOCK_API_RESPONSE
    
    # Create test report files
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    (report_dir / "test_report.md").write_text("Test content")
    
    # Run main
    with patch('sys.argv', ['submit_reports.py']):
        main()
    
    # Verify API client was created
    mock_api.assert_called_once_with('test_user', 'test_token')
    
    # Verify notification was attempted
    mock_notifier.return_value.send_notification.assert_called()

if __name__ == '__main__':
    pytest.main([__file__])
