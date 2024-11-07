#!/usr/bin/env python3
"""
HackerOne API Client for Bug Report Submission

This script provides functionality to submit vulnerability reports to HackerOne
using their REST API v1. It handles authentication, rate limiting, and proper
formatting of report data according to HackerOne's specifications.

API Base URL: https://api.hackerone.com/v1

Rate Limits:
- Read operations: 600 requests per minute
- Write operations: 25 requests per 20 seconds

Authentication:
Uses HTTP Basic Authentication with API username and token
"""

import os
import sys
import json
import time
import base64
import requests
import logging
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ConfigError(Exception):
    """Custom exception for configuration errors"""
    pass

class NotificationHandler:
    """Handles sending notifications to configured channels"""
    
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url
        
    def send_notification(self, message: str, level: str = 'info') -> bool:
        """
        Send notification to configured channels
        Returns True if notification was sent successfully
        """
        if not self.webhook_url:
            return False
            
        try:
            payload = {
                "text": f"[{level.upper()}] {message}",
                "username": "HackerOne Report Bot",
                "icon_emoji": ":bug:",
                "timestamp": datetime.now().timestamp()
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=5
            )
            response.raise_for_status()
            return True
            
        except Exception as e:
            logger.error(f"Failed to send notification: {str(e)}")
            return False

def check_environment() -> Tuple[str, str]:
    """
    Check and validate environment variables
    Returns tuple of (username, token) if valid
    Raises detailed ConfigError if invalid
    """
    load_dotenv()
    
    api_username = os.getenv("HACKERONE_API_USERNAME")
    api_token = os.getenv("HACKERONE_API_TOKEN")
    
    missing = []
    if not api_username:
        missing.append("HACKERONE_API_USERNAME")
    if not api_token:
        missing.append("HACKERONE_API_TOKEN")
        
    if missing:
        raise ConfigError(
            f"Missing required environment variables: {', '.join(missing)}\n"
            "Please set them in your .env file or environment.\n"
            "See .env.example for required variables."
        )
        
    return api_username, api_token

class RateLimiter:
    """Rate limiter for API requests"""
    
    def __init__(self, max_requests: int, time_window: int):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
    
    def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        now = time.time()
        
        # Remove old requests outside time window
        self.requests = [req_time for req_time in self.requests 
                        if now - req_time <= self.time_window]
        
        if len(self.requests) >= self.max_requests:
            sleep_time = self.requests[0] + self.time_window - now
            if sleep_time > 0:
                logger.info(f"Rate limit reached, waiting {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
        
        self.requests.append(now)

class HackerOneAPI:
    """HackerOne API client for submitting vulnerability reports"""
    
    def __init__(self, api_username: str, api_token: str):
        """
        Initialize HackerOne API client
        
        Args:
            api_username: HackerOne API username
            api_token: HackerOne API token
        """
        self.base_url = "https://api.hackerone.com/v1"
        self.auth = (api_username, api_token)
        
        # Setup rate limiters
        self.read_limiter = RateLimiter(600, 60)  # 600 requests per minute
        self.write_limiter = RateLimiter(25, 20)  # 25 requests per 20 seconds
    
    def _make_request(self, method: str, endpoint: str, 
                     data: Optional[Dict] = None) -> Dict:
        """
        Make an API request with rate limiting and error handling
        
        Args:
            method: HTTP method (GET, POST, etc)
            endpoint: API endpoint
            data: Request data (for POST/PUT)
            
        Returns:
            API response as dictionary
        """
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        # Apply rate limiting
        if method in ["POST", "PUT", "PATCH", "DELETE"]:
            self.write_limiter.wait_if_needed()
        else:
            self.read_limiter.wait_if_needed()
        
        try:
            response = requests.request(
                method=method,
                url=url,
                auth=self.auth,
                headers=headers,
                json=data
            )
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                logger.error("Rate limit exceeded")
            elif e.response.status_code == 401:
                logger.error("Invalid API credentials")
            elif e.response.status_code == 403:
                logger.error("Insufficient permissions")
            elif e.response.status_code == 422:
                logger.error(f"Invalid report data: {e.response.text}")
            raise
            
        except Exception as e:
            logger.error(f"API request failed: {str(e)}")
            raise

    def submit_report(self, 
                     title: str,
                     vulnerability_info: str,
                     impact: str,
                     severity: Optional[str] = None,
                     weakness_id: Optional[int] = None,
                     attachments: Optional[List[str]] = None,
                     structured_scope: Optional[Dict] = None) -> Dict:
        """
        Submit a vulnerability report
        
        Args:
            title: Report title
            vulnerability_info: Detailed vulnerability description
            impact: Security impact description
            severity: CVSS-based severity rating (must be one of: none, low, medium, high, critical)
            weakness_id: CWE ID for vulnerability type
            attachments: List of file paths to attach
            structured_scope: Affected assets/components
            
        Returns:
            API response containing report details
            
        Raises:
            ValueError: If required fields are missing or invalid
        """
        # Validate required fields
        if not title or not title.strip():
            raise ValueError("Title is required and cannot be empty")
        if not vulnerability_info or not vulnerability_info.strip():
            raise ValueError("Vulnerability information is required")
        if not impact or not impact.strip():
            raise ValueError("Impact description is required")
            
        # Validate severity if provided
        valid_severities = {'none', 'low', 'medium', 'high', 'critical'}
        if severity and severity.lower() not in valid_severities:
            raise ValueError(f"Invalid severity. Must be one of: {', '.join(valid_severities)}")
            
        # Validate weakness_id if provided
        if weakness_id is not None and not isinstance(weakness_id, int):
            raise ValueError("weakness_id must be an integer")
        # Validate required fields
        if not title or not title.strip():
            raise ValueError("Title is required and cannot be empty")
        if not vulnerability_info or not vulnerability_info.strip():
            raise ValueError("Vulnerability information is required")
        if not impact or not impact.strip():
            raise ValueError("Impact description is required")
            
        # Validate severity if provided
        valid_severities = {'none', 'low', 'medium', 'high', 'critical'}
        if severity and severity.lower() not in valid_severities:
            raise ValueError(f"Invalid severity. Must be one of: {', '.join(valid_severities)}")
            
        # Validate weakness_id if provided
        if weakness_id is not None and not isinstance(weakness_id, int):
            raise ValueError("weakness_id must be an integer")
        """
        Submit a vulnerability report
        
        Args:
            title: Report title
            vulnerability_info: Detailed vulnerability description
            impact: Security impact description
            severity: CVSS-based severity rating
            weakness_id: CWE ID for vulnerability type
            attachments: List of file paths to attach
            structured_scope: Affected assets/components
            
        Returns:
            API response containing report details
        """
        # Prepare report data
        data = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": title,
                    "vulnerability_information": vulnerability_info,
                    "impact": impact
                }
            }
        }
        
        # Add optional fields
        if severity:
            data["data"]["attributes"]["severity"] = {
                "rating": severity
            }
        
        if weakness_id:
            data["data"]["relationships"] = {
                "weakness": {
                    "data": {
                        "type": "weakness",
                        "id": str(weakness_id)
                    }
                }
            }
        
        if structured_scope:
            if "relationships" not in data["data"]:
                data["data"]["relationships"] = {}
            data["data"]["relationships"]["structured_scope"] = {
                "data": structured_scope
            }
        
        # Submit report
        response = self._make_request("POST", "/reports", data)
        report_id = response["data"]["id"]
        
        # Upload attachments if provided
        if attachments:
            for file_path in attachments:
                self.add_attachment(report_id, file_path)
        
        return response

    def add_attachment(self, report_id: str, file_path: str) -> Dict:
        """
        Add an attachment to a report
        
        Args:
            report_id: HackerOne report ID
            file_path: Path to file to attach
            
        Returns:
            API response for attachment
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise ValueError(f"File not found: {file_path}")
        
        # Get file metadata
        file_name = file_path.name
        file_size = file_path.stat().st_size
        
        # Read file content
        with open(file_path, "rb") as f:
            file_content = f.read()
            file_base64 = base64.b64encode(file_content).decode()
        
        # Prepare attachment data
        data = {
            "data": {
                "type": "attachment",
                "attributes": {
                    "file": file_base64,
                    "file_name": file_name,
                    "content_type": "application/octet-stream"
                }
            }
        }
        
        return self._make_request(
            "POST", 
            f"/reports/{report_id}/attachments",
            data
        )

    def check_report_status(self, report_id: str) -> Dict:
        """
        Check status of a submitted report
        
        Args:
            report_id: HackerOne report ID
            
        Returns:
            Report status information
        """
        return self._make_request("GET", f"/reports/{report_id}")

def main():
    """Main function to submit vulnerability reports"""
    try:
        # Check environment setup
        config = check_environment()
        
        # Initialize notification handler if webhook provided
        notifier = NotificationHandler(config.get('SLACK_WEBHOOK'))
        
        # Initialize API client
        client = HackerOneAPI(
            api_username=st.secrets["HACKERONE_API_USERNAME"],
            api_token=st.secrets["HACKERONE_API_TOKEN"]
        )
        
        if notifier.webhook_url:
            notifier.send_notification("Starting vulnerability report submission")
        
        # Define reports to submit
        reports = [
            {
                "title": "Command Injection in API Endpoint",
                "file": "command_injection_report.md",
                "severity": "high",
                "weakness_id": 77  # CWE-77: Command Injection
            },
            {
                "title": "SQL Injection in User Query",
                "file": "sql_injection_report.md", 
                "severity": "high",
                "weakness_id": 89  # CWE-89: SQL Injection
            },
            {
                "title": "Cross-Site Scripting in Comment Display",
                "file": "xss_report.md",
                "severity": "medium", 
                "weakness_id": 79  # CWE-79: Cross-site Scripting
            },
            {
                "title": "Weak Cryptographic Implementation",
                "file": "weak_crypto_report.md",
                "severity": "medium",
                "weakness_id": 326  # CWE-326: Inadequate Encryption Strength
            }
        ]
        
        # Submit reports
        submitted_reports = []
        for report in reports:
            try:
                # Validate report file exists
                if not Path(report["file"]).exists():
                    raise FileNotFoundError(f"Report file not found: {report['file']}")
                
                # Read report content
                with open(report["file"], "r") as f:
                    content = f.read()
                
                # Extract impact section
                impact_start = content.find("## Impact")
                if impact_start == -1:
                    logger.error(f"No Impact section found in {report['file']}")
                    continue
                    
                impact_end = content.find("##", impact_start + 1)
                if impact_end == -1:
                    impact_end = len(content)
                impact = content[impact_start:impact_end].strip()
                
                # Submit report
                result = client.submit_report(
                    title=report["title"],
                    vulnerability_info=content,
                    impact=impact,
                    severity=report["severity"],
                    weakness_id=report["weakness_id"]
                )
                
                submitted_reports.append(result)
                logger.info(f"Successfully submitted report: {report['title']}")
                logger.debug(f"Report ID: {result['data']['id']}")
                
            except FileNotFoundError as e:
                logger.error(str(e))
            except KeyError as e:
                logger.error(f"Missing required field in report config: {e}")
            except Exception as e:
                error_msg = f"Failed to submit {report['title']}: {str(e)}"
                logger.error(error_msg)
                logger.debug("Stack trace:", exc_info=True)
                if notifier.webhook_url:
                    notifier.send_notification(error_msg, level='error')
    
        # Check status of submitted reports
        for report in submitted_reports:
            try:
                report_id = report["data"]["id"]
                status = client.check_report_status(report_id)
                logger.info(
                    f"Report {report_id} status: "
                    f"{status['data']['attributes']['state']}"
                )
                
            except KeyError as e:
                logger.error(f"Invalid report response format: {e}")
            except Exception as e:
                logger.error(f"Failed to check status for {report_id}: {str(e)}")
                logger.debug("Stack trace:", exc_info=True)
                
    except ConfigError as e:
        logger.error(f"Configuration Error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        logger.debug("Stack trace:", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
