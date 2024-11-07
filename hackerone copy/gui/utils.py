"""
Utility functions for the AI Hacker Fix GUI application.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union
import markdown
import re
from config import (
    REPORTS_DIR,
    CACHE_DIR,
    SEVERITY_LEVELS,
    VULNERABILITY_TYPES,
    REPORT_TEMPLATE
)

logger = logging.getLogger(__name__)

def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to be safe for filesystem operations.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '', filename)
    # Replace spaces with underscores
    filename = filename.replace(' ', '_')
    return filename.lower()

def save_report(report: Dict, report_id: Optional[str] = None) -> str:
    """
    Save a report to the filesystem.
    
    Args:
        report: Report data dictionary
        report_id: Optional report ID (generated if not provided)
        
    Returns:
        Report ID
    """
    if not report_id:
        report_id = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    filepath = REPORTS_DIR / f"{sanitize_filename(report_id)}.json"
    
    try:
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"Saved report to {filepath}")
        return report_id
    except Exception as e:
        logger.error(f"Failed to save report: {str(e)}")
        raise

def load_report(report_id: str) -> Dict:
    """
    Load a report from the filesystem.
    
    Args:
        report_id: Report ID to load
        
    Returns:
        Report data dictionary
    """
    filepath = REPORTS_DIR / f"{sanitize_filename(report_id)}.json"
    
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load report: {str(e)}")
        raise

def list_reports() -> List[str]:
    """
    List all saved reports.
    
    Returns:
        List of report IDs
    """
    return [f.stem for f in REPORTS_DIR.glob('*.json')]

def calculate_cvss_score(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str
) -> float:
    """
    Calculate CVSS 3.1 score based on metrics.
    
    Args:
        attack_vector: Network, Adjacent, Local, Physical
        attack_complexity: Low, High
        privileges_required: None, Low, High
        user_interaction: None, Required
        scope: Unchanged, Changed
        confidentiality: None, Low, High
        integrity: None, Low, High
        availability: None, Low, High
        
    Returns:
        CVSS score (0.0-10.0)
    """
    # Implement CVSS 3.1 calculation logic
    # This is a simplified version
    impact_scores = {
        'None': 0,
        'Low': 0.22,
        'High': 0.56
    }
    
    base_score = (
        impact_scores[confidentiality] +
        impact_scores[integrity] +
        impact_scores[availability]
    ) / 3 * 10
    
    # Adjust for attack complexity
    if attack_complexity == 'High':
        base_score *= 0.8
    
    return round(base_score, 1)

def get_severity_from_cvss(score: float) -> str:
    """
    Get severity level from CVSS score.
    
    Args:
        score: CVSS score (0.0-10.0)
        
    Returns:
        Severity level (critical, high, medium, low)
    """
    for level, config in SEVERITY_LEVELS.items():
        min_score, max_score = config['range']
        if min_score <= score <= max_score:
            return level
    return 'low'

def format_report(report: Dict) -> str:
    """
    Format report data into markdown.
    
    Args:
        report: Report data dictionary
        
    Returns:
        Formatted markdown string
    """
    return REPORT_TEMPLATE.format(**report)

def markdown_to_html(markdown_text: str) -> str:
    """
    Convert markdown to HTML with syntax highlighting.
    
    Args:
        markdown_text: Markdown formatted text
        
    Returns:
        HTML formatted text
    """
    return markdown.markdown(
        markdown_text,
        extensions=['fenced_code', 'codehilite']
    )

def cache_result(key: str, data: Dict):
    """
    Cache analysis results.
    
    Args:
        key: Cache key
        data: Data to cache
    """
    filepath = CACHE_DIR / f"{sanitize_filename(key)}.json"
    
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        logger.error(f"Failed to cache result: {str(e)}")

def get_cached_result(key: str) -> Optional[Dict]:
    """
    Get cached analysis result.
    
    Args:
        key: Cache key
        
    Returns:
        Cached data or None if not found
    """
    filepath = CACHE_DIR / f"{sanitize_filename(key)}.json"
    
    if not filepath.exists():
        return None
    
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load cached result: {str(e)}")
        return None

def validate_report(report: Dict) -> List[str]:
    """
    Validate report data.
    
    Args:
        report: Report data to validate
        
    Returns:
        List of validation errors (empty if valid)
    """
    errors = []
    
    required_fields = [
        'title',
        'vulnerability_details',
        'impact',
        'steps',
        'poc',
        'fix'
    ]
    
    for field in required_fields:
        if field not in report or not report[field]:
            errors.append(f"Missing required field: {field}")
    
    if 'severity' in report:
        if report['severity'] not in SEVERITY_LEVELS:
            errors.append(f"Invalid severity level: {report['severity']}")
    
    if 'vulnerability_type' in report:
        if report['vulnerability_type'] not in VULNERABILITY_TYPES:
            errors.append(f"Invalid vulnerability type: {report['vulnerability_type']}")
    
    return errors

def clean_cache():
    """Clean old cache files."""
    try:
        for file in CACHE_DIR.glob('*.json'):
            if (datetime.now() - datetime.fromtimestamp(file.stat().st_mtime)).days > 7:
                file.unlink()
    except Exception as e:
        logger.error(f"Failed to clean cache: {str(e)}")

def export_report(report: Dict, format: str = 'md') -> Union[str, bytes]:
    """
    Export report in various formats.
    
    Args:
        report: Report data
        format: Export format (md, html, pdf)
        
    Returns:
        Formatted report content
    """
    if format == 'md':
        return format_report(report)
    elif format == 'html':
        return markdown_to_html(format_report(report))
    else:
        raise ValueError(f"Unsupported export format: {format}")
