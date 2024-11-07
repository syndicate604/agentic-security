"""
Configuration settings for the AI Hacker Fix GUI application.
"""

from typing import Dict, Final, List
from pathlib import Path
import os

# Application paths
BASE_DIR: Final[Path] = Path(__file__).parent
REPORTS_DIR: Final[Path] = BASE_DIR / "reports"
CACHE_DIR: Final[Path] = BASE_DIR / ".cache"

# Ensure directories exist
REPORTS_DIR.mkdir(exist_ok=True)
CACHE_DIR.mkdir(exist_ok=True)

# UI Configuration
UI_CONFIG: Final[Dict] = {
    "page_title": "AI Hacker Fix",
    "page_icon": "🛡️",
    "layout": "wide",
    "initial_sidebar_state": "expanded",
    "menu_items": {
        'Get Help': 'https://hackerone.com/security',
        'Report a bug': "https://hackerone.com/security",
        'About': "AI-powered bug bounty submission tool"
    }
}

# Theme Configuration
THEME_CONFIG: Final[Dict] = {
    "base": "dark",
    "primaryColor": "#FF4B4B",
    "backgroundColor": "#0E1117",
    "secondaryBackgroundColor": "#262730",
    "textColor": "#FAFAFA",
    "font": "sans serif"
}

# Custom CSS
CUSTOM_CSS: Final[str] = """
<style>
    /* Main app styling */
    .stApp {
        background-color: #0E1117;
        color: #FAFAFA;
    }
    
    /* Sidebar styling */
    .stSidebar {
        background-color: #262730;
        padding: 1rem;
    }
    
    /* Tabs styling */
    .stTabs {
        background-color: #262730;
        border-radius: 5px;
        padding: 1rem;
    }
    
    /* Button styling */
    .stButton>button {
        background-color: #FF4B4B;
        color: white;
        border: none;
        border-radius: 5px;
        padding: 0.5rem 1rem;
    }
    
    /* Input field styling */
    .stTextInput>div>div>input {
        background-color: #1E2127;
        color: #FAFAFA;
        border: 1px solid #3B3F46;
    }
    
    /* Code block styling */
    .stCodeBlock {
        background-color: #1E2127;
        border: 1px solid #3B3F46;
    }
    
    /* Alert styling */
    .stAlert {
        background-color: #262730;
        border: 1px solid #3B3F46;
    }
</style>
"""

# Vulnerability Types
VULNERABILITY_TYPES: Final[List[str]] = [
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Command Injection",
    "Weak Cryptography",
    "Authentication Bypass",
    "Authorization Bypass",
    "Information Disclosure",
    "Server-Side Request Forgery",
    "XML External Entity (XXE)",
    "Remote Code Execution"
]

# Severity Levels with CVSS Score Ranges
SEVERITY_LEVELS: Final[Dict[str, Dict]] = {
    "critical": {
        "range": (9.0, 10.0),
        "color": "#FF0000",
        "description": "Critical severity issues that require immediate attention"
    },
    "high": {
        "range": (7.0, 8.9),
        "color": "#FF4B4B",
        "description": "High severity issues that should be fixed promptly"
    },
    "medium": {
        "range": (4.0, 6.9),
        "color": "#FFA500",
        "description": "Medium severity issues that should be addressed"
    },
    "low": {
        "range": (0.1, 3.9),
        "color": "#FFD700",
        "description": "Low severity issues that should be fixed when possible"
    }
}

# LiteLLM Configuration
LITELLM_CONFIG: Final[Dict] = {
    "model": "gpt-4",
    "temperature": 0.3,
    "max_tokens": 2000,
    "top_p": 0.95,
    "frequency_penalty": 0.0,
    "presence_penalty": 0.0
}

# API Rate Limits
API_RATE_LIMITS: Final[Dict] = {
    "read": {
        "requests": 600,
        "window": 60  # seconds
    },
    "write": {
        "requests": 25,
        "window": 20  # seconds
    }
}

# Cache Configuration
CACHE_CONFIG: Final[Dict] = {
    "ttl": 3600,  # 1 hour
    "max_size": 100  # Maximum number of items
}

# Report Template
REPORT_TEMPLATE: Final[str] = """
# {title}

## Vulnerability Details
{vulnerability_details}

## Impact
{impact}

## Steps to Reproduce
{steps}

## Proof of Concept
{poc}

## Recommended Fix
{fix}

## CVSS Score
Score: {cvss_score}
Vector: {cvss_vector}

## Additional Information
{additional_info}
"""

# Environment Variables (with defaults)
ENV_CONFIG: Final[Dict] = {
    "HACKERONE_API_USERNAME": os.getenv("HACKERONE_API_USERNAME", ""),
    "HACKERONE_API_TOKEN": os.getenv("HACKERONE_API_TOKEN", ""),
    "OPENAI_API_KEY": os.getenv("OPENAI_API_KEY", ""),
    "LOG_LEVEL": os.getenv("LOG_LEVEL", "INFO"),
    "ENVIRONMENT": os.getenv("ENVIRONMENT", "development")
}

# Logging Configuration
LOGGING_CONFIG: Final[Dict] = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        }
    },
    "handlers": {
        "default": {
            "level": ENV_CONFIG["LOG_LEVEL"],
            "formatter": "standard",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout"
        },
        "file": {
            "level": ENV_CONFIG["LOG_LEVEL"],
            "formatter": "standard",
            "class": "logging.FileHandler",
            "filename": str(BASE_DIR / "app.log"),
            "mode": "a"
        }
    },
    "loggers": {
        "": {
            "handlers": ["default", "file"],
            "level": ENV_CONFIG["LOG_LEVEL"],
            "propagate": True
        }
    }
}
