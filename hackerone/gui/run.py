#!/usr/bin/env python3
"""
Run script for the AI Hacker Fix GUI application.
This script handles environment setup and launches the Streamlit app.
"""

import os
import sys
from pathlib import Path
import logging
import subprocess
import argparse
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

def check_dependencies():
    """Check if all required dependencies are installed"""
    try:
        import streamlit
        import litellm
        import markdown
        logger.info("All required dependencies are installed")
        return True
    except ImportError as e:
        logger.error(f"Missing dependency: {str(e)}")
        return False

def install_dependencies():
    """Install required dependencies"""
    requirements_file = Path(__file__).parent / "requirements.txt"
    
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
        ])
        logger.info("Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install dependencies: {str(e)}")
        return False

def setup_environment():
    """Setup environment variables and directories"""
    # Load environment variables
    env_file = Path(__file__).parent.parent / ".env"
    load_dotenv(env_file)
    
    # Create required directories
    from config import REPORTS_DIR, CACHE_DIR
    REPORTS_DIR.mkdir(exist_ok=True)
    CACHE_DIR.mkdir(exist_ok=True)
    
    # Verify required environment variables
    required_vars = [
        "HACKERONE_API_USERNAME",
        "HACKERONE_API_TOKEN",
        "OPENAI_API_KEY"
    ]
    
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    if missing_vars:
        logger.warning(f"Missing environment variables: {', '.join(missing_vars)}")
        logger.warning("Some features may not work without these variables")

def run_app(port: int = 8501, debug: bool = False):
    """
    Run the Streamlit application
    
    Args:
        port: Port number to run the app on
        debug: Enable debug mode
    """
    app_path = Path(__file__).parent / "app.py"
    
    # Build Streamlit command
    command = [
        "streamlit",
        "run",
        str(app_path),
        "--server.port", str(port)
    ]
    
    if debug:
        os.environ["STREAMLIT_DEBUG"] = "true"
        command.append("--logger.level=debug")
    
    try:
        logger.info(f"Starting AI Hacker Fix on port {port}")
        subprocess.run(command)
    except KeyboardInterrupt:
        logger.info("Shutting down AI Hacker Fix")
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        sys.exit(1)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Run AI Hacker Fix GUI")
    parser.add_argument(
        "--port",
        type=int,
        default=8501,
        help="Port to run the application on"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode"
    )
    parser.add_argument(
        "--install-deps",
        action="store_true",
        help="Install dependencies before running"
    )
    
    args = parser.parse_args()
    
    # Install dependencies if requested
    if args.install_deps:
        if not install_dependencies():
            sys.exit(1)
    
    # Check dependencies
    if not check_dependencies():
        logger.error("Please install required dependencies")
        logger.error("Run with --install-deps to install automatically")
        sys.exit(1)
    
    # Setup environment
    setup_environment()
    
    # Run application
    run_app(port=args.port, debug=args.debug)

if __name__ == "__main__":
    main()
