from typing import Tuple, Optional
import subprocess
from aider.coders import Coder
import json
import os

class SecurityHandler:
    def __init__(self, coder: Coder):
        """Initialize with an existing coder instance"""
        self.coder = coder
        self.io = coder.commands.io
        
        # Map friendly names to command configurations
        self.tool_configs = {
            "Bandit": {
                "command": "bandit",
                "args": ["-r", ".", "-f", "json"],
                "requires": ["bandit"]
            },
            "OWASP ZAP": {
                "command": "zap-cli",
                "args": ["quick-scan", "--self-contained", "--format", "json"],
                "requires": ["zaproxy", "python-owasp-zap-v2.4"]
            },
            "Semgrep": {
                "command": "semgrep",
                "args": ["scan", "--json"],
                "requires": ["semgrep"]
            },
            "GitLeaks": {
                "command": "gitleaks",
                "args": ["detect", "--report-format", "json"],
                "requires": ["gitleaks"]
            },
            "TruffleHog": {
                "command": "trufflehog",
                "args": ["filesystem", ".", "--json"],
                "requires": ["trufflehog"]
            },
            "Safety": {
                "command": "safety",
                "args": ["check", "--json"],
                "requires": ["safety"]
            },
            "PyLint": {
                "command": "pylint",
                "args": [".", "--output-format=json"],
                "requires": ["pylint"]
            },
            "Nuclei": {
                "command": "nuclei",
                "args": ["-target", ".", "-json"],
                "requires": ["nuclei"]
            }
        }
    
    def _check_tool_installed(self, tool_name: str) -> bool:
        """Check if required tool is installed"""
        config = self.tool_configs.get(tool_name)
        if not config:
            return False
            
        for req in config["requires"]:
            try:
                subprocess.run(["pip", "show", req], capture_output=True, check=True)
            except subprocess.CalledProcessError:
                return False
        return True
    
    def run_security_scan(self, tool_name: str, severity: str = "Medium", output_format: str = "JSON") -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Run security scan with specified tool"""
        try:
            # Get tool configuration
            config = self.tool_configs.get(tool_name)
            if not config:
                return None, f"Unknown security tool: {tool_name}", None
                
            # Check if tool is installed
            if not self._check_tool_installed(tool_name):
                install_msg = f"Tool {tool_name} is not installed. Please install required packages:\n"
                for req in config["requires"]:
                    install_msg += f"pip install {req}\n"
                return None, install_msg, None
            
            # Prepare command with args
            cmd = [config["command"]] + config["args"]
            
            # Add severity if supported
            if tool_name in ["Bandit", "Semgrep"]:
                cmd.extend(["--severity", severity.lower()])
            
            # Run the scan
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            # Generate AI analysis message
            chat_msg = (
                f"{tool_name} scan completed.\n\n"
                f"```\n{result.stdout}\n```\n\n"
                "I can help you:\n"
                "1. Analyze the security findings\n"
                "2. Prioritize vulnerabilities\n"
                "3. Suggest fixes for issues found\n"
                "4. Explain specific vulnerability types\n"
                "5. Recommend security best practices\n\n"
                "What would you like me to focus on?"
            )
            
            return result.stdout, result.stderr, chat_msg
            
        except Exception as e:
            error_msg = str(e)
            return None, f"Error running {tool_name} scan: {error_msg}", None
