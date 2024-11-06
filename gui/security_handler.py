from typing import Tuple, Optional
from datetime import datetime
from aider.coders import Coder
from agentic_security.security_pipeline import SecurityPipeline
from agentic_security.fix_cycle import FixCycle
import json
import os

class SecurityHandler:
    def __init__(self, coder: Coder):
        """Initialize with an existing coder instance"""
        self.coder = coder
        self.io = coder.commands.io
        self.pipeline = SecurityPipeline()
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
    
    def run_security_scan(self, scan_type: str, severity: str = "Medium", paths: list = None) -> Tuple[Optional[dict], Optional[str], Optional[str]]:
        """Run security scan using SecurityPipeline"""
        try:
            if not paths:
                paths = ['.']
                
            # Convert scan_type to appropriate configuration
            scan_config = {
                "Quick Scan": {"depth": "quick"},
                "Deep Scan": {"depth": "deep"},
                "Dependency Scan": {"type": "dependency"},
                "Secret Scanner": {"type": "secrets"}
            }.get(scan_type, {"depth": "quick"})
            
            # Run the scan
            results = self.pipeline.scan_paths(
                paths=paths,
                auto_fix=False,
                **scan_config
            )
            
            # Generate timestamp for report
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_path = f'security_reports/security_report_{timestamp}.md'
            os.makedirs('security_reports', exist_ok=True)
            
            # Generate report
            self.pipeline.generate_review_report(results, report_path)
            
            # Generate AI analysis message
            chat_msg = (
                f"Security scan completed ({scan_type}).\n\n"
                f"Report saved to: {report_path}\n\n"
                "I can help you:\n"
                "1. Analyze the security findings\n"
                "2. Prioritize vulnerabilities\n"
                "3. Suggest fixes for issues found\n"
                "4. Explain specific vulnerability types\n"
                "5. Recommend security best practices\n\n"
                "What would you like me to focus on?"
            )
            
            return results, None, chat_msg
            
        except Exception as e:
            error_msg = str(e)
            return None, f"Error running security scan: {error_msg}", None
            
    def apply_fixes(self, files: list, message: str = None, max_attempts: int = 3) -> bool:
        """Apply security fixes using FixCycle"""
        try:
            fixer = FixCycle(
                files=files,
                message=message or "Review this code for security issues and propose fixes following security best practices.",
                max_attempts=max_attempts
            )
            return fixer.run_fix_cycle()
        except Exception as e:
            self.io.tool_error(f"Error applying fixes: {str(e)}")
            return False
