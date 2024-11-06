from typing import Tuple, Optional
from datetime import datetime
from pathlib import Path
from aider.coders import Coder
from agentic_security.security_pipeline import SecurityPipeline
from agentic_security.fix_cycle import FixCycle
import json
import os
import subprocess

class SecurityHandler:
    def __init__(self, coder: Coder):
        """Initialize with an existing coder instance"""
        self.coder = coder
        self.io = coder.commands.io
        self.pipeline = SecurityPipeline()
        
        # Tool configurations for dependency checks
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
            
            # Add severity filter
            scan_config["min_severity"] = severity.lower()
            
            # Run the scan
            results = self.pipeline.scan_paths(
                paths=paths,
                auto_fix=False,
                **scan_config
            )
            
            # Generate timestamp for report
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_dir = Path('security_reports')
            report_dir.mkdir(exist_ok=True)
            report_path = str(report_dir / f'security_report_{timestamp}.md')
            
            # Generate report
            self.pipeline.generate_review_report(results, report_path)
            
            # Generate detailed AI analysis message
            vulnerabilities = results.get('vulnerabilities', [])
            stats = {
                "total": len(vulnerabilities),
                "critical": sum(1 for v in vulnerabilities if v.get('severity') == 'critical'),
                "high": sum(1 for v in vulnerabilities if v.get('severity') == 'high'),
                "medium": sum(1 for v in vulnerabilities if v.get('severity') == 'medium'),
                "low": sum(1 for v in vulnerabilities if v.get('severity') == 'low')
            }
            
            chat_msg = (
                f"Security scan completed ({scan_type}).\n\n"
                f"Summary:\n"
                f"- Total Issues: {stats['total']}\n"
                f"- Critical: {stats['critical']}\n"
                f"- High: {stats['high']}\n"
                f"- Medium: {stats['medium']}\n"
                f"- Low: {stats['low']}\n\n"
                f"Report saved to: {report_path}\n\n"
                "I can help you:\n"
                "1. Analyze specific vulnerabilities\n"
                "2. Prioritize issues by risk level\n"
                "3. Suggest detailed fixes with code examples\n"
                "4. Explain security implications\n"
                "5. Recommend best practices\n"
                "6. Identify patterns and systemic issues\n\n"
                "What aspect would you like me to focus on?"
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
