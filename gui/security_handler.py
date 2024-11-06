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
            
            # Parse and format the scan results
            try:
                # Try to parse JSON output if available
                scan_data = json.loads(result.stdout)
                
                # Format based on tool type
                if tool_name == "Bandit":
                    issues = scan_data.get('results', [])
                    stats = scan_data.get('metrics', {})
                    
                    chat_msg = (
                        f"# {tool_name} Security Scan Results\n\n"
                        f"Found {len(issues)} potential security issues:\n\n"
                        "## Summary\n"
                        f"- Files scanned: {stats.get('_totals', {}).get('loc', 0)}\n"
                        f"- Issues by severity:\n"
                        f"  - HIGH: {sum(1 for i in issues if i.get('issue_severity') == 'HIGH')}\n"
                        f"  - MEDIUM: {sum(1 for i in issues if i.get('issue_severity') == 'MEDIUM')}\n"
                        f"  - LOW: {sum(1 for i in issues if i.get('issue_severity') == 'LOW')}\n\n"
                        "## Detailed Findings\n"
                    )
                    
                    # Add detailed findings
                    for issue in issues:
                        chat_msg += (
                            f"### {issue.get('issue_text', 'Unknown Issue')}\n"
                            f"- Severity: {issue.get('issue_severity', 'Unknown')}\n"
                            f"- Confidence: {issue.get('issue_confidence', 'Unknown')}\n"
                            f"- Location: {issue.get('filename', 'Unknown')}:{issue.get('line_number', 0)}\n"
                            f"- CWE: {issue.get('cwe', {}).get('id', 'N/A')}\n"
                            "```python\n"
                            f"{issue.get('code', 'No code sample available')}\n"
                            "```\n\n"
                        )
                
                elif tool_name == "Safety":
                    vulnerabilities = scan_data
                    
                    chat_msg = (
                        f"# {tool_name} Dependency Scan Results\n\n"
                        f"Found {len(vulnerabilities)} vulnerable dependencies:\n\n"
                    )
                    
                    for vuln in vulnerabilities:
                        chat_msg += (
                            f"### {vuln.get('package', 'Unknown Package')}\n"
                            f"- Installed version: {vuln.get('installed_version', 'Unknown')}\n"
                            f"- Vulnerable below: {vuln.get('vulnerable_below', 'Unknown')}\n"
                            f"- Advisory: {vuln.get('advisory', 'No details available')}\n\n"
                        )
                
                else:
                    # Generic JSON output formatting
                    chat_msg = (
                        f"# {tool_name} Security Scan Results\n\n"
                        "```json\n"
                        f"{json.dumps(scan_data, indent=2)}\n"
                        "```\n\n"
                    )
                
            except json.JSONDecodeError:
                # Fallback for non-JSON output
                chat_msg = (
                    f"# {tool_name} Security Scan Results\n\n"
                    "```\n"
                    f"{result.stdout}\n"
                    "```\n\n"
                )
            
            # Add action items
            chat_msg += (
                "## Next Steps\n\n"
                "I can help you:\n"
                "1. Fix identified vulnerabilities\n"
                "2. Implement security best practices\n"
                "3. Add security tests\n"
                "4. Update vulnerable dependencies\n"
                "5. Explain specific issues in detail\n\n"
                "Which security issue would you like me to address first?"
            )
            
            return result.stdout, result.stderr, chat_msg
            
        except Exception as e:
            error_msg = str(e)
            return None, f"Error running {tool_name} scan: {error_msg}", None
