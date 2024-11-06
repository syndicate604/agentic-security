from typing import Tuple, Optional
import subprocess
from aider.coders import Coder

class SecurityHandler:
    def __init__(self, coder: Coder):
        """Initialize with an existing coder instance"""
        self.coder = coder
        self.io = coder.commands.io
    
    def run_security_scan(self, scan_type: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Run a basic security scan"""
        try:
            if scan_type == "bandit":
                result = subprocess.run(
                    ["bandit", "-r", "."],
                    capture_output=True,
                    text=True
                )
                # Enhanced chat message for Bandit results
                chat_msg = (
                    f"I've completed a Bandit security scan. Here's the analysis:\n\n"
                    f"```\n{result.stdout.strip()}\n```\n\n"
                    "I can help you:\n"
                    "1. Explain any security issues found\n"
                    "2. Prioritize vulnerabilities by severity\n"
                    "3. Suggest specific fixes for each issue\n"
                    "4. Recommend security best practices\n"
                    "5. Help implement the fixes\n\n"
                    "What would you like me to focus on?"
                )
                return result.stdout.strip(), result.stderr.strip(), chat_msg
                
            elif scan_type == "safety":
                result = subprocess.run(
                    ["safety", "check"],
                    capture_output=True,
                    text=True
                )
                # Enhanced chat message for Safety results
                chat_msg = (
                    f"I've completed a Safety dependency scan. Here's the analysis:\n\n"
                    f"```\n{result.stdout.strip()}\n```\n\n"
                    "I can help you:\n"
                    "1. Explain any vulnerable dependencies found\n"
                    "2. Suggest safe version upgrades\n"
                    "3. Evaluate the impact of these vulnerabilities\n"
                    "4. Create a remediation plan\n"
                    "5. Help update your requirements.txt\n\n"
                    "What aspects would you like me to address?"
                )
                return result.stdout.strip(), result.stderr.strip(), chat_msg
                
            return None, "Invalid scan type", None
        except Exception as e:
            error_msg = str(e)
            chat_msg = (
                f"There was an error running the {scan_type} scan:\n\n"
                f"```\n{error_msg}\n```\n\n"
                "I can help you:\n"
                "1. Troubleshoot the scan error\n"
                "2. Check if the security tool is installed correctly\n"
                "3. Suggest alternative security checks\n"
                "4. Help set up the security scanning environment\n\n"
                "How would you like to proceed?"
            )
            return None, error_msg, chat_msg
