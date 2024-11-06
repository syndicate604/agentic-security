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
                # Enhanced chat message with specific vulnerability guidance
                chat_msg = (
                    f"I've completed a Bandit security scan. Here's the analysis:\n\n"
                    f"```\n{result.stdout.strip()}\n```\n\n"
                    "I can help you address specific vulnerabilities:\n\n"
                    "1. SQL Injection\n"
                    "   - Identify unsafe database queries\n"
                    "   - Convert to parameterized queries\n"
                    "   - Implement proper input validation\n"
                    "   - Add query sanitization\n\n"
                    "2. Command Injection\n"
                    "   - Review subprocess calls\n"
                    "   - Implement safe command execution\n"
                    "   - Add input sanitization\n"
                    "   - Use shell=False in subprocess\n\n"
                    "3. Cross-Site Scripting (XSS)\n"
                    "   - Verify HTML escaping\n"
                    "   - Review template usage\n"
                    "   - Implement Content Security Policy\n"
                    "   - Use secure template engines\n\n"
                    "4. Password Security\n"
                    "   - Check password storage methods\n"
                    "   - Implement proper hashing (bcrypt/Argon2)\n"
                    "   - Add salt to passwords\n"
                    "   - Set up password policies\n\n"
                    "5. Input Validation\n"
                    "   - Review validation logic\n"
                    "   - Implement strong validation\n"
                    "   - Add type checking\n"
                    "   - Sanitize all inputs\n\n"
                    "6. General Security\n"
                    "   - Review error handling\n"
                    "   - Check access controls\n"
                    "   - Audit logging practices\n"
                    "   - Update dependencies\n\n"
                    "Which security issue would you like me to help fix first?"
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
