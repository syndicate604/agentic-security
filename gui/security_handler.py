from typing import Tuple, Optional
import subprocess
from aider.coders import Coder

class SecurityHandler:
    def __init__(self, coder: Coder):
        """Initialize with an existing coder instance"""
        self.coder = coder
        self.io = coder.commands.io
    
    def run_security_scan(self, scan_type: str) -> Tuple[Optional[str], Optional[str]]:
        """Run a basic security scan"""
        try:
            if scan_type == "bandit":
                result = subprocess.run(
                    ["bandit", "-r", "."],
                    capture_output=True,
                    text=True
                )
                return result.stdout.strip(), result.stderr.strip()
            elif scan_type == "safety":
                result = subprocess.run(
                    ["safety", "check"],
                    capture_output=True,
                    text=True
                )
                return result.stdout.strip(), result.stderr.strip()
            return None, "Invalid scan type"
        except Exception as e:
            return None, str(e)
