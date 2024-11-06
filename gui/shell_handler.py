from typing import Tuple, Optional
import subprocess
from aider.coders import Coder
from aider.models import Model
from aider.io import InputOutput

class AiderShellHandler:
    def __init__(self, coder: Coder):
        """Initialize with an existing coder instance"""
        self.coder = coder
        self.io = coder.commands.io
    
    def run_shell_command(self, command: str, share_output: bool = True) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Execute a shell command and optionally share output with AI
        Returns: Tuple of (stdout, stderr)
        """
        try:
            # Strip /run prefix if present
            if command.startswith('/run '):
                command = command[5:]
            
            # Execute command
            result = subprocess.run(
                command,
                shell=True,
                text=True,
                capture_output=True
            )
            
            # Capture output
            stdout = result.stdout.strip() if result.stdout else None
            stderr = result.stderr.strip() if result.stderr else None
            
            # Share with AI if requested and there's output
            if share_output and (stdout or stderr):
                output = stdout if stdout else stderr
                # Return the output to be handled by GUI's chat system with git-specific handling
                if command.startswith('git '):
                    return stdout, stderr, (
                        f"Git command `{command}` output:\n```\n{output}\n```\n\n"
                        "Would you like me to explain the git status or help with any git operations?"
                    )
                else:
                    return stdout, stderr, f"Command output:\n```\n{output}\n```"
            
            return stdout, stderr, None
            
        except Exception as e:
            error_msg = str(e)
            self.io.tool_error(f"Error executing command: {error_msg}")
            return None, error_msg
    
    def run_with_ai_feedback(self, command: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Run command and get AI feedback on the output
        Returns: Tuple of (stdout, stderr, ai_feedback)
        """
        stdout, stderr, _ = self.run_shell_command(command, share_output=False)
        
        ai_feedback = None
        if stderr:
            ai_feedback = self.coder.run(
                f"There was an error running '{command}':\n```\n{stderr}\n```\n"
                "Can you help fix this?"
            )
        elif stdout:
            ai_feedback = self.coder.run(
                f"I ran '{command}' and got this output:\n```\n{stdout}\n```\n"
                "Can you explain what this means?"
            )
            
        return stdout, stderr, ai_feedback
