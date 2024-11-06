from typing import Tuple, Optional
import subprocess
import os
from aider.coders import Coder
from aider.models import Model
from aider.io import InputOutput
import shutil

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
                capture_output=True,
                env={**os.environ, "PATH": os.environ.get("PATH", "") + os.pathsep + str(shutil.which("python"))}  # Preserve PATH and add python
            )
            
            # Capture output
            stdout = result.stdout.strip() if result.stdout else None
            stderr = result.stderr.strip() if result.stderr else None
            
            # Share with AI if requested and there's output
            if share_output and (stdout or stderr):
                output = stdout if stdout else stderr
                # Return the output to be handled by GUI's chat system
                # Provide context-aware guidance based on command type
                if command.startswith('git '):
                    return stdout, stderr, (
                        f"Git command `{command}` output:\n```\n{output}\n```\n\n"
                        "Summary of git output:\n"
                        f"- Command executed: {command}\n"
                        f"- Output lines: {len(output.splitlines())}\n"
                        "- Shows repository status and changes\n\n"
                        "I can help you:\n"
                        "- Explain what these changes show\n"
                        "- Suggest next git commands\n"
                        "- Help understand any error messages\n"
                        "\nWhat would you like to know more about?"
                    )
                elif command.startswith('python ') or command.endswith('.py'):
                    return stdout, stderr, (
                        f"Python script `{command}` output:\n```\n{output}\n```\n\n"
                        "Summary of Python execution:\n"
                        f"- Script executed: {command}\n"
                        f"- Output lines: {len(output.splitlines())}\n"
                        "- Contains program output/results\n\n"
                        "I can help you:\n"
                        "- Explain the execution results\n"
                        "- Debug any errors or warnings\n"
                        "- Suggest improvements\n"
                        "\nWhat aspect would you like me to explain?"
                    )
                else:
                    # Provide command-specific guidance
                    if command.startswith('ls'):
                        lines = output.splitlines()
                        file_count = len(lines) - 2 if len(lines) > 2 else 0
                        return stdout, stderr, (
                            f"Command `{command}` output:\n```\n{output}\n```\n\n"
                            "Directory listing summary:\n"
                            f"- Total files/directories: {file_count}\n"
                            "- Shows: permissions, owners, sizes, dates, names\n"
                            f"- Current directory contains {sum(1 for line in lines if line.startswith('-'))} files\n"
                            f"- And {sum(1 for line in lines if line.startswith('d'))} directories\n\n"
                            "I can help you:\n"
                            "- Explain file permissions\n"
                            "- Analyze directory structure\n"
                            "- Suggest organization improvements\n"
                            "\nWhat would you like to know more about?"
                        )
                    else:
                        return stdout, stderr, (
                            f"Command `{command}` output:\n```\n{output}\n```\n\n"
                            "Command execution summary:\n"
                            f"- Command run: {command}\n"
                            f"- Output lines: {len(output.splitlines())}\n"
                            "- Status: {'Error occurred' if stderr else 'Completed successfully'}\n\n"
                            "I can help you:\n"
                            "- Explain the output meaning\n"
                            "- Analyze any warnings/errors\n"
                            "- Suggest related commands\n"
                            "\nWhat would you like to understand better?"
                        )
            
            return stdout, stderr, None
            
        except Exception as e:
            error_msg = str(e)
            self.io.tool_error(f"Error executing command: {error_msg}")
            return None, error_msg
    
    def run_with_ai_feedback(self, command: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Run command and get AI feedback on the output
        Returns: Tuple of (stdout, stderr, chat_msg)
        """
        stdout, stderr, _ = self.run_shell_command(command, share_output=False)
        
        output = stderr if stderr else stdout
        if output:
            if command.startswith('git '):
                chat_msg = (
                    f"Git command `{command}` output:\n```\n{output}\n```\n\n"
                    "Please provide a detailed analysis including:\n"
                    "1. What changes were made or what state is shown\n"
                    "2. Any potential issues or warnings\n"
                    "3. Recommended next steps\n"
                    "4. Best practices relevant to this operation"
                )
            elif command.startswith('python ') or command.endswith('.py'):
                chat_msg = (
                    f"Python script `{command}` output:\n```\n{output}\n```\n\n"
                    "Please provide a detailed analysis including:\n"
                    "1. Execution results and any errors\n"
                    "2. Code quality insights\n"
                    "3. Performance considerations\n"
                    "4. Security implications if relevant"
                )
            else:
                chat_msg = (
                    f"Command `{command}` output:\n```\n{output}\n```\n\n"
                    "Please provide a detailed analysis including:\n"
                    "1. What the output means\n"
                    "2. Any warnings or issues\n"
                    "3. Relevant system implications\n"
                    "4. Suggested follow-up actions"
                )
            return stdout, stderr, chat_msg
        return stdout, stderr, None
