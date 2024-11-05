#!/usr/bin/env python3

import subprocess
import os
import sys
from pathlib import Path
import re
import logging
import difflib
import shlex
from typing import Dict, List, Optional, Union
import json
from datetime import datetime
import stat
from typing import Dict, List, Optional, Union
import json
from datetime import datetime

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Add file handler to save logs
try:
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    file_handler = logging.FileHandler(log_dir / f"fix_cycle_{datetime.now():%Y%m%d}.log")
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)
except Exception as e:
    logger.warning(f"Failed to set up file logging: {e}")

class FixCycle:
    def __init__(self, files, message, max_attempts=3):
        # Sanitize and validate file paths
        self.files = []
        base_dir = Path.cwd()
        for f in files:
            try:
                path = Path(f).resolve()
                # Prevent path traversal by checking if path is within base directory
                if not str(path).startswith(str(base_dir)):
                    raise ValueError(f"File path {f} must be within the current directory")
                if not path.exists():
                    raise ValueError(f"File not found: {f}")
                if not path.is_file():
                    raise ValueError(f"Path is not a file: {f}")
                if not os.access(path, os.R_OK | os.W_OK):
                    raise PermissionError(f"Insufficient permissions for file: {f}")
                # Validate file extension
                if path.suffix not in {'.py', '.js', '.cpp', '.c', '.h', '.hpp', '.java'}:
                    raise ValueError(f"Unsupported file type: {path.suffix}")
                self.files.append(str(path))
            except Exception as e:
                logger.error(f"Failed to validate file {f}: {e}")
                raise
            
        self.message = message
        self.max_attempts = max_attempts
        self.original_contents = {}
        self._store_original_contents()

    def _store_original_contents(self):
        """Store original file contents for later comparison"""
        for file in self.files:
            try:
                with open(file, 'r') as f:
                    self.original_contents[file] = f.readlines()
            except Exception as e:
                logger.error(f"Failed to read original content of {file}: {e}")

    def _generate_diff_summary(self, file_path):
        """Generate a human-readable summary of changes made to a file"""
        try:
            with open(file_path, 'r') as f:
                new_content = f.readlines()

            original = self.original_contents.get(file_path, [])
            diff = list(difflib.unified_diff(original, new_content, lineterm=''))
            
            if not diff:
                return "No changes made to file."

            changes = {
                'added': [],
                'removed': [],
                'modified': []
            }

            for line in diff:
                if line.startswith('+') and not line.startswith('+++'):
                    changes['added'].append(line[1:].strip())
                elif line.startswith('-') and not line.startswith('---'):
                    changes['removed'].append(line[1:].strip())

            # Identify modified lines (lines that were both removed and added)
            for r_line in changes['removed']:
                for a_line in changes['added']:
                    if difflib.SequenceMatcher(None, r_line, a_line).ratio() > 0.5:
                        changes['modified'].append((r_line, a_line))

            summary = []
            if changes['added']:
                summary.append("\nAdded:")
                for line in changes['added']:
                    if not any(line in mod[1] for mod in changes['modified']):
                        if 'import' in line:
                            summary.append(f"  - New import: {line}")
                        elif 'class' in line:
                            summary.append(f"  - New class: {line.split('class ')[1].split('(')[0]}")
                        elif 'def' in line:
                            summary.append(f"  - New function: {line.split('def ')[1].split('(')[0]}")
                        else:
                            summary.append(f"  - {line[:100]}...")

            if changes['modified']:
                summary.append("\nModified:")
                for old, new in changes['modified']:
                    if 'def' in old and 'def' in new:
                        summary.append(f"  - Updated function: {old.split('def ')[1].split('(')[0]}")
                    elif len(old) < 100:
                        summary.append(f"  - Changed: {old} → {new}")
                    else:
                        summary.append(f"  - Modified long line containing: {old[:50]}...")

            if changes['removed']:
                summary.append("\nRemoved:")
                for line in changes['removed']:
                    if not any(line in mod[0] for mod in changes['modified']):
                        if len(line) < 100:
                            summary.append(f"  - {line}")
                        else:
                            summary.append(f"  - {line[:50]}...")

            return "\n".join(summary)

        except Exception as e:
            return f"Failed to generate diff summary: {e}"

    def run_fix_cycle(self):
        """Run fix cycle using aider with direct message passing"""
        attempts = 0
        while attempts < self.max_attempts:
            logger.info(f"\nAttempt {attempts + 1}/{self.max_attempts}")
            
            try:
                # Apply fixes using aider with direct message passing
                logger.info("Applying fixes with aider")
                logger.info(f"Files to process: {', '.join(self.files)}")
                logger.info(f"Message to aider: {self.message}")
                
                # Construct command with proper escaping
                # Sanitize command arguments
                if not re.match(r'^[a-zA-Z0-9\s\-_.,]+$', self.message):
                    raise ValueError("Message contains invalid characters")
                    
                cmd = ["aider", "--yes-always"]
                cmd.extend(self.files)
                cmd.extend(["--message", self.message])
                
                # Validate each argument
                for arg in cmd:
                    if not isinstance(arg, str) or ';' in arg or '&' in arg or '|' in arg:
                        raise ValueError(f"Invalid command argument: {arg}")
                
                logger.info(f"Executing command: {' '.join(cmd)}")
                
                # Use a more secure subprocess configuration
                # Check if aider is installed
                try:
                    subprocess.run(["aider", "--version"], 
                                 capture_output=True, 
                                 check=True)
                except (subprocess.SubprocessError, FileNotFoundError):
                    logger.error("aider is not installed. Please install it with: pip install aider-chat")
                    return False

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,  # Increased timeout to 5 minutes
                    shell=False,  # Prevent shell injection
                    env=os.environ.copy(),  # Use clean environment
                    cwd=os.getcwd()  # Explicitly set working directory
                )
                
                if result.returncode == 0:
                    logger.info("Aider completed successfully")
                    logger.info("Aider output:")
                    if result.stdout:
                        logger.info(result.stdout)
                    
                    # Generate and log summary of changes
                    logger.info("\nSummary of changes made:")
                    for file in self.files:
                        logger.info(f"\nChanges in {file}:")
                        summary = self._generate_diff_summary(file)
                        logger.info(summary)
                    
                    self._update_changelog()
                    return True
                
                logger.error(f"Aider failed with return code {result.returncode}")
                if result.stdout:
                    logger.error(f"Output: {result.stdout}")
                if result.stderr:
                    logger.error(f"Error: {result.stderr}")
                logger.error("Try running aider manually to debug the issue")
                
            except subprocess.TimeoutExpired:
                logger.error("Fix cycle step timed out")
            except subprocess.CalledProcessError as e:
                logger.error(f"Error during fix cycle: {e}")
                if e.stdout:
                    logger.error(f"Stdout: {e.stdout}")
                if e.stderr:
                    logger.error(f"Stderr: {e.stderr}")
            except Exception as e:
                logger.error(f"Unexpected error: {str(e)}")
            
            attempts += 1
            
        logger.error(f"Fix cycle failed after {attempts} attempts")
        return False

    def _update_changelog(self):
        """Update CHANGELOG.md with fix details"""
        # Sanitize file paths for display
        safe_files = [os.path.basename(f) for f in self.files]
        files_str = ", ".join(safe_files)
        
        # Generate summary of changes for changelog
        changelog_details = []
        for file in self.files:
            summary = self._generate_diff_summary(file)
            if summary and summary != "No changes made to file.":
                changelog_details.append(f"\nChanges in {file}:{summary}")
        
        changelog_entry = f"""
## Security Fix
- Applied security fixes to: {files_str}
- Changes made based on provided instructions
{"".join(changelog_details)}
"""
        changelog_path = Path("CHANGELOG.md").resolve()
        if not changelog_path.parent.samefile(Path.cwd()):
            raise ValueError("CHANGELOG.md must be in current directory")
            
        try:
            # Create with secure permissions if new
            if not changelog_path.exists():
                changelog_path.touch(mode=0o644)
            
            # Verify file permissions
            current_mode = os.stat(changelog_path).st_mode
            if current_mode & (stat.S_IWOTH | stat.S_IWGRP):
                logger.warning("Insecure CHANGELOG.md permissions detected")
                os.chmod(changelog_path, 0o644)
            
            # Validate file size before writing
            if changelog_path.exists() and changelog_path.stat().st_size > 10 * 1024 * 1024:  # 10MB limit
                raise ValueError("Changelog file too large")
                
            # Validate content before writing
            safe_entry = changelog_entry.encode('utf-8', errors='replace').decode('utf-8')
            if len(safe_entry) > 100000:  # Reasonable entry size limit
                raise ValueError("Changelog entry too large")
                
            # Write with exclusive creation for atomic operation
            temp_path = changelog_path.with_suffix('.tmp')
            with open(temp_path, "w") as f:
                f.write(safe_entry)
            temp_path.replace(changelog_path)
        except Exception as e:
            logger.error(f"Failed to update changelog: {e}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Run fix cycle with direct message passing to aider')
    parser.add_argument('files', nargs='*', help='Files to fix')
    parser.add_argument('--message', help='Message to pass directly to aider')
    parser.add_argument('--max-attempts', type=int, default=3, help='Maximum fix attempts')
    
    args = parser.parse_args()
    
    # Default values if not provided
    if not args.files:
        args.files = ['src/agentic_security/fix_cycle.py']  # Default to self
    if not args.message:
        args.message = "Review this code for security issues and propose fixes"
    
    fixer = FixCycle(
        files=args.files,
        message=args.message,
        max_attempts=args.max_attempts
    )
    
    success = fixer.run_fix_cycle()
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())
