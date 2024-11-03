#!/usr/bin/env python3

import os
import json
import uuid
import subprocess
import difflib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union
import logging

logger = logging.getLogger(__name__)

class FixCycle:
    def __init__(self, reports_dir: str = "security_reports"):
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.fix_id = str(uuid.uuid4())[:8]
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    def process_fixes(self, scan_results: Dict[str, any]) -> Dict[str, any]:
        """Process security scan results and generate fixes"""
        fixes_applied = []
        
        try:
            # Process each vulnerability
            for vuln_type, findings in scan_results.items():
                if isinstance(findings, list):
                    for finding in findings:
                        fix = self._generate_fix(finding)
                        if fix:
                            fixes_applied.append(fix)
                            
            # Generate report
            report = {
                'fix_id': self.fix_id,
                'timestamp': self.timestamp,
                'fixes_applied': fixes_applied,
                'original_findings': scan_results
            }
            
            # Save report
            self._save_report(report)
            
            return report
            
        except Exception as e:
            logger.error(f"Error processing fixes: {str(e)}")
            return {
                'fix_id': self.fix_id,
                'timestamp': self.timestamp,
                'error': str(e),
                'fixes_applied': fixes_applied
            }

    def _generate_fix(self, finding: Dict) -> Optional[Dict]:
        """Generate fix instructions based on vulnerability type"""
        if not isinstance(finding, dict):
            return None
            
        file_path = finding.get('file')
        vuln_type = finding.get('type')
        
        if not file_path or not vuln_type:
            return None
            
        fix_instructions = {
            'sql_injection': {
                'message': 'Use parameterized queries instead of string formatting',
                'fixes': [
                    'Replace string formatting with query parameters',
                    'Use prepared statements',
                    'Implement proper input validation'
                ]
            },
            'command_injection': {
                'message': 'Secure command execution',
                'fixes': [
                    'Use subprocess.run with shell=False',
                    'Implement strict input validation',
                    'Use allowlist for permitted commands'
                ]
            },
            'xss': {
                'message': 'Prevent cross-site scripting',
                'fixes': [
                    'Implement proper HTML escaping',
                    'Use Content Security Policy',
                    'Validate and sanitize user input'
                ]
            },
            'weak_crypto': {
                'message': 'Strengthen cryptographic implementation',
                'fixes': [
                    'Use strong hashing algorithms (SHA-256/512)',
                    'Implement proper key management',
                    'Use secure random number generation'
                ]
            },
            'insecure_deserialization': {
                'message': 'Secure deserialization',
                'fixes': [
                    'Use safe serialization formats',
                    'Implement strict input validation',
                    'Avoid using pickle with untrusted data'
                ]
            }
        }
        
        if vuln_type in fix_instructions:
            return {
                'file': file_path,
                'type': vuln_type,
                'severity': finding.get('severity', 'medium'),
                'instructions': fix_instructions[vuln_type],
                'original_finding': finding
            }
        
        return None

    def _save_report(self, report: Dict) -> None:
        """Save fix report to security_reports directory"""
        report_file = self.reports_dir / f"security_fix_{self.timestamp}_{self.fix_id}.json"
        
        try:
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Fix report saved to {report_file}")
        except Exception as e:
            logger.error(f"Error saving fix report: {str(e)}")

    def run_fix_cycle(self, files: List[str], message: str, max_attempts: int = 3) -> bool:
        """Run fix cycle using aider with direct message passing"""
        attempts = 0
        while attempts < max_attempts:
            logger.info(f"\nAttempt {attempts + 1}/{max_attempts}")
            
            try:
                # Apply fixes using aider with direct message passing
                logger.info("Applying fixes with aider")
                result = subprocess.run([
                    "aider",
                    "--yes-always",
                    *files,
                    "--message", message
                ], capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    logger.info("Aider completed successfully")
                    
                    # Generate and log summary of changes
                    logger.info("\nSummary of changes made:")
                    for file in files:
                        logger.info(f"\nChanges in {file}:")
                        summary = self._generate_diff_summary(file)
                        logger.info(summary)
                    
                    self._update_changelog()
                    return True
                
                logger.error(f"Aider failed with return code {result.returncode}")
                if result.stderr:
                    logger.error(f"Stderr: {result.stderr}")
                
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

    def _generate_diff_summary(self, file_path: str) -> str:
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

            # Identify modified lines
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

    def _update_changelog(self) -> None:
        """Update CHANGELOG.md with fix details"""
        files_str = ", ".join(self.files)
        
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
        try:
            with open("CHANGELOG.md", "a") as f:
                f.write(changelog_entry)
        except Exception as e:
            logger.error(f"Failed to update changelog: {e}")

def apply_fixes(scan_results: Dict[str, any], auto_commit: bool = False) -> Dict[str, any]:
    """Main function to process and apply security fixes"""
    fix_cycle = FixCycle()
    return fix_cycle.process_fixes(scan_results)
