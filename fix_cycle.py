#!/usr/bin/env python3

import os
import json
import uuid
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

def apply_fixes(scan_results: Dict[str, any], auto_commit: bool = False) -> Dict[str, any]:
    """Main function to process and apply security fixes"""
    fix_cycle = FixCycle()
    return fix_cycle.process_fixes(scan_results)
