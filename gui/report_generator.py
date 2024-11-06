import datetime
from typing import Dict, List, Optional
import json
from fpdf import FPDF

class SecurityReportGenerator:
    def __init__(self):
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        
    def generate_report(self, scan_results: Dict, vulnerabilities: List[Dict], 
                       dependencies: Dict, ai_analysis: str) -> bytes:
        """Generate a comprehensive security report"""
        self.pdf.add_page()
        
        # Title
        self.pdf.set_font("Arial", "B", 16)
        self.pdf.cell(0, 10, "Security Scan Report", ln=True, align="C")
        self.pdf.ln(10)
        
        # Summary section
        self.pdf.set_font("Arial", "B", 14)
        self.pdf.cell(0, 10, "Scan Summary", ln=True)
        self.pdf.set_font("Arial", "", 12)
        self.pdf.multi_cell(0, 10, f"""
        Total Issues: {scan_results.get('total_issues', 0)}
        Critical: {scan_results.get('critical', 0)}
        High: {scan_results.get('high', 0)}
        Medium: {scan_results.get('medium', 0)}
        Low: {scan_results.get('low', 0)}
        """)
        
        # Vulnerabilities section
        self.pdf.add_page()
        self.pdf.set_font("Arial", "B", 14)
        self.pdf.cell(0, 10, "Security Issues", ln=True)
        self.pdf.set_font("Arial", "", 12)
        
        for vuln in vulnerabilities:
            self.pdf.set_font("Arial", "B", 12)
            self.pdf.cell(0, 10, f"{vuln['severity']}: {vuln['title']}", ln=True)
            self.pdf.set_font("Arial", "", 12)
            self.pdf.multi_cell(0, 10, f"""
            File: {vuln['file']}
            Line: {vuln['line']}
            Description: {vuln['description']}
            """)
            self.pdf.ln(5)
        
        # Dependencies section
        self.pdf.add_page()
        self.pdf.set_font("Arial", "B", 14)
        self.pdf.cell(0, 10, "Dependency Analysis", ln=True)
        self.pdf.set_font("Arial", "", 12)
        
        for pkg, details in dependencies.items():
            self.pdf.multi_cell(0, 10, f"""
            Package: {pkg}
            Version: {details.get('version', 'unknown')}
            Status: {details.get('status', 'unknown')}
            Risk: {details.get('risk', 'unknown')}
            """)
            self.pdf.ln(5)
        
        # AI Analysis section
        self.pdf.add_page()
        self.pdf.set_font("Arial", "B", 14)
        self.pdf.cell(0, 10, "AI Security Analysis", ln=True)
        self.pdf.set_font("Arial", "", 12)
        self.pdf.multi_cell(0, 10, ai_analysis)
        
        # Return PDF as bytes
        return self.pdf.output(dest='S').encode('latin1')
