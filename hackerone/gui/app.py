import streamlit as st
import sys
import os
from pathlib import Path
import json
from datetime import datetime
import litellm
from typing import Dict, List, Optional
import markdown

# Add parent directory to Python path
sys.path.append(str(Path(__file__).parent.parent))
from submit_reports import HackerOneAPI

# Configure page and theme
st.set_page_config(
    page_title="AI Hacker Fix",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://hackerone.com/security',
        'Report a bug': "https://hackerone.com/security",
        'About': "AI-powered bug bounty submission tool"
    }
)

# Apply dark theme
st.markdown("""
<style>
    .stApp {
        background-color: #0E1117;
        color: #FAFAFA;
    }
    .stSidebar {
        background-color: #262730;
    }
    .stTabs {
        background-color: #262730;
    }
</style>
""", unsafe_allow_html=True)

class AIHackerFix:
    def __init__(self):
        self.api_client = None
        self.reports = []
        
    def init_api_client(self, username: str, token: str):
        """Initialize HackerOne API client"""
        self.api_client = HackerOneAPI(username, token)
    
    def analyze_vulnerability(self, code: str, vulnerability_type: str) -> Dict:
        """Use LiteLLM to analyze vulnerability and suggest fixes"""
        prompt = f"""
        Analyze the following code for {vulnerability_type} vulnerability:
        
        ```
        {code}
        ```
        
        Provide:
        1. Vulnerability description
        2. Security impact
        3. Steps to reproduce
        4. Recommended fix
        5. CVSS score and vector
        """
        
        response = litellm.completion(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3
        )
        
        return {
            "analysis": response.choices[0].message.content,
            "timestamp": datetime.now().isoformat()
        }
    
    def generate_report(self, analysis: Dict) -> Dict:
        """Generate HackerOne report from analysis"""
        # Parse analysis into report sections
        sections = analysis["analysis"].split("\n\n")
        
        return {
            "title": f"Security Vulnerability: {sections[0]}",
            "vulnerability_information": markdown.markdown(analysis["analysis"]),
            "impact": sections[2] if len(sections) > 2 else "",
            "severity": "medium",  # Default to medium, can be adjusted
            "weakness_id": None  # Can be mapped based on vulnerability type
        }

def main():
    # Initialize session state
    init_session_state()
    
    st.title("🛡️ AI Hacker Fix")
    
    # Initialize app state
    if 'app' not in st.session_state:
        st.session_state.app = AIHackerFix()
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ["Settings", "Analyze", "Reports", "Submit"])
    
    # Settings page
    if page == "Settings":
        st.header("Settings")
        
        # API Configuration
        st.subheader("HackerOne API Configuration")
        api_username = st.text_input("API Username", type="password")
        api_token = st.text_input("API Token", type="password")
        
        if st.button("Save Credentials"):
            try:
                st.session_state.app.init_api_client(api_username, api_token)
                st.success("API credentials saved!")
            except Exception as e:
                st.error(f"Failed to initialize API client: {str(e)}")
        
        # LiteLLM Configuration
        st.subheader("AI Configuration")
        litellm_key = st.text_input("OpenAI API Key", type="password")
        if st.button("Save AI Config"):
            os.environ["OPENAI_API_KEY"] = litellm_key
            st.success("AI configuration saved!")
    
    # Analyze page
    elif page == "Analyze":
        st.header("Analyze Vulnerability")
        
        # Add sample code selector
        st.subheader("Select Sample or Enter Code")
        sample_option = st.selectbox(
            "Choose a sample or enter your own code",
            ["Custom Code", "SQL Injection Sample", "Command Injection Sample", "XSS Sample", "Weak Crypto Sample"]
        )
        
        # Sample code dictionary
        sample_codes = {
            "SQL Injection Sample": """
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()
            """,
            
            "Command Injection Sample": """
def process_user_input(user_input):
    command = f"echo {user_input}"
    os.system(command)
            """,
            
            "XSS Sample": """
def display_comment(comment):
    return f"<div>{comment}</div>"  # Unsanitized output
            """,
            
            "Weak Crypto Sample": """
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
            """
        }
        
        # Code input
        if sample_option == "Custom Code":
            code = st.text_area("Paste code here", height=200)
        else:
            code = st.text_area("Code to Analyze", value=sample_codes[sample_option], height=200)
        
        # Vulnerability type selection
        vuln_type = st.selectbox(
            "Vulnerability Type",
            ["SQL Injection", "XSS", "Command Injection", "Weak Cryptography"]
        )
        
        # Auto-select vulnerability type based on sample
        if sample_option != "Custom Code":
            vuln_type = sample_option.replace(" Sample", "")
        
        if st.button("Analyze"):
            with st.spinner("Analyzing vulnerability..."):
                try:
                    analysis = st.session_state.app.analyze_vulnerability(
                        code, vuln_type
                    )
                    st.session_state.last_analysis = analysis
                    st.success("Analysis complete!")
                    
                    # Display analysis
                    st.subheader("Analysis Results")
                    st.markdown(analysis["analysis"])
                    
                    # Generate report
                    report = st.session_state.app.generate_report(analysis)
                    st.session_state.reports.append(report)
                    
                except Exception as e:
                    st.error(f"Analysis failed: {str(e)}")
    
    # Reports page
    elif page == "Reports":
        st.header("Vulnerability Reports")
        
        if not hasattr(st.session_state, 'reports'):
            st.session_state.reports = []
        
        # Add report filtering/sorting options
        col1, col2 = st.columns(2)
        with col1:
            sort_by = st.selectbox(
                "Sort by",
                ["Newest First", "Oldest First", "Severity", "Vulnerability Type"]
            )
        with col2:
            filter_type = st.multiselect(
                "Filter by Type",
                ["SQL Injection", "XSS", "Command Injection", "Weak Cryptography"],
                default=[]
            )
        
        # Display reports in an organized way
        if st.session_state.reports:
            # Sort reports based on selection
            reports = st.session_state.reports.copy()
            if sort_by == "Newest First":
                reports.reverse()
            elif sort_by == "Severity":
                severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                reports.sort(key=lambda x: severity_order.get(x.get("severity", "low"), 4))
            
            # Filter reports if filters are selected
            if filter_type:
                reports = [r for r in reports if any(vt in r.get("title", "") for vt in filter_type)]
            
            # Display reports in expandable sections
            for i, report in enumerate(reports):
                with st.expander(f"Report {i+1}: {report['title']}", expanded=False):
                    # Report metadata
                    cols = st.columns(3)
                    with cols[0]:
                        st.markdown(f"**Severity:** {report.get('severity', 'Not set')}")
                    with cols[1]:
                        st.markdown(f"**Type:** {report.get('vulnerability_type', 'Not specified')}")
                    with cols[2]:
                        st.markdown(f"**Status:** {report.get('status', 'Draft')}")
                    
                    # Report content
                    st.markdown("### Description")
                    st.markdown(report.get("vulnerability_information", "No description available"))
                    
                    st.markdown("### Impact")
                    st.markdown(report.get("impact", "No impact statement available"))
                    
                    # Edit options
                    st.markdown("### Edit Report")
                    report["title"] = st.text_input("Title", report["title"], key=f"title_{i}")
                    report["severity"] = st.select_slider(
                        "Severity",
                        options=["low", "medium", "high", "critical"],
                        value=report.get("severity", "medium"),
                        key=f"severity_{i}"
                    )
                    
                    # Action buttons
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        if st.button("Save Changes", key=f"save_{i}"):
                            st.success("Changes saved!")
                    with col2:
                        if st.button("Export Report", key=f"export_{i}"):
                            # Add export functionality
                            st.download_button(
                                "Download Report",
                                report_to_markdown(report),
                                file_name=f"vulnerability_report_{i}.md",
                                mime="text/markdown"
                            )
                    with col3:
                        if st.button("Delete Report", key=f"delete_{i}"):
                            if st.session_state.reports.remove(report):
                                st.success("Report deleted!")
                                st.rerun()
        else:
            st.info("No reports generated yet. Go to Analyze page to create reports.")
    
    # Submit page
    elif page == "Submit":
        st.header("Submit Reports")
        
        try:
            # Get API credentials from secrets.toml
            api_username = st.secrets["HACKERONE_API_USERNAME"]
            api_token = st.secrets["HACKERONE_API_TOKEN"]
            
            # Initialize API client if not already done
            if not hasattr(st.session_state, 'api_client'):
                st.session_state.api_client = HackerOneAPI(api_username, api_token)
            
            if not hasattr(st.session_state, 'reports'):
                st.warning("No reports to submit. Generate reports in the Analyze page first.")
                return
            
            # Display reports for submission
            for i, report in enumerate(st.session_state.reports):
                with st.expander(f"Report {i+1}: {report['title']}", expanded=False):
                    # Show report details
                    st.markdown(f"**Severity:** {report.get('severity', 'Not specified')}")
                    st.markdown(f"**Type:** {report.get('vulnerability_type', 'Not specified')}")
                    
                    # Preview section
                    if st.checkbox(f"Preview Report {i+1}", key=f"preview_{i}"):
                        st.markdown("### Description")
                        st.markdown(report.get("vulnerability_information", "No description available"))
                        st.markdown("### Impact")
                        st.markdown(report.get("impact", "No impact statement available"))
                    
                    # Submit button
                    if st.button(f"Submit Report {i+1}", key=f"submit_{i}"):
                        try:
                            with st.spinner(f"Submitting report {i+1}..."):
                                response = st.session_state.api_client.submit_report(
                                    title=report['title'],
                                    vulnerability_info=report.get('vulnerability_information', ''),
                                    impact=report.get('impact', ''),
                                    severity=report.get('severity', 'medium')
                                )
                                st.success(f"Report {i+1} submitted successfully!")
                                st.json(response)
                                
                                # Update report status
                                report['status'] = 'Submitted'
                                report['submission_id'] = response.get('data', {}).get('id')
                                
                        except Exception as e:
                            st.error(f"Failed to submit report {i+1}: {str(e)}")
                            
        except Exception as e:
            if "HACKERONE_API_USERNAME" not in st.secrets or "HACKERONE_API_TOKEN" not in st.secrets:
                st.error("HackerOne API credentials not found in .streamlit/secrets.toml")
                st.markdown("""
                Please add your HackerOne API credentials to `.streamlit/secrets.toml`:
                ```toml
                HACKERONE_API_USERNAME = "your_username"
                HACKERONE_API_TOKEN = "your_token"
                ```
                """)
            else:
                st.error(f"Error initializing API client: {str(e)}")

def report_to_markdown(report: dict) -> str:
    """Convert report to markdown format"""
    return f"""# Vulnerability Report: {report['title']}

## Severity
{report.get('severity', 'Not specified').title()}

## Description
{report.get('vulnerability_information', 'No description available')}

## Impact
{report.get('impact', 'No impact statement available')}

## Status
{report.get('status', 'Draft')}
"""

if __name__ == "__main__":
    main()
