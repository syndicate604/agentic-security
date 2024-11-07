import streamlit as st
import sys
import os
from pathlib import Path
import json
from datetime import datetime
import litellm
from typing import Dict, List, Optional
import markdown

# Add parent directory to path to import submit_reports
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
        
        # Code input
        st.subheader("Code to Analyze")
        code = st.text_area("Paste code here", height=200)
        
        # Vulnerability type selection
        vuln_type = st.selectbox(
            "Vulnerability Type",
            ["SQL Injection", "XSS", "Command Injection", "Weak Cryptography"]
        )
        
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
        
        # Display reports in tabs
        if st.session_state.reports:
            tabs = st.tabs([f"Report {i+1}" for i in range(len(st.session_state.reports))])
            
            for i, (tab, report) in enumerate(zip(tabs, st.session_state.reports)):
                with tab:
                    st.subheader(report["title"])
                    st.markdown(report["vulnerability_information"])
                    
                    # Edit report
                    report["title"] = st.text_input("Title", report["title"], key=f"title_{i}")
                    report["severity"] = st.selectbox(
                        "Severity",
                        ["low", "medium", "high", "critical"],
                        index=["low", "medium", "high", "critical"].index(report["severity"]),
                        key=f"severity_{i}"
                    )
        else:
            st.info("No reports generated yet. Go to Analyze page to create reports.")
    
    # Submit page
    elif page == "Submit":
        st.header("Submit Reports")
        
        if not st.session_state.app.api_client:
            st.warning("Please configure API credentials in Settings first.")
            return
        
        if not hasattr(st.session_state, 'reports'):
            st.warning("No reports to submit. Generate reports in the Analyze page first.")
            return
        
        # Display reports for submission
        for i, report in enumerate(st.session_state.reports):
            st.subheader(f"Report {i+1}: {report['title']}")
            submit = st.checkbox(f"Submit Report {i+1}")
            
            if submit:
                try:
                    with st.spinner(f"Submitting report {i+1}..."):
                        response = st.session_state.app.api_client.submit_report(**report)
                        st.success(f"Report {i+1} submitted successfully!")
                        st.json(response)
                except Exception as e:
                    st.error(f"Failed to submit report {i+1}: {str(e)}")

if __name__ == "__main__":
    main()
