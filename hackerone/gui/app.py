import streamlit as st
import sys
import os
from pathlib import Path
import json
from datetime import datetime
import litellm
from typing import Dict, List, Optional
import markdown
from bounty_hunter import BountyHunter

def render_markdown_report(report: dict) -> None:
    """Render a report in markdown format with proper formatting"""
    st.markdown(f"""
    # {report['title']}
    
    **Severity:** {report.get('severity', 'Not set')}  
    **Status:** {report.get('status', 'Draft')}  
    **Type:** {report.get('vulnerability_type', 'Not specified')}
    
    ## Description
    {report.get('vulnerability_information', 'No description available')}
    
    ## Impact
    {report.get('impact', 'No impact statement available')}
    
    {f"**Submission ID:** {report.get('submission_id')}" if report.get('submission_id') else ''}
    """)

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

def init_session_state():
    """Initialize session state variables"""
    if 'reports' not in st.session_state:
        st.session_state.reports = []
    if 'app' not in st.session_state:
        st.session_state.app = AIHackerFix()

def main():
    # Initialize session state
    init_session_state()
    
    st.title("🛡️ AI Hacker Fix")
    
    # Initialize app state
    if 'app' not in st.session_state:
        st.session_state.app = AIHackerFix()
    
    # Sidebar navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio("Go to", ["Settings", "Analyze", "Reports", "Bounty Search", "Submit"])
    
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
        
        # Create tabs for reports and bounty search
        reports_tab, bounty_tab = st.tabs(["My Reports", "Bounty Programs"])
        
        with reports_tab:
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
                    render_markdown_report(report)
                    
                    # Edit options 
                    with st.form(f"edit_form_{i}"):
                        report["title"] = st.text_input("Title", report["title"])
                        report["severity"] = st.select_slider(
                            "Severity",
                            options=["none", "low", "medium", "high", "critical"],
                            value=report.get("severity", "medium")
                        )
                        
                        # Action buttons
                        col1, col2 = st.columns(2)
                        with col1:
                            if st.form_submit_button("Save Changes"):
                                st.success("Changes saved!")
                        with col2:
                            if st.form_submit_button("Delete Report"):
                                st.session_state.reports.remove(report)
                                st.success("Report deleted!")
                                st.rerun()
        else:
            st.info("No reports generated yet. Go to Analyze page to create reports.")
    
    # Submit page
    elif page == "Bounty Search":
        st.title("🎯 Bug Bounty Program Search")
        
        # Debug output for secrets
        st.write("Checking API credentials...")
        try:
            api_username = st.secrets["HACKERONE_API_USERNAME"]
            api_token = st.secrets["HACKERONE_API_TOKEN"]
            
            # Show partial credentials for debugging
            st.write(f"Username: {api_username[:3]}...")
            st.write(f"Token: {api_token[:5]}...")
            
            if api_username and api_token:
                st.success("API credentials found")
            else:
                st.error("API credentials are empty")
                st.stop()
        except Exception as e:
            st.error(f"Error accessing secrets: {str(e)}")
            st.stop()
        
        # Initialize BountyHunter
        if 'bounty_hunter' not in st.session_state:
            st.session_state.bounty_hunter = BountyHunter(api_username, api_token)

        # Simple search first
        st.subheader("Basic Program Search")
        
        # Initialize session state for pagination
        if 'page' not in st.session_state:
            st.session_state.page = 1
        if 'programs' not in st.session_state:
            st.session_state.programs = []
        
        # Fetch programs button
        if st.button("Fetch All Programs") or not st.session_state.programs:
            with st.spinner("Fetching programs..."):
                st.session_state.programs = st.session_state.bounty_hunter.get_programs()
                st.success(f"Found {len(st.session_state.programs)} programs")
        
        # Display programs with pagination
        if st.session_state.programs:
            # Pagination controls
            items_per_page = 10
            total_pages = (len(st.session_state.programs) + items_per_page - 1) // items_per_page
            
            col1, col2, col3 = st.columns([1,3,1])
            with col1:
                if st.button("Previous") and st.session_state.page > 1:
                    st.session_state.page -= 1
            with col2:
                st.write(f"Page {st.session_state.page} of {total_pages}")
            with col3:
                if st.button("Next") and st.session_state.page < total_pages:
                    st.session_state.page += 1
            
            # Display current page of programs
            start_idx = (st.session_state.page - 1) * items_per_page
            end_idx = min(start_idx + items_per_page, len(st.session_state.programs))
            
            for program in st.session_state.programs[start_idx:end_idx]:
                with st.expander(f"🎯 {program['attributes'].get('name', 'Unnamed Program')}", expanded=False):
                    # Program header
                    st.markdown(f"""
                    ### Program Details
                    **Program:** [{program['attributes']['name']}]({program['attributes'].get('website', '')})  
                    **Bounty Range:** {program['attributes']['bounty_range']}  
                    **Response Rate:** {program['attributes'].get('response_efficiency', 0)}%  
                    **Resolved Reports:** {program['attributes'].get('resolved_reports', 0)}
                    
                    **Launch Date:** {program['attributes'].get('launch_date', 'Not available')}  
                    **Last Updated:** {program['attributes'].get('last_updated', 'Not available')}  
                    **Status:** {program['attributes'].get('submission_state', 'Unknown')}
                    
                    ### Description
                    {program['attributes'].get('description', 'No description available')}
                    
                    ### Scope
                    """)
                    
                    # Display scopes in a table
                    scopes = program['attributes'].get('scopes', [])
                    if scopes:
                        scope_data = []
                        for scope in scopes:
                            scope_data.append({
                                "Type": scope['type'],
                                "Target": scope['identifier'],
                                "Bounty Eligible": "✅" if scope['eligible_for_bounty'] else "❌"
                            })
                        st.table(scope_data)
                    else:
                        st.info("No scope information available")
                    
                    # Action buttons
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button("View Details", key=f"view_{program['id']}"):
                            st.json(program)
                    with col2:
                        if st.button("Analyze", key=f"analyze_{program['id']}"):
                            with st.spinner("Analyzing program..."):
                                analysis = st.session_state.bounty_hunter.analyze_program(program)
                                st.markdown(analysis)
        
        # Advanced search section
        st.subheader("Advanced Search")
        with st.expander("Advanced Search Options"):
            col1, col2 = st.columns(2)
            with col1:
                min_bounty = st.number_input("Minimum Bounty ($)", 0, 100000, 100)
                max_response_time = st.slider("Max Response Time (days)", 1, 30, 7)
                program_types = st.multiselect(
                    "Program Types",
                    ["Public", "Private", "Enterprise"],
                    default=["Public"]
                )
            with col2:
                min_resolved = st.number_input("Minimum Resolved Reports", 0, 1000, 10)
                min_response_rate = st.slider("Minimum Response Rate (%)", 0, 100, 50)
                
        # Technology stack filter
        tech_stack = st.multiselect(
            "Technology Stack",
            ["Web", "Mobile", "API", "Desktop", "IoT", "Smart Contracts", 
             "Android", "iOS", "Cloud", "Blockchain", "Network"],
            default=["Web", "API"]
        )
        
        # Vulnerability focus
        vuln_types = st.multiselect(
            "Vulnerability Types",
            ["RCE", "SQLi", "XSS", "CSRF", "SSRF", "File Upload", 
             "Authentication", "Authorization", "Information Disclosure"],
            default=["RCE", "SQLi", "XSS"]
        )
        
        if st.button("Search Programs", type="primary"):
            with st.spinner("Searching and analyzing programs..."):
                try:
                    programs = st.session_state.bounty_hunter.get_programs()
                    
                    # Filter programs based on criteria
                    filtered_programs = []
                    for program in programs:
                        attrs = program['attributes']
                        
                        # Parse bounty range
                        try:
                            min_program_bounty = int(''.join(filter(str.isdigit, 
                                attrs.get('bounty_range', '0').split('-')[0])))
                        except:
                            min_program_bounty = 0
                        
                        # Check if program matches criteria
                        if (min_program_bounty >= min_bounty and
                            attrs.get('response_efficiency_percentage', 0) >= min_response_rate and
                            attrs.get('resolved_report_count', 0) >= min_resolved and
                            any(tech.lower() in attrs.get('description', '').lower() 
                                for tech in tech_stack)):
                            filtered_programs.append(program)
                    
                    st.success(f"Found {len(filtered_programs)} matching programs")
                    
                    # Display results
                    for program in filtered_programs:
                        with st.expander(f"🎯 {program['attributes']['name']}", expanded=False):
                            # Program details
                            st.markdown(f"""
                            ### Program Overview
                            **Bounty Range:** {program['attributes'].get('bounty_range', 'N/A')}  
                            **Response Rate:** {program['attributes'].get('response_efficiency_percentage', 'N/A')}%  
                            **Resolved Reports:** {program['attributes'].get('resolved_report_count', 'N/A')}
                            
                            ### Description
                            {program['attributes'].get('description', 'No description available')}
                            """)
                            
                            # AI Analysis
                            if st.button("Generate AI Analysis", key=f"ai_{program['id']}"):
                                with st.spinner("Analyzing program..."):
                                    analysis = st.session_state.bounty_hunter.analyze_program(program)
                                    st.markdown(analysis)
                            
                            # Action buttons
                            col1, col2 = st.columns(2)
                            with col1:
                                if st.button("Save Program", key=f"save_{program['id']}"):
                                    if 'saved_programs' not in st.session_state:
                                        st.session_state.saved_programs = []
                                    st.session_state.saved_programs.append(program)
                                    st.success("Program saved!")
                            
                            with col2:
                                if st.button("Create Report Template", key=f"template_{program['id']}"):
                                    template = {
                                        "title": f"Security Vulnerability in {program['attributes']['name']}",
                                        "program": program['attributes']['name'],
                                        "severity": "medium",
                                        "vulnerability_information": "## Description\n\n[Add details]\n\n",
                                        "impact": "## Impact\n\n[Add impact]\n\n",
                                        "status": "Draft"
                                    }
                                    if not hasattr(st.session_state, 'reports'):
                                        st.session_state.reports = []
                                    st.session_state.reports.append(template)
                                    st.success("Report template created!")
                                    
                except Exception as e:
                    st.error(f"Search failed: {str(e)}")

    elif page == "Submit":
        st.header("Submit Reports")
        
        try:
            # Get API credentials from secrets.toml
            api_username = st.secrets["HACKERONE_API_USERNAME"]
            api_token = st.secrets["HACKERONE_API_TOKEN"]
            
            # Add program matching section
            st.subheader("Program Matching")
            if hasattr(st.session_state, 'reports') and st.session_state.reports:
                unsubmitted_reports = [r for r in st.session_state.reports if r.get('status') != 'Submitted']
                
                if unsubmitted_reports:
                    st.info("Finding best matching programs for your reports...")
                    
                    for report in unsubmitted_reports:
                        with st.expander(f"🎯 Matches for: {report['title']}", expanded=False):
                            try:
                                programs = st.session_state.bounty_hunter.get_programs()
                                matches = []
                                
                                for program in programs:
                                    # Basic matching based on vulnerability type and tech stack
                                    if (report.get('vulnerability_type', '').lower() in 
                                        program['attributes'].get('description', '').lower()):
                                        matches.append(program)
                                
                                if matches:
                                    st.success(f"Found {len(matches)} potential matching programs")
                                    for program in matches:
                                        st.markdown(f"""
                                        ### {program['attributes']['name']}
                                        **Bounty Range:** {program['attributes'].get('bounty_range', 'N/A')}
                                        
                                        **Match Reason:** Vulnerability type matches program scope
                                        """)
                                else:
                                    st.warning("No direct matches found. Consider reviewing program scopes manually.")
                                    
                            except Exception as e:
                                st.error(f"Failed to find matches: {str(e)}")
            
            # Initialize API client if not already done
            if not hasattr(st.session_state, 'api_client'):
                st.session_state.api_client = HackerOneAPI(api_username, api_token)
            
            # Display submission queue
            st.subheader("Reports Queue")
            if not hasattr(st.session_state, 'reports') or not st.session_state.reports:
                st.warning("No reports to submit. Generate reports in the Analyze page first.")
                st.info("Go to the Analyze page to create new vulnerability reports.")
                return
                
            # Create tabs for different views
            queue_tab, history_tab = st.tabs(["Submission Queue", "Submission History"])
            
            with queue_tab:
                for i, report in enumerate(st.session_state.reports):
                    if report.get('status') != 'Submitted':  # Only show unsubmitted reports
                        with st.expander(f"📝 Report {i+1}: {report['title']}", expanded=False):
                            # Report metadata
                            cols = st.columns(3)
                            with cols[0]:
                                st.markdown(f"**Severity:** {report.get('severity', 'Not set')}")
                            with cols[1]:
                                st.markdown(f"**Type:** {report.get('vulnerability_type', 'Not specified')}")
                            with cols[2]:
                                st.markdown(f"**Status:** {report.get('status', 'Draft')}")
                            
                            # Report content preview
                            st.markdown("### Description")
                            st.markdown(report.get("vulnerability_information", "No description available"))
                            
                            st.markdown("### Impact")
                            st.markdown(report.get("impact", "No impact statement available"))
                            
                            # Edit options
                            with st.form(f"edit_form_{i}"):
                                report['title'] = st.text_input("Title", report['title'])
                                report['severity'] = st.select_slider(
                                    "Severity",
                                    options=["none", "low", "medium", "high", "critical"],
                                    value=report.get('severity', 'medium')
                                )
                                
                                col1, col2 = st.columns(2)
                                with col1:
                                    if st.form_submit_button("Save Changes"):
                                        st.success("Changes saved!")
                                        
                                with col2:
                                    if st.form_submit_button("Submit to HackerOne"):
                                        try:
                                            with st.spinner("Submitting report..."):
                                                response = st.session_state.api_client.submit_report(
                                                    title=report['title'],
                                                    vulnerability_info=report.get('vulnerability_information', ''),
                                                    impact=report.get('impact', ''),
                                                    severity=report.get('severity', 'medium')
                                                )
                                                report['status'] = 'Submitted'
                                                report['submission_id'] = response.get('data', {}).get('id')
                                                st.success("Report submitted successfully!")
                                                st.json(response)
                                        except Exception as e:
                                            st.error(f"Failed to submit report: {str(e)}")
            
            with history_tab:
                st.subheader("Submission History")
                submitted_reports = [r for r in st.session_state.reports if r.get('status') == 'Submitted']
                
                if not submitted_reports:
                    st.info("No reports have been submitted yet.")
                else:
                    for i, report in enumerate(submitted_reports):
                        with st.expander(f"✅ {report['title']}", expanded=False):
                            render_markdown_report(report)
                            
                            if st.button(f"Check Status {i}", key=f"check_status_{i}"):
                                try:
                                    status = st.session_state.api_client.check_report_status(
                                        report['submission_id']
                                    )
                                    st.json(status)
                                except Exception as e:
                                    st.error(f"Failed to check status: {str(e)}")
                                    
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
