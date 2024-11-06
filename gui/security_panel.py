import streamlit as st
import datetime
from typing import Dict, List, Optional

def get_ai_security_analysis(scan_results: dict, scan_type: str) -> str:
    """Format security scan results for AI analysis"""
    return f"""Security scan completed ({scan_type}). Please analyze these results:

Scan Summary:
- Total Issues: {scan_results.get('total_issues', 0)}
- Critical: {scan_results.get('critical', 0)}
- High: {scan_results.get('high', 0)}
- Medium: {scan_results.get('medium', 0)}
- Low: {scan_results.get('low', 0)}

Detailed Findings:
```
{scan_results.get('details', '')}
```

Please provide:
1. A severity assessment for each issue
2. Explanation of the security implications
3. Recommended fixes with code examples
4. Best practices to prevent similar issues
5. Any patterns or systemic issues identified

What would you like me to explain first?"""

def render_security_panel(coder=None):
    """Render the security scanning interface"""
    with st.container():
        st.markdown("## Security Scanner")
        
        # Create columns for scan options and configuration
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Scan Options")
            scan_type = st.radio(
                "Select Scan Type",
                ["Quick Scan", "Deep Scan", "Dependency Scan", "Secret Scanner"]
            )
            
            severity = st.select_slider(
                "Minimum Severity",
                options=["Low", "Medium", "High", "Critical"],
                value="Medium"
            )
            
            scan_target = st.radio(
                "Scan Target",
                ["Current Directory", "Selected Files", "Full Project"]
            )
        
        with col2:
            st.markdown("### Configuration")
            ignore_tests = st.checkbox("Ignore Tests", value=True)
            auto_fix = st.checkbox("Auto-fix Issues", value=False)
            include_deps = st.checkbox("Include Dependencies", value=True)
            save_report = st.checkbox("Save Report", value=True)
        
        # Scan button and progress tracking
        if st.button("Start Security Scan", type="primary"):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            # Simulate scan progress
            for i in range(100):
                progress_bar.progress(i + 1)
                if i < 30:
                    status_text.text("Analyzing code structure...")
                elif i < 60:
                    status_text.text("Running security checks...")
                elif i < 90:
                    status_text.text("Processing results...")
                else:
                    status_text.text("Generating report...")
                
            # Display results in tabs
            tab1, tab2, tab3, tab4 = st.tabs([
                "Summary", 
                "Vulnerabilities", 
                "Dependencies",
                "AI Analysis"
            ])
            
            with tab1:
                st.markdown("### Scan Summary")
                metrics_col1, metrics_col2, metrics_col3 = st.columns(3)
                
                with metrics_col1:
                    st.metric("Total Issues", "12")
                with metrics_col2:
                    st.metric("Critical", "2", delta="-1")
                with metrics_col3:
                    st.metric("High", "4", delta="+1")
                
                st.markdown("#### Quick Stats")
                st.json({
                    "Files Scanned": 156,
                    "Lines of Code": 8234,
                    "Scan Duration": "2m 34s",
                    "Issues by Severity": {
                        "Critical": 2,
                        "High": 4,
                        "Medium": 3,
                        "Low": 3
                    }
                })
            
            with tab2:
                st.markdown("### Security Issues")
                
                # Example vulnerabilities
                vulnerabilities = [
                    {
                        "severity": "Critical",
                        "title": "SQL Injection Vulnerability",
                        "file": "app.py",
                        "line": 23,
                        "description": "Unsanitized user input in SQL query"
                    },
                    {
                        "severity": "High",
                        "title": "Insecure Password Storage",
                        "file": "auth.py",
                        "line": 45,
                        "description": "Passwords stored without proper hashing"
                    }
                ]
                
                for vuln in vulnerabilities:
                    with st.container():
                        st.markdown(f"""
                        **{vuln['severity']}: {vuln['title']}**  
                        File: `{vuln['file']}`, Line: {vuln['line']}  
                        {vuln['description']}
                        """)
                        st.divider()
            
            with tab3:
                st.markdown("### Dependency Analysis")
                st.dataframe({
                    "Package": ["requests", "flask", "sqlalchemy"],
                    "Version": ["2.28.1", "2.0.1", "1.4.41"],
                    "Status": ["Up to date", "Update available", "Vulnerable"],
                    "Risk": ["Low", "Medium", "High"]
                })
            
            # Prepare scan results for AI analysis
            scan_results = {
                "total_issues": 12,  # Replace with actual counts
                "critical": metrics_col2._value,
                "high": metrics_col3._value,
                "medium": 3,
                "low": 3,
                "details": "\n".join(
                    f"{vuln['severity']}: {vuln['title']} in {vuln['file']}:{vuln['line']}\n{vuln['description']}"
                    for vuln in vulnerabilities
                )
            }
            
            # Prepare scan results for AI analysis
            ai_prompt = get_ai_security_analysis(scan_results, scan_type)
            
            with tab4:
                st.markdown("### AI Security Analysis")
                
                # Add AI feedback option
                get_feedback = st.checkbox("Get AI Feedback", value=True, key="security_feedback")
                
                if get_feedback and coder:
                    with st.spinner("Analyzing security results..."):
                        # Stream the AI analysis
                        with st.chat_message("assistant"):
                            res = st.write_stream(coder.run_stream(ai_prompt))
                            st.session_state['messages'].append({
                                "role": "assistant", 
                                "content": res
                            })
                else:
                    st.info("✓ Security scan results captured")
                    if not coder:
                        st.warning("AI analysis not available - no aider instance provided")
                st.markdown("The AI assistant will provide:")
                st.markdown("""
                1. **Severity Assessment**
                   - Detailed analysis of each issue
                   - Risk categorization
                
                2. **Security Implications**
                   - Potential exploit scenarios
                   - Impact analysis
                
                3. **Recommended Fixes**
                   - Code-level solutions
                   - Implementation guidance
                   
                4. **Best Practices**
                   - Prevention strategies
                   - Security patterns
                   
                5. **Pattern Analysis**
                   - Common vulnerability types
                   - Systemic issues
                """)
            
            # Generate and download report
            if save_report:
                try:
                    from report_generator import SecurityReportGenerator
                    
                    # Collect all scan data
                    report_data = {
                        'scan_results': scan_results,
                        'vulnerabilities': vulnerabilities,
                        'dependencies': {
                            pkg: {
                                'version': ver,
                                'status': status,
                                'risk': risk
                            } for pkg, ver, status, risk in zip(
                                ["requests", "flask", "sqlalchemy"],
                                ["2.28.1", "2.0.1", "1.4.41"],
                                ["Up to date", "Update available", "Vulnerable"],
                                ["Low", "Medium", "High"]
                            )
                        }
                    }
                    
                    # Get AI analysis if available
                    ai_analysis = ""
                    if get_feedback and coder:
                        analysis_prompt = get_ai_security_analysis(scan_results, scan_type)
                        ai_analysis = coder.run(analysis_prompt)
                    
                    # Generate report
                    generator = SecurityReportGenerator()
                    report_content = generator.generate_report(
                        report_data['scan_results'],
                        report_data['vulnerabilities'],
                        report_data['dependencies'],
                        ai_analysis
                    )
                    
                    # Add report to chat for AI insights
                    if coder:
                        report_prompt = f"""I've generated a security report. Please review and provide:
1. Additional security insights
2. Recommended next steps
3. Risk mitigation strategies
4. Best practices to implement

Report summary:
{json.dumps(report_data, indent=2)}

AI Analysis:
{ai_analysis}
"""
                        with st.spinner("Getting AI insights on report..."):
                            with st.chat_message("assistant"):
                                res = st.write_stream(coder.run_stream(report_prompt))
                                st.session_state['messages'].append({
                                    "role": "assistant",
                                    "content": res
                                })
                    
                    # Offer report download
                    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                    st.download_button(
                        "Download Full Report",
                        report_content,
                        file_name=f"security_report_{timestamp}.pdf",
                        mime="application/pdf"
                    )
                    
                except Exception as e:
                    st.error(f"Error generating report: {str(e)}")
import streamlit as st
import datetime
from typing import Dict, List, Optional

def get_ai_security_analysis(scan_results: dict, scan_type: str) -> str:
    """Format security scan results for AI analysis"""
    return f"""Security scan completed ({scan_type}). Please analyze these results:

Scan Summary:
- Total Issues: {scan_results.get('total_issues', 0)}
- Critical: {scan_results.get('critical', 0)}
- High: {scan_results.get('high', 0)}
- Medium: {scan_results.get('medium', 0)}
- Low: {scan_results.get('low', 0)}

Detailed Findings:
```
{scan_results.get('details', '')}
```

Please provide:
1. A severity assessment for each issue
2. Explanation of the security implications
3. Recommended fixes with code examples
4. Best practices to prevent similar issues
5. Any patterns or systemic issues identified

What would you like me to explain first?"""

def render_security_panel(coder=None):
    """Render the security scanning interface"""
    with st.container():
        st.markdown("## Security Scanner")
        
        # Create columns for scan options and configuration
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Scan Options")
            scan_type = st.radio(
                "Select Scan Type",
                ["Quick Scan", "Deep Scan", "Dependency Scan", "Secret Scanner"]
            )
            
            severity = st.select_slider(
                "Minimum Severity",
                options=["Low", "Medium", "High", "Critical"],
                value="Medium"
            )
            
            scan_target = st.radio(
                "Scan Target",
                ["Current Directory", "Selected Files", "Full Project"]
            )
        
        with col2:
            st.markdown("### Configuration")
            ignore_tests = st.checkbox("Ignore Tests", value=True)
            auto_fix = st.checkbox("Auto-fix Issues", value=False)
            include_deps = st.checkbox("Include Dependencies", value=True)
            save_report = st.checkbox("Save Report", value=True)
        
        # Scan button and progress tracking
        if st.button("Start Security Scan", type="primary"):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            # Simulate scan progress
            for i in range(100):
                progress_bar.progress(i + 1)
                if i < 30:
                    status_text.text("Analyzing code structure...")
                elif i < 60:
                    status_text.text("Running security checks...")
                elif i < 90:
                    status_text.text("Processing results...")
                else:
                    status_text.text("Generating report...")
                
            # Display results in tabs
            tab1, tab2, tab3, tab4 = st.tabs([
                "Summary", 
                "Vulnerabilities", 
                "Dependencies",
                "AI Analysis"
            ])
            
            with tab1:
                st.markdown("### Scan Summary")
                metrics_col1, metrics_col2, metrics_col3 = st.columns(3)
                
                with metrics_col1:
                    st.metric("Total Issues", "12")
                with metrics_col2:
                    st.metric("Critical", "2", delta="-1")
                with metrics_col3:
                    st.metric("High", "4", delta="+1")
                
                st.markdown("#### Quick Stats")
                st.json({
                    "Files Scanned": 156,
                    "Lines of Code": 8234,
                    "Scan Duration": "2m 34s",
                    "Issues by Severity": {
                        "Critical": 2,
                        "High": 4,
                        "Medium": 3,
                        "Low": 3
                    }
                })
            
            with tab2:
                st.markdown("### Security Issues")
                
                # Example vulnerabilities
                vulnerabilities = [
                    {
                        "severity": "Critical",
                        "title": "SQL Injection Vulnerability",
                        "file": "app.py",
                        "line": 23,
                        "description": "Unsanitized user input in SQL query"
                    },
                    {
                        "severity": "High",
                        "title": "Insecure Password Storage",
                        "file": "auth.py",
                        "line": 45,
                        "description": "Passwords stored without proper hashing"
                    }
                ]
                
                for vuln in vulnerabilities:
                    with st.container():
                        st.markdown(f"""
                        **{vuln['severity']}: {vuln['title']}**  
                        File: `{vuln['file']}`, Line: {vuln['line']}  
                        {vuln['description']}
                        """)
                        st.divider()
            
            with tab3:
                st.markdown("### Dependency Analysis")
                st.dataframe({
                    "Package": ["requests", "flask", "sqlalchemy"],
                    "Version": ["2.28.1", "2.0.1", "1.4.41"],
                    "Status": ["Up to date", "Update available", "Vulnerable"],
                    "Risk": ["Low", "Medium", "High"]
                })
            
            # Prepare scan results for AI analysis
            scan_results = {
                "total_issues": 12,  # Replace with actual counts
                "critical": metrics_col2._value,
                "high": metrics_col3._value,
                "medium": 3,
                "low": 3,
                "details": "\n".join(
                    f"{vuln['severity']}: {vuln['title']} in {vuln['file']}:{vuln['line']}\n{vuln['description']}"
                    for vuln in vulnerabilities
                )
            }
            
            # Prepare scan results for AI analysis
            ai_prompt = get_ai_security_analysis(scan_results, scan_type)
            
            with tab4:
                st.markdown("### AI Security Analysis")
                
                # Add AI feedback option
                get_feedback = st.checkbox("Get AI Feedback", value=True, key="security_feedback")
                
                if get_feedback and coder:
                    with st.spinner("Analyzing security results..."):
                        # Stream the AI analysis
                        with st.chat_message("assistant"):
                            res = st.write_stream(coder.run_stream(ai_prompt))
                            st.session_state['messages'].append({
                                "role": "assistant", 
                                "content": res
                            })
                else:
                    st.info("✓ Security scan results captured")
                    if not coder:
                        st.warning("AI analysis not available - no aider instance provided")
                st.markdown("The AI assistant will provide:")
                st.markdown("""
                1. **Severity Assessment**
                   - Detailed analysis of each issue
                   - Risk categorization
                
                2. **Security Implications**
                   - Potential exploit scenarios
                   - Impact analysis
                
                3. **Recommended Fixes**
                   - Code-level solutions
                   - Implementation guidance
                   
                4. **Best Practices**
                   - Prevention strategies
                   - Security patterns
                   
                5. **Pattern Analysis**
                   - Common vulnerability types
                   - Systemic issues
                """)
            
            # Download report button
            if save_report:
                timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                st.download_button(
                    "Download Full Report",
                    "Detailed security report content...",
                    file_name=f"security_report_{timestamp}.pdf",
                    mime="application/pdf"
                )
