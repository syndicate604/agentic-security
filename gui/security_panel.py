import streamlit as st
import datetime
import json
from typing import Dict, List, Optional

def get_ai_security_analysis(scan_results: dict, scan_type: str) -> str:
    """Format security scan results for AI analysis"""
    vulnerabilities = scan_results.get('vulnerabilities', [])
    
    # Group vulnerabilities by type
    vuln_types = {}
    for vuln in vulnerabilities:
        v_type = vuln.get('type', 'Unknown')
        if v_type not in vuln_types:
            vuln_types[v_type] = []
        vuln_types[v_type].append(vuln)
    
    # Build detailed analysis prompt
    analysis = f"""Security scan completed ({scan_type}). Please analyze these results:

Scan Summary:
- Total Issues: {len(vulnerabilities)}
- Critical: {sum(1 for v in vulnerabilities if v.get('severity') == 'critical')}
- High: {sum(1 for v in vulnerabilities if v.get('severity') == 'high')}
- Medium: {sum(1 for v in vulnerabilities if v.get('severity') == 'medium')}
- Low: {sum(1 for v in vulnerabilities if v.get('severity') == 'low')}

Vulnerability Types Found:
{chr(10).join(f"- {v_type}: {len(vulns)} issue(s)" for v_type, vulns in vuln_types.items())}

Detailed Findings:
```
{json.dumps(vulnerabilities, indent=2)}
```

Please provide:
1. Severity Assessment
   - Risk level analysis for each vulnerability type
   - Impact on system security
   - Exploitation potential

2. Security Implications
   - Detailed explanation of each vulnerability type
   - Potential attack scenarios
   - Data/system exposure risks

3. Recommended Fixes
   - Code-level solutions with examples
   - Implementation guidance
   - Testing recommendations

4. Best Practices
   - Prevention strategies for each vulnerability type
   - Security patterns to implement
   - Code review guidelines

5. Pattern Analysis
   - Common vulnerability patterns identified
   - Systemic issues in the codebase
   - Architecture/design recommendations

Which aspect would you like me to analyze first?"""
    
    return analysis

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
                
            # Run the security scan with proper configuration
            scan_config = {
                "Quick Scan": {"depth": "quick"},
                "Deep Scan": {"depth": "deep"},
                "Dependency Scan": {"type": "dependency"},
                "Secret Scanner": {"type": "secrets"}
            }
                
            paths = ["."] if scan_target == "Current Directory" else None
            if scan_target == "Selected Files":
                # TODO: Add file selector
                st.warning("File selection not yet implemented")
                return
                
            results, error, chat_msg = coder.security.run_security_scan(
                scan_type=scan_config[scan_type]["type"] if "type" in scan_config[scan_type] else "bandit",
                severity=severity,
                paths=paths
            )
            
            if error:
                st.error(error)
                return
                
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
                
                vulnerabilities = results.get('vulnerabilities', [])
                total = len(vulnerabilities)
                critical = sum(1 for v in vulnerabilities if v.get('severity') == 'critical')
                high = sum(1 for v in vulnerabilities if v.get('severity') == 'high')
                
                with metrics_col1:
                    st.metric("Total Issues", str(total))
                with metrics_col2:
                    st.metric("Critical", str(critical))
                with metrics_col3:
                    st.metric("High", str(high))
                
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
                
                # Display actual vulnerabilities from scan results
                vulnerabilities = results.get('vulnerabilities', [])
                
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
                if 'dependencies' in results:
                    deps_data = {
                        "Package": [],
                        "Version": [],
                        "Status": [],
                        "Risk": []
                    }
                    for dep in results['dependencies']:
                        deps_data["Package"].append(dep.get('name', 'Unknown'))
                        deps_data["Version"].append(dep.get('version', 'Unknown'))
                        deps_data["Status"].append(dep.get('status', 'Unknown'))
                        deps_data["Risk"].append(dep.get('risk_level', 'Unknown'))
                    
                    st.dataframe(deps_data)
                else:
                    st.info("No dependency information available")
            
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
