import streamlit as st
import plotly.express as px
from datetime import datetime
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))
from bounty_hunter import BountyHunter

def render_bounty_search():
    st.title("Bug Bounty Program Search")
    
    # Check for API credentials
    try:
        api_username = st.secrets["HACKERONE_API_USERNAME"]
        api_token = st.secrets["HACKERONE_API_TOKEN"]
        
        if api_username == "your_actual_username" or api_token == "your_actual_token":
            st.error("Please configure your HackerOne API credentials in .streamlit/secrets.toml")
            st.code("""
HACKERONE_API_USERNAME = "your_username"  # Get from HackerOne
HACKERONE_API_TOKEN = "your_token"        # Get from HackerOne
OPENAI_API_KEY = "your_openai_key"        # Get from OpenAI
            """)
            return
            
        # Initialize BountyHunter
        if 'bounty_hunter' not in st.session_state:
            st.session_state.bounty_hunter = BountyHunter(api_username, api_token)
    
        # Sidebar filters
        st.sidebar.header("Filters")
    min_bounty = st.sidebar.number_input("Minimum Bounty ($)", 0, 100000, 100)
    tech_stack = st.sidebar.multiselect(
        "Technology Stack",
        ["Web", "Mobile", "API", "Desktop", "IoT", "Smart Contracts"]
    )
    
    # Main content tabs
    tab1, tab2, tab3 = st.tabs(["Programs", "Analytics", "Recommendations"])
    
    with tab1:
        st.header("Available Programs")
        programs = st.session_state.bounty_hunter.get_programs()
        
        for program in programs:
            with st.expander(program['attributes']['name']):
                st.write("Description:", program['attributes'].get('description', 'N/A'))
                st.write("Bounty Range:", program['attributes'].get('bounty_range', 'N/A'))
                
                if st.button("Analyze Program", key=program['id']):
                    analysis = st.session_state.bounty_hunter.analyze_program(program)
                    st.json(analysis)
    
    with tab2:
        st.header("Program Analytics")
        stats_df = st.session_state.bounty_hunter.get_program_stats()
        
        # Bounty distribution chart
        fig1 = px.histogram(stats_df, x='bounty_range', title='Bounty Range Distribution')
        st.plotly_chart(fig1)
        
        # Response efficiency chart
        fig2 = px.scatter(stats_df, x='launch_date', y='response_efficiency',
                         title='Program Response Efficiency vs Age')
        st.plotly_chart(fig2)
    
    with tab3:
        st.header("AI-Powered Recommendations")
        if st.button("Generate Recommendations"):
            with st.spinner("Analyzing programs..."):
                # Get top programs based on analysis
                programs = st.session_state.bounty_hunter.get_programs()[:5]
                for program in programs:
                    analysis = st.session_state.bounty_hunter.analyze_program(program)
                    st.write(f"### {program['attributes']['name']}")
                    st.write(f"Score: {analysis['score']}/10")
                    st.write(f"Reasoning: {analysis['reasoning']}")
                    st.write(f"Recommended Focus: {analysis['recommended_focus']}")
