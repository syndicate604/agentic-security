import streamlit as st
from aider.coders import Coder

def render_prompt_engineering_panel(coder: Coder):
    """Render the prompt engineering panel with various templates and options"""
    
    # Prompt templates
    templates = {
        "Chain of Thought": {
            "description": "Break down complex problems step by step",
            "template": """Let's approach this step by step:
1. First, let's understand what we need to do
2. Then break it down into smaller tasks
3. Finally implement each part systematically""",
            "use_cases": "Complex problems, debugging, architecture decisions"
        },
        "Expert Role": {
            "description": "Assume specific expertise for specialized tasks",
            "template": """Act as an expert {role} with deep experience in {domain}.
Focus on {specific_aspect} while considering best practices.""",
            "use_cases": "Security reviews, optimization, architecture design"
        },
        "Context Enhanced": {
            "description": "Provide rich context for better understanding",
            "template": """Given this context:
- Project: {project_type}
- Language: {language}
- Framework: {framework}
- Requirements: {requirements}

Please help with: {request}""",
            "use_cases": "Project-specific tasks, framework integration"
        },
        "Comparative Analysis": {
            "description": "Compare multiple approaches or solutions",
            "template": """Let's compare these approaches:

1. Option A: {option_a}
   Pros:
   Cons:

2. Option B: {option_b}
   Pros:
   Cons:

Recommendation based on {criteria}:""",
            "use_cases": "Technology choices, architecture decisions"
        }
    }
    
    # Template selection
    selected_template = st.selectbox(
        "Select Prompt Template",
        options=["Select..."] + list(templates.keys())
    )
    
    if selected_template and selected_template != "Select...":
        template_info = templates[selected_template]
        
        # Show template info
        st.markdown(f"### {selected_template}")
        st.markdown(f"**Description:** {template_info['description']}")
        st.markdown(f"**Use Cases:** {template_info['use_cases']}")
        
        # Template customization
        st.markdown("### Customize Template")
        
        if selected_template == "Expert Role":
            role = st.text_input("Expert Role", "software architect")
            domain = st.text_input("Domain", "system design")
            aspect = st.text_input("Specific Aspect", "scalability")
            
            prompt = template_info["template"].format(
                role=role,
                domain=domain,
                specific_aspect=aspect
            )
            
        elif selected_template == "Context Enhanced":
            project_type = st.text_input("Project Type", "web application")
            language = st.text_input("Language", "Python")
            framework = st.text_input("Framework", "FastAPI")
            requirements = st.text_area("Requirements", "Build a secure API...")
            request = st.text_area("Specific Request", "Help implement...")
            
            prompt = template_info["template"].format(
                project_type=project_type,
                language=language,
                framework=framework,
                requirements=requirements,
                request=request
            )
            
        elif selected_template == "Comparative Analysis":
            option_a = st.text_area("Option A", "REST API")
            option_b = st.text_area("Option B", "GraphQL")
            criteria = st.text_input("Comparison Criteria", "scalability, maintainability")
            
            prompt = template_info["template"].format(
                option_a=option_a,
                option_b=option_b,
                criteria=criteria
            )
            
        else:
            prompt = template_info["template"]
        
        # Display generated prompt
        st.markdown("### Generated Prompt")
        st.code(prompt, language="text")
        
        # Add to chat button
        if st.button("Add to Chat"):
            # Create a formatted message
            formatted_prompt = (
                f"Using {selected_template} template:\n\n"
                f"{prompt}\n\n"
                "Please proceed with this template to help structure our interaction."
            )
            
            # Add to chat via coder's message system
            if hasattr(coder, 'add_to_chat'):
                coder.add_to_chat(formatted_prompt)
            elif hasattr(coder, 'messages'):
                coder.messages.append({
                    "role": "user",
                    "content": formatted_prompt
                })
            
            st.success("✓ Prompt added to chat! Please submit to process.")
            
            # Set the prompt in the parent GUI
            if 'prompt' in st.session_state:
                st.session_state.prompt = formatted_prompt
