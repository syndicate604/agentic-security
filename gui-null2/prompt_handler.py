from string import Template
import streamlit as st
from typing import Dict, Any
from .git_handler import SimpleGitHandler

class PromptHandler:
    def __init__(self):
        self.initialize_session_state()

    def initialize_session_state(self):
        """Initialize session state variables for prompt templates and settings"""
        if 'prompt_templates' not in st.session_state:
            st.session_state.prompt_templates = {
                'default': {
                    'name': 'Default',
                    'template': "${git_context}\n\n**User Query:** ${user_query}\n**AI Response:**"
                }
            }
        
        if 'context_settings' not in st.session_state:
            st.session_state.context_settings = {
                'num_commits': 3,
                'include_status': True,
                'include_branch': True
            }

    def render_prompt_engineering_panel(self, git_handler: SimpleGitHandler):
        """Render the prompt engineering panel in the sidebar."""
        
        # Template Management
        st.markdown("### 🔧 Template Management")
        
        # Template Selection
        selected_template = st.selectbox(
            "Select Template",
            options=list(st.session_state.prompt_templates.keys()),
            key="selected_template"
        )

        # Template Editor
        st.markdown("#### Edit Template")
        template_text = st.text_area(
            "Template Content",
            value=st.session_state.prompt_templates[selected_template]['template'],
            height=150,
            key="template_editor"
        )

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Save Template"):
                st.session_state.prompt_templates[selected_template]['template'] = template_text
                st.success("Template saved!")
        
        with col2:
            new_template_name = st.text_input("New Template Name")
            if st.button("Create New"):
                if new_template_name and new_template_name not in st.session_state.prompt_templates:
                    st.session_state.prompt_templates[new_template_name] = {
                        'name': new_template_name,
                        'template': template_text
                    }
                    st.success(f"Created new template: {new_template_name}")
                else:
                    st.error("Please provide a unique template name")

        # Variables Reference
        st.markdown("### 📝 Available Variables")
        st.code("""
        ${git_context} - Current Git repository context
        ${user_query} - User's input query
        ${branch} - Current Git branch
        ${status} - Git status
        ${commits} - Recent commits
        """)

        # Context Customization
        st.markdown("### 🎯 Context Settings")
        num_commits = st.slider("Number of commits in context", 1, 10, 
                              st.session_state.context_settings['num_commits'])
        include_status = st.checkbox("Include Git status", 
                                   value=st.session_state.context_settings['include_status'])
        include_branch = st.checkbox("Include branch info", 
                                   value=st.session_state.context_settings['include_branch'])

        # Save context settings
        st.session_state.context_settings.update({
            'num_commits': num_commits,
            'include_status': include_status,
            'include_branch': include_branch
        })

        # Preview Section
        st.markdown("### 👁️ Preview")
        if st.button("Generate Preview"):
            preview = self.generate_preview(git_handler, template_text)
            st.code(preview, language='markdown')

        # Export/Import
        self.render_export_import_section()

    def generate_preview(self, git_handler: SimpleGitHandler, template_text: str) -> str:
        """Generate a preview of the prompt template with current context."""
        settings = st.session_state.context_settings
        preview_context = self.generate_context(git_handler, settings)
        
        return Template(template_text).safe_substitute(
            git_context=preview_context,
            user_query="Sample user query"
        )

    def generate_context(self, git_handler: SimpleGitHandler, settings: Dict[str, Any]) -> str:
        """Generate Git context based on current settings."""
        context_parts = []
        
        if settings['include_branch']:
            context_parts.append(f"**Branch:** {git_handler.get_current_branch()}")
        if settings['include_status']:
            context_parts.append(f"**Status:**\n```\n{git_handler.get_status()}\n```")
        
        commits = git_handler.get_recent_commits(settings['num_commits'])
        if commits:
            context_parts.append("**Recent Commits:**")
            for commit in commits:
                context_parts.append(f"- {commit['hash']}: {commit['message']}")
        
        return "\n".join(context_parts)

    def render_export_import_section(self):
        """Render the export/import section for templates."""
        st.markdown("### 💾 Backup/Restore")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Export Templates"):
                import json
                templates_json = json.dumps(st.session_state.prompt_templates, indent=2)
                st.download_button(
                    "Download Templates",
                    templates_json,
                    "prompt_templates.json",
                    "application/json"
                )
        
        with col2:
            uploaded_file = st.file_uploader("Import Templates", type=['json'])
            if uploaded_file is not None:
                try:
                    import json
                    templates = json.load(uploaded_file)
                    st.session_state.prompt_templates.update(templates)
                    st.success("Templates imported successfully!")
                except Exception as e:
                    st.error(f"Error importing templates: {str(e)}")

    def generate_prompt(self, git_handler: SimpleGitHandler, user_input: str) -> str:
        """Generate a prompt using the selected template and context settings."""
        selected_template = st.session_state.prompt_templates[st.session_state.selected_template]
        git_context = self.generate_context(git_handler, st.session_state.context_settings)
        
        template = Template(selected_template['template'])
        return template.safe_substitute(
            git_context=git_context,
            user_query=user_input
        )
