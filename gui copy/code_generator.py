from typing import Dict, List, Optional
import streamlit as st
from aider.coders import Coder

class CodeGeneratorHandler:
    def __init__(self, coder: Coder):
        self.coder = coder
        self.templates = {
            "Python": {
                "Web Frameworks": {
                    "FastAPI": {
                        "Basic API": self._fastapi_basic,
                        "CRUD API": self._fastapi_crud,
                        "Full REST API": self._fastapi_full_rest,
                        "WebSocket Server": self._fastapi_websocket,
                        "Authentication": self._fastapi_auth,
                    },
                    "Flask": {
                        "Basic App": self._flask_basic,
                        "REST API": self._flask_rest,
                        "Database App": self._flask_database,
                    },
                    "Django": {
                        "Basic Project": self._django_basic,
                        "REST API": self._django_rest,
                        "Full Web App": self._django_full,
                    },
                    "Streamlit": {
                        "Data App": self._streamlit_data,
                        "ML App": self._streamlit_ml,
                        "Dashboard": self._streamlit_dashboard,
                    },
                    "Gradio": {
                        "ML Interface": self._gradio_ml,
                        "Audio Processing": self._gradio_audio,
                        "Image Processing": self._gradio_image,
                    }
                },
                "Data Science": {
                    "Pandas Analysis": self._pandas_analysis,
                    "Scikit-learn ML": self._sklearn_ml,
                    "PyTorch Deep Learning": self._pytorch_dl,
                    "TensorFlow Model": self._tensorflow_model,
                },
                "CLI Tools": {
                    "Click App": self._click_cli,
                    "Typer App": self._typer_cli,
                    "ArgParse Tool": self._argparse_tool,
                }
            },
            "JavaScript": {
                "Frontend": {
                    "Next.js": {
                        "Basic App": self._nextjs_basic,
                        "Full Stack": self._nextjs_fullstack,
                        "Static Site": self._nextjs_static,
                    },
                    "React": {
                        "Basic App": self._react_basic,
                        "Redux Setup": self._react_redux,
                        "Component Library": self._react_components,
                    },
                    "Vue.js": {
                        "Basic App": self._vue_basic,
                        "Vuex Store": self._vue_vuex,
                        "Component Set": self._vue_components,
                    }
                },
                "Backend": {
                    "Express.js": {
                        "Basic Server": self._express_basic,
                        "REST API": self._express_rest,
                        "GraphQL": self._express_graphql,
                    },
                    "Deno": {
                        "Basic Server": self._deno_basic,
                        "Oak API": self._deno_oak,
                        "Fresh App": self._deno_fresh,
                    }
                },
                "Full Stack": {
                    "MERN Stack": self._mern_stack,
                    "MEAN Stack": self._mean_stack,
                    "JAMstack": self._jamstack,
                }
            },
            "DevOps": {
                "Docker": {
                    "Basic Setup": self._docker_basic,
                    "Multi-container": self._docker_compose,
                    "Production Ready": self._docker_prod,
                },
                "Kubernetes": {
                    "Basic Deployment": self._k8s_basic,
                    "Microservices": self._k8s_microservices,
                    "StatefulSet": self._k8s_stateful,
                },
                "CI/CD": {
                    "GitHub Actions": self._github_actions,
                    "Jenkins Pipeline": self._jenkins_pipeline,
                    "GitLab CI": self._gitlab_ci,
                }
            }
        }

    def generate_code(self, template_path: List[str], specs: Dict) -> str:
        """
        Generate code based on template path and specifications
        Returns the AI prompt for code generation
        """
        # Navigate to the correct template function
        template = self.templates
        for key in template_path:
            template = template[key]
        
        if callable(template):
            return template(specs)
        raise ValueError("Invalid template path")

    # Template functions that return AI prompts
    def _fastapi_basic(self, specs: Dict) -> str:
        return f"""Please generate a basic FastAPI application with the following specifications:
- Project name: {specs.get('project_name', 'fastapi_app')}
- Include: Basic CORS, error handling, and logging
- API endpoints: Health check, basic CRUD operations
- Project structure: Follow best practices with routes, models, and services separation
- Include requirements.txt and README.md
- Add comprehensive docstrings and type hints
- Include basic unit tests

Please provide the complete code structure with explanations for each component."""

    def _nextjs_basic(self, specs: Dict) -> str:
        return f"""Please generate a Next.js application with the following specifications:
- Project name: {specs.get('project_name', 'nextjs_app')}
- Include: TypeScript configuration
- Features: Basic routing, layout system, and API routes
- State management: React Context or specified solution
- Styling: Tailwind CSS or specified solution
- Include comprehensive documentation
- Add basic testing setup

Please provide the complete code structure with explanations for each component."""

    # Add more template functions here...
    # Each should return a well-structured prompt for the AI

    def get_template_options(self) -> Dict:
        """Return all available template options"""
        return self.templates

def render_code_generator(coder: Coder):
    """Render code generator panel in sidebar"""
    with st.sidebar.expander("Code Generator", expanded=False):
        generator = CodeGeneratorHandler(coder)
        
        # Get all template options
        templates = generator.get_template_options()
        
        # Language selection
        language = st.selectbox(
            "Select Language/Platform",
            options=["Select..."] + list(templates.keys())
        )
        
        if language and language != "Select...":
            # Category selection
            category = st.selectbox(
                "Select Category",
                options=["Select..."] + list(templates[language].keys())
            )
            
            if category and category != "Select...":
                # Framework selection
                framework = st.selectbox(
                    "Select Framework",
                    options=["Select..."] + list(templates[language][category].keys())
                )
                
                if framework and framework != "Select...":
                    # Template selection
                    template = st.selectbox(
                        "Select Template",
                        options=["Select..."] + list(templates[language][category][framework].keys())
                    )
                    
                    if template and template != "Select...":
                        # Specifications input
                        st.markdown("### Project Specifications")
                        specs = {
                            "project_name": st.text_input("Project Name", "my_app"),
                            "description": st.text_area("Description", "A new project"),
                            "features": st.multiselect(
                                "Features",
                                ["Authentication", "Database", "API", "Testing", "Docker", "CI/CD"]
                            ),
                            "advanced_options": st.checkbox("Include Advanced Options")
                        }
                        
                        if st.button("Generate Code"):
                            try:
                                # Generate the prompt
                                prompt = generator.generate_code(
                                    [language, category, framework, template],
                                    specs
                                )
                                
                                # Add to chat as a new message
                                st.session_state['messages'] = st.session_state.get('messages', [])
                                st.session_state['messages'].append({
                                    "role": "system",
                                    "content": "Code Generator activated"
                                })
                                st.session_state['messages'].append({
                                    "role": "user",
                                    "content": prompt
                                })
                                
                                st.success("Code generation prompt added to chat!")
                                st.info("Please check the chat for the generated code and instructions.")
                                
                            except Exception as e:
                                st.error(f"Error generating code: {str(e)}")
        
        # Help text
        with st.expander("Code Generator Help", expanded=False):
            st.markdown("""
            ### How to use the Code Generator
            
            1. Select your preferred language/platform
            2. Choose a category (e.g., Web Frameworks, Data Science)
            3. Select a framework
            4. Pick a template
            5. Fill in the specifications
            6. Click 'Generate Code'
            
            The AI will provide:
            - Complete project structure
            - Required files and configurations
            - Documentation and examples
            - Best practices and recommendations
            
            **Note**: The generated code will be added to the chat where you can:
            - Review the code
            - Ask for modifications
            - Get explanations
            - Request additional features
            """)
