from typing import Dict, List, Tuple
import subprocess
import shutil
from aider.coders import Coder
import streamlit as st

class ConfigHandler:
    def __init__(self, coder: Coder):
        self.coder = coder
        self.tool_configs = {
            "Security Tools": {
                "OWASP ZAP": {
                    "pip": ["python-owasp-zap-v2.4", "zaproxy"],
                    "check_cmd": "zap-cli --version",
                    "description": "Dynamic security testing tool"
                },
                "Bandit": {
                    "pip": ["bandit"],
                    "check_cmd": "bandit --version",
                    "description": "Python security linter"
                },
                "Semgrep": {
                    "pip": ["semgrep"],
                    "check_cmd": "semgrep --version",
                    "description": "Static analysis tool"
                },
                "GitLeaks": {
                    "pip": ["gitleaks"],
                    "check_cmd": "gitleaks version",
                    "description": "Secret scanner"
                }
            },
            "Development Tools": {
                "PyLint": {
                    "pip": ["pylint"],
                    "check_cmd": "pylint --version",
                    "description": "Python code quality checker"
                },
                "Safety": {
                    "pip": ["safety"],
                    "check_cmd": "safety --version",
                    "description": "Dependency vulnerability checker"
                }
            },
            "System Tools": {
                "Docker": {
                    "system": True,
                    "check_cmd": "docker --version",
                    "install_cmd": {
                        "ubuntu": "sudo apt-get install -y docker.io",
                        "macos": "brew install docker",
                        "windows": "choco install docker-desktop"
                    },
                    "description": "Container platform"
                },
                "Git": {
                    "system": True,
                    "check_cmd": "git --version",
                    "install_cmd": {
                        "ubuntu": "sudo apt-get install -y git",
                        "macos": "brew install git",
                        "windows": "choco install git"
                    },
                    "description": "Version control system"
                }
            }
        }

    def check_tool(self, tool_name: str, config: Dict) -> bool:
        """Check if a tool is installed"""
        try:
            check_cmd = config["check_cmd"].split()
            result = subprocess.run(check_cmd, capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def install_tool(self, tool_name: str, config: Dict) -> Tuple[bool, str]:
        """Install a tool"""
        try:
            if config.get("pip"):
                # Install Python packages
                cmd = ["pip", "install", "--quiet"] + config["pip"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                return result.returncode == 0, result.stderr if result.stderr else "Installation successful"
            elif config.get("system"):
                # For system tools, return installation instructions
                return False, "Please install using system package manager"
            return False, "Unknown installation method"
        except Exception as e:
            return False, str(e)

    def get_system_info(self) -> Dict:
        """Get basic system information"""
        info = {}
        try:
            # Python version
            result = subprocess.run(["python", "--version"], capture_output=True, text=True)
            info["Python"] = result.stdout.strip()
            
            # Pip version
            result = subprocess.run(["pip", "--version"], capture_output=True, text=True)
            info["Pip"] = result.stdout.strip()
            
            # Git version
            result = subprocess.run(["git", "--version"], capture_output=True, text=True)
            info["Git"] = result.stdout.strip()
        except:
            pass
        return info

def render_config_panel(coder: Coder):
    """Render configuration management panel"""
    with st.sidebar:
        config_handler = ConfigHandler(coder)
        
        # Main configuration tabs
        system_tab, tools_tab, help_tab = st.tabs(["System", "Tools", "Help"])
        
        # System Information Tab
        with system_tab:
            st.markdown("### System Information")
            sys_info = config_handler.get_system_info()
            for key, value in sys_info.items():
                st.text(f"{key}: {value}")
        
        # Tools Tab        
        with tools_tab:
            # Tool Categories in Sub-tabs
            categories = list(config_handler.tool_configs.keys())
            category_tabs = st.tabs(categories)
            
            for cat_tab, category in zip(category_tabs, categories):
                with cat_tab:
                    tools = config_handler.tool_configs[category]
                    
                    # Tool list with status and install buttons
                    for tool_name, config in tools.items():
                        with st.container():
                            col1, col2, col3 = st.columns([2, 1, 1])
                            
                            with col1:
                                st.markdown(f"**{tool_name}**")
                                st.caption(config["description"])
                            
                            with col2:
                                installed = config_handler.check_tool(tool_name, config)
                                if installed:
                                    st.success("✓ Installed")
                                else:
                                    st.warning("Not Found")
                            
                            with col3:
                                if not installed:
                                    if st.button("Install", key=f"install_{tool_name}"):
                                        with st.spinner("Installing..."):
                                            success, message = config_handler.install_tool(tool_name, config)
                                            if success:
                                                st.success("✓")
                                            else:
                                                st.error(message)
                    
                    # Bulk install section at bottom of each category
                    st.markdown("---")
                    if st.button(f"Install All {category}", key=f"install_all_{category}"):
                        missing = [(name, cfg) for name, cfg in tools.items() 
                                 if not config_handler.check_tool(name, cfg)]
                        if missing:
                            progress = st.progress(0)
                            for i, (tool_name, tool_cfg) in enumerate(missing):
                                with st.spinner(f"Installing {tool_name}..."):
                                    success, msg = config_handler.install_tool(tool_name, tool_cfg)
                                    if success:
                                        st.success(f"✓ {tool_name}")
                                    else:
                                        st.error(f"Failed: {tool_name}")
                                progress.progress((i + 1) / len(missing))
                        else:
                            st.success("All tools are installed!")
        
        # Help Tab
        with help_tab:
            st.markdown("### Configuration Help")
            
            # Features section
            st.markdown("#### Available Features")
            features = {
                "System Info": "View installed versions and system details",
                "Tool Management": "Install and manage security tools",
                "Bulk Installation": "Install multiple tools at once",
                "Status Tracking": "Monitor tool installation status"
            }
            
            for feature, desc in features.items():
                with st.container():
                    st.markdown(f"**{feature}**")
                    st.caption(desc)
            
            # Package manager info
            st.markdown("#### System Requirements")
            st.markdown("""
            Package Managers:
            - Ubuntu/Debian: `sudo apt-get install <package>`
            - macOS: `brew install <package>`
            - Windows: `choco install <package>`
            
            Python Requirements:
            - Python 3.8+
            - pip (latest version)
            """)
