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
        with st.expander("Configuration Manager", expanded=False):
            config_handler = ConfigHandler(coder)
            
            # System Information
            st.markdown("### System Information")
            sys_info = config_handler.get_system_info()
            for key, value in sys_info.items():
                st.text(f"{key}: {value}")
            
            # Tool Installation Status
            st.markdown("### Tool Status")
            
            # Create columns for different tool categories
            categories = list(config_handler.tool_configs.keys())
            for category in categories:
                st.markdown(f"#### {category}")
                tools = config_handler.tool_configs[category]
                
                for tool_name, config in tools.items():
                    col1, col2 = st.columns([3,1])
                    
                    with col1:
                        st.markdown(f"**{tool_name}**")
                        st.caption(config["description"])
                    
                    with col2:
                        installed = config_handler.check_tool(tool_name, config)
                        if installed:
                            st.success("✓")
                        else:
                            if st.button("Install", key=f"install_{tool_name}"):
                                with st.spinner(f"Installing {tool_name}..."):
                                    success, message = config_handler.install_tool(tool_name, config)
                                    if success:
                                        st.success("✓")
                                    else:
                                        st.error(message)
                st.markdown("---")
            
            # Bulk Installation
            st.markdown("### Bulk Installation")
            if st.button("Install All Missing Tools"):
                missing_tools = []
                for category, tools in config_handler.tool_configs.items():
                    for tool_name, config in tools.items():
                        if not config_handler.check_tool(tool_name, config):
                            missing_tools.append((tool_name, config))
                
                if missing_tools:
                    progress_bar = st.progress(0)
                    for i, (tool_name, config) in enumerate(missing_tools):
                        with st.spinner(f"Installing {tool_name}..."):
                            success, message = config_handler.install_tool(tool_name, config)
                            if success:
                                st.success(f"✓ {tool_name}")
                            else:
                                st.error(f"Failed: {tool_name}")
                        progress_bar.progress((i + 1) / len(missing_tools))
                else:
                    st.success("All tools are installed!")

            # Help section
            st.markdown("### Configuration Manager Help")
            st.markdown("""
            This panel helps you manage security and development tools:
            
            1. **System Information**: Shows installed versions of core components
            2. **Tool Status**: Check installation status of each tool
            3. **Installation**: Install individual tools or all missing tools
            
            **Note**: Some tools require system-level installation and may need manual intervention.
            
            For system tools, please use your system's package manager:
            - Ubuntu/Debian: `sudo apt-get install <package>`
            - macOS: `brew install <package>`
            - Windows: `choco install <package>`
            """)
