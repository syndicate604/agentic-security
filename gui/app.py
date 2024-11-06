#!/usr/bin/env python

import os
import random
import sys
import io
import subprocess
import streamlit as st
from aider import urls, coders, io, main, scrape
from aider.commands import SwitchCoder


class CaptureIO(io.InputOutput):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.lines = []

    def tool_output(self, msg, log_only=False):
        if not log_only:
            self.lines.append(msg)
        super().tool_output(msg, log_only=log_only)

    def tool_error(self, msg):
        self.lines.append(msg)
        super().tool_error(msg)

    def tool_warning(self, msg):
        self.lines.append(msg)
        super().tool_warning(msg)

    def get_captured_lines(self):
        lines = self.lines
        self.lines = []
        return lines

def search(text=None):
    results = []
    for root, _, files in os.walk("."):
        for file in files:
            path = os.path.join(root, file)
            if not text or text in path:
                results.append(path)
    return results

class State:
    keys = set()

    def init(self, key, val=None):
        if key in self.keys:
            return
        self.keys.add(key)
        setattr(self, key, val)
        return True

@st.cache_resource
def get_state():
    return State()

@st.cache_resource
def get_coder():
    try:
        # Get model name from session state if available
        model_name = st.session_state.get('selected_model')
        
        if model_name:
            from aider.models import Model, OPENAI_MODELS, ANTHROPIC_MODELS
            # Determine model type and validate
            if model_name in OPENAI_MODELS or (isinstance(model_name, str) and model_name.startswith("openai/")):
                model = Model(model_name)
            elif model_name in ANTHROPIC_MODELS or (isinstance(model_name, str) and model_name.startswith("claude-")):
                model = Model(model_name)
            else:
                model = None
                
            if model:
                coder = coders.Coder.create(main_model=model)
            else:
                coder = main.main(return_coder=True)
        else:
            coder = main.main(return_coder=True)
            
        if not isinstance(coder, coders.Coder):
            raise ValueError(coder)
        if not coder.repo:
            raise ValueError("GUI can currently only be used inside a git repo")

        # Create CaptureIO instance with proper initialization
        capture_io = CaptureIO(
            pretty=False,
            yes=True,
            dry_run=coder.io.dry_run,
            encoding=coder.io.encoding,
        )
        
        # Set the IO instance
        coder.commands.io = capture_io
        
        # Get initial announcements
        for line in coder.get_announcements():
            capture_io.tool_output(line, log_only=False)
            
        return coder
    except Exception as e:
        st.error(f"Error initializing Aider: {str(e)}")
        raise

class GUI:
    prompt = None
    prompt_as = "user"
    last_undo_empty = None
    recent_msgs_empty = None
    web_content_empty = None

    def announce(self, force_update=False):
        if force_update:
            # Force refresh of announcements to reflect new model
            self.coder.update_announcements()
        lines = self.coder.get_announcements()
        lines = "  \n".join(lines)
        return lines

    def show_edit_info(self, edit):
        commit_hash = edit.get("commit_hash")
        commit_message = edit.get("commit_message")
        diff = edit.get("diff")
        fnames = edit.get("fnames")
        if fnames:
            fnames = sorted(fnames)

        if not commit_hash and not fnames:
            return

        show_undo = False
        res = ""
        if commit_hash:
            res += f"Commit `{commit_hash}`: {commit_message}  \n"
            if commit_hash == self.coder.last_aider_commit_hash:
                show_undo = True

        if fnames:
            fnames = [f"`{fname}`" for fname in fnames]
            fnames = ", ".join(fnames)
            res += f"Applied edits to {fnames}."

        if diff:
            with st.expander(res):
                st.code(diff, language="diff")
                if show_undo:
                    self.add_undo(commit_hash)
        else:
            with st.container(border=True):
                st.write(res)
                if show_undo:
                    self.add_undo(commit_hash)

    def add_undo(self, commit_hash):
        if self.last_undo_empty:
            self.last_undo_empty.empty()

        self.last_undo_empty = st.empty()
        undone = self.state.last_undone_commit_hash == commit_hash
        if not undone:
            with self.last_undo_empty:
                if self.button(f"Undo commit `{commit_hash}`", key=f"undo_{commit_hash}"):
                    self.do_undo(commit_hash)

    def do_sidebar(self):
        with st.sidebar:
            # Title
            st.markdown("""
            <h1 style='
                font-family: "Courier New", monospace;
                color: #00ff00;
                text-shadow: 2px 2px 4px #003300;
                border: 1px solid #00ff00;
                padding: 30px;
                background: linear-gradient(45deg, #050505, #0a0a0a);
                text-align: center;
                letter-spacing: 3px;
                margin-bottom: 20px;
            '>
            S.P.A.R.C.
            </h1>            
            """, unsafe_allow_html=True)
            
            # Create main tabs for better organization
            chat_tab, tools_tab = st.tabs(["Chat & Files", "Tools & Settings"])
            
            with chat_tab:
                # Chat related sections
                self.do_add_to_chat()
                self.do_clear_chat_history()
            
            with tools_tab:
                # Tools and settings in collapsible sections
                with st.expander("🤖 Model Settings", expanded=False):
                    self.do_model_settings()
                
                with st.expander("🛠️ Shell Commands", expanded=False):
                    self.do_shell_commands()
                
                with st.expander("🔄 GitHub Actions", expanded=False):
                    self.do_github_actions()
                
                with st.expander("🔒 Security Tools", expanded=False):
                    self.do_security_tools()
                
                with st.expander("⚙️ Developer Tools", expanded=False):
                    self.do_dev_tools()
                
                with st.expander("🧠 Prompt Engineering", expanded=False):
                    render_prompt_engineering_panel(self.coder)
            
            # Footer
            st.markdown("---")
            st.warning(
                "Created by rUv, bacause he could, with help from aider."
            )

    def do_add_to_chat(self):
        # Create tabs for file management, documentation and recent messages
        files_tab, docs_tab, recent_tab = st.tabs(["Files", "Documentation", "Recent"])
        
        with files_tab:
            self.do_add_files()
            self.do_add_web_page()
            
        with docs_tab:
            # Quick Start accordion
            with st.expander("🚀 Quick Start Guide", expanded=True):
                st.markdown("""
                1. Add files to edit in the Files tab
                2. Type your request in the chat
                3. Review and confirm changes
                """)
            
            # Features accordion
            with st.expander("✨ Features"):
                st.markdown("""
                - Real-time code editing
                - Git integration
                - Security scanning
                - Shell commands
                - GitHub Actions
                """)
            
            # Tips accordion
            with st.expander("💡 Tips & Best Practices"):
                st.markdown("""
                - Use clear, specific requests
                - Review diffs before confirming
                - Check security scan results
                - Keep chat context focused
                """)
                
            # Keyboard Shortcuts accordion
            with st.expander("⌨️ Keyboard Shortcuts"):
                st.markdown("""
                - `Ctrl + Enter`: Submit chat
                - `Ctrl + Z`: Undo last change
                - `Ctrl + /`: Toggle sidebar
                - `Ctrl + F`: Search in files
                """)
                
            # Common Commands accordion
            with st.expander("🔧 Common Commands"):
                st.markdown("""
                - `/help`: Show help
                - `/clear`: Clear chat history
                - `/undo`: Undo last change
                - `/add <file>`: Add file to chat
                - `/run <cmd>`: Run shell command
                """)
            
        with recent_tab:
            self.do_recent_msgs()

    def do_add_files(self):
        fnames = st.multiselect(
            "Add files to the chat",
            self.coder.get_all_relative_files(),
            default=self.state.initial_inchat_files,
            placeholder="Files to edit",
            disabled=self.prompt_pending(),
            help=(
                "Only add the files that need to be *edited* for the task you are working"
                " on. Aider will pull in other relevant code to provide context to the LLM."
            ),
        )

        for fname in fnames:
            if fname not in self.coder.get_inchat_relative_files():
                self.coder.add_rel_fname(fname)
                self.info(f"Added {fname} to the chat")

        for fname in self.coder.get_inchat_relative_files():
            if fname not in fnames:
                self.coder.drop_rel_fname(fname)
                self.info(f"Removed {fname} from the chat")

    def do_add_web_page(self):
        with st.popover("Add a web page to the chat"):
            self.do_web()

    def do_recent_msgs(self):
        if not self.recent_msgs_empty:
            self.recent_msgs_empty = st.empty()

        if self.prompt_pending():
            self.recent_msgs_empty.empty()
            self.state.recent_msgs_num += 1

        with self.recent_msgs_empty:
            self.old_prompt = st.selectbox(
                "Resend a recent chat message",
                self.state.input_history,
                placeholder="Choose a recent chat message",
                index=None,
                key=f"recent_msgs_{self.state.recent_msgs_num}",
                disabled=self.prompt_pending(),
            )
            if self.old_prompt:
                self.prompt = self.old_prompt

    def do_clear_chat_history(self):
        text = "Saves tokens, reduces confusion"
        if self.button("Clear chat history", help=text):
            self.coder.done_messages = []
            self.coder.cur_messages = []
            self.info("Cleared chat history. Now the LLM can't see anything before this line.")

    def do_messages_container(self):
        self.messages = st.container()

        with self.messages:
                for msg in self.state.messages:
                    role = msg["role"]

                    if role == "edit":
                        self.show_edit_info(msg)
                    elif role == "info":
                        st.info(msg["content"])
                    elif role == "text":
                        text = msg["content"]
                        line = text.splitlines()[0]
                        with self.messages.expander(line):
                            st.text(text)
                    elif role == "user":
                        with st.chat_message(role, avatar="💀"):  # User icon
                            st.write(msg["content"])
                    elif role == "assistant":
                        with st.chat_message(role, avatar="🤖"):  # Assistant icon
                            st.write(msg["content"])
                    else:
                        st.json(msg)  # Changed from st.dict to st.json for better display
    def initialize_state(self):
        messages = [
            dict(role="info", content=self.announce()),
            dict(role="assistant", content="How can I help you?"),
        ]

        self.state.init("messages", messages)
        self.state.init("last_aider_commit_hash", self.coder.last_aider_commit_hash)
        self.state.init("last_undone_commit_hash")
        self.state.init("recent_msgs_num", 0)
        self.state.init("web_content_num", 0)
        self.state.init("prompt")
        self.state.init("scraper")
        self.state.init("current_model", self.coder.main_model)
        self.state.init("initial_inchat_files", self.coder.get_inchat_relative_files())

        if "input_history" not in self.state.keys:
            input_history = list(self.coder.io.get_input_history())
            seen = set()
            input_history = [x for x in input_history if not (x in seen or seen.add(x))]
            self.state.input_history = input_history
            self.state.keys.add("input_history")

    def button(self, args, **kwargs):
        if self.prompt_pending():
            kwargs["disabled"] = True
        return st.button(args, **kwargs)

    def __init__(self):
        try:
            # Initialize core components
            self.coder = get_coder()
            self.state = get_state()
            
            # Configure coder settings
            if hasattr(self.coder, 'yield_stream'):
                self.coder.yield_stream = True
            if hasattr(self.coder, 'stream'):
                self.coder.stream = True
            if hasattr(self.coder, 'pretty'):
                self.coder.pretty = False
            
            # Configure IO settings
            if hasattr(self.coder, 'io'):
                self.coder.io.yes = True
                self.coder.io.no_interactive = True
            
            # Initialize handlers
            self.shell_handler = None
            self.github_handler = None
            self.security_handler = None
            
            # Initialize state last
            self.initialize_state()
        except Exception as e:
            st.error(f"Error initializing GUI: {str(e)}")
            return

        self.do_messages_container()
        self.do_sidebar()

        user_inp = st.chat_input("// Enter Command Here")
        if user_inp:
            self.prompt = user_inp

        if self.prompt_pending():
            self.process_chat()

        if not self.prompt:
            return

        self.state.prompt = self.prompt

        if self.prompt_as == "user":
            self.coder.io.add_to_input_history(self.prompt)

        self.state.input_history.append(self.prompt)

        if self.prompt_as:
            self.state.messages.append({"role": self.prompt_as, "content": self.prompt})
        if self.prompt_as == "user":
            with self.messages.chat_message("user"):
                st.write(self.prompt)
        elif self.prompt_as == "text":
            line = self.prompt.splitlines()[0]
            line += "??"
            with self.messages.expander(line):
                st.text(self.prompt)

        st.rerun()

    def prompt_pending(self):
        return self.state.prompt is not None

    def process_chat(self):
        prompt = self.state.prompt
        self.state.prompt = None

        self.num_reflections = 0
        self.max_reflections = 3

        while prompt:
            with self.messages.chat_message("assistant"):
                res = st.write_stream(self.coder.run_stream(prompt))
                self.state.messages.append({"role": "assistant", "content": res})

            prompt = None
            if self.coder.reflected_message:
                if self.num_reflections < self.max_reflections:
                    self.num_reflections += 1
                    self.info(self.coder.reflected_message)
                    prompt = self.coder.reflected_message

        with self.messages:
            edit = dict(
                role="edit",
                fnames=self.coder.aider_edited_files,
            )
            if self.state.last_aider_commit_hash != self.coder.last_aider_commit_hash:
                edit["commit_hash"] = self.coder.last_aider_commit_hash
                edit["commit_message"] = self.coder.last_aider_commit_message
                commits = f"{self.coder.last_aider_commit_hash}~1"
                diff = self.coder.repo.diff_commits(
                    self.coder.pretty,
                    commits,
                    self.coder.last_aider_commit_hash,
                )
                edit["diff"] = diff
                self.state.last_aider_commit_hash = self.coder.last_aider_commit_hash

            self.state.messages.append(edit)
            self.show_edit_info(edit)

        st.rerun()

    def info(self, message, echo=True):
        info = dict(role="info", content=message)
        self.state.messages.append(info)

        if echo:
            self.messages.info(message)

    def do_web(self):
        st.markdown("Add the text content of a web page to the chat")

        if not self.web_content_empty:
            self.web_content_empty = st.empty()

        if self.prompt_pending():
            self.web_content_empty.empty()
            self.state.web_content_num += 1

        with self.web_content_empty:
            self.web_content = st.text_input(
                "URL",
                placeholder="https://...",
                key=f"web_content_{self.state.web_content_num}",
            )

        if not self.web_content:
            return

        url = self.web_content

        if not self.state.scraper:
            self.scraper = scrape.Scraper(print_error=self.info)

        content = self.scraper.scrape(url) or ""
        if content.strip():
            content = f"{url}\n\n" + content
            self.prompt = content
            self.prompt_as = "text"
        else:
            self.info(f"No web content found for `{url}`.")
            self.web_content = None


    def do_shell_commands(self):
        from shell_handler import AiderShellHandler
        
        with st.sidebar.expander("Shell Commands", expanded=False):
            # Initialize shell handler if needed
            if not hasattr(self, 'shell_handler'):
                self.shell_handler = AiderShellHandler(self.coder)
            
            # Common commands dropdown
            common_commands = {
                "Git Status": "git status",
                "List Files": "ls -la",
                "Python Tests": "python -m pytest",
                "Git Log": "git log --oneline",
                "Check Python Version": "python --version",
                "List Git Branches": "git branch",
                "Current Directory": "pwd",
                "System Info": "uname -a",
                "Disk Usage": "df -h",
                "Memory Usage": "free -h",
                "Process Status": "ps aux",
                "Network Status": "netstat -tuln"
            }
            
            selected_command = st.selectbox(
                "Common Commands",
                options=["Select a command..."] + list(common_commands.keys()),
                key="common_commands"
            )
            
            # Command input with auto-fill from dropdown
            command = st.text_input(
                "Shell Command:", 
                value=common_commands.get(selected_command, ""),
                placeholder="/run python test.py",
                help="Enter a shell command to execute. '/run' prefix is optional."
            )
            
            # Command options
            col1, col2 = st.columns(2)
            with col1:
                share_output = st.checkbox("Share with AI", value=True)
            with col2:
                get_feedback = st.checkbox("Get AI Feedback", value=True)
            
            # Run button
            if st.button("Run Command") and command:
                with st.spinner("Running command..."):
                    try:
                        if get_feedback:
                            # Run with AI feedback
                            stdout, stderr, chat_msg = self.shell_handler.run_with_ai_feedback(command)
                            
                            # Display command output
                            if stdout:
                                st.text("Command Output:")
                                st.code(stdout)
                            if stderr:
                                st.error("Error Output:")
                                st.code(stderr)
                            
                            # If we have output and a chat message, process it through the chat
                            if chat_msg:
                                self.prompt = chat_msg
                                self.prompt_as = "text"
                                st.info("✓ Analyzing command output...")
                        
                        else:
                            # Run without feedback
                            stdout, stderr, chat_msg = self.shell_handler.run_shell_command(
                                command, 
                                share_output=share_output
                            )
                            
                            # Display results
                            if stdout:
                                st.text("Command Output:")
                                st.code(stdout)
                                if share_output:
                                    st.info("✓ Output shared with AI")
                            if stderr:
                                st.error("Error Output:")
                                st.code(stderr)
                                if share_output:
                                    st.info("✓ Error shared with AI")
                            
                            if not stdout and not stderr:
                                st.info("Command executed successfully with no output")
                            
                            # Add to chat if sharing is enabled and we have a chat message
                            if share_output and chat_msg:
                                # Add command context and instructions
                                self.prompt = (
                                    f"Shell command: `{command}`\n\n"
                                    f"{chat_msg}\n\n"
                                    "Please let me know what specific aspects of this output "
                                    "you'd like me to explain or what assistance you need."
                                )
                                self.prompt_as = "text"
                                
                    except Exception as e:
                        st.error(f"Error executing command: {str(e)}")
            
            # Help text in a container
            with st.container():
                st.markdown("""
                ### Shell Command Help
                
                **Available Options:**
                - **Share with AI**: Adds command output to the chat
                - **Get AI Feedback**: Gets AI analysis of the command output
                
                **Example Commands:**
                - `python test.py`
                - `git status`
                - `ls -la`
                
                **Note**: Commands are executed in the current working directory
                """)

    def do_github_actions(self):
        from github_handler import GitHubActionsHandler
        
        with st.sidebar.expander("GitHub Actions", expanded=False):
            # Initialize GitHub handler if needed
            if not hasattr(self, 'github_handler'):
                self.github_handler = GitHubActionsHandler(self.coder)
            
            # Common GitHub Actions commands
            github_commands = {
                "List Workflows": "gh workflow list",
                "View Recent Runs": "gh run list",
                "List Secrets": "gh secret list",
                "List Variables": "gh variable list",
                "View Repository Status": "gh repo view",
                "List Pull Requests": "gh pr list",
                "List Issues": "gh issue list",
                "View CI Status": "gh status",
                "List Contributors": "gh contributor list",
                "View Repository Settings": "gh repo view --json name,description,visibility"
            }
            
            selected_action = st.selectbox(
                "Common GitHub Actions",
                options=["Select an action..."] + list(github_commands.keys()),
                key="github_actions"
            )
            
            # Command input with auto-fill from dropdown
            command = st.text_input(
                "GitHub Command:", 
                value=github_commands.get(selected_action, ""),
                placeholder="gh workflow list",
                help="Enter a GitHub CLI command to execute."
            )
            
            # Command options
            col1, col2 = st.columns(2)
            with col1:
                share_output = st.checkbox("Share with AI", value=True, key="gh_share")
            with col2:
                get_feedback = st.checkbox("Get AI Feedback", value=True, key="gh_feedback")
            
            # Run button
            if st.button("Run GitHub Command") and command:
                with st.spinner("Running command..."):
                    try:
                        if get_feedback:
                            # Run with AI feedback
                            stdout, stderr, chat_msg = self.shell_handler.run_with_ai_feedback(command)
                            
                            # Display command output
                            if stdout:
                                st.text("Command Output:")
                                st.code(stdout)
                            if stderr:
                                st.error("Error Output:")
                                st.code(stderr)
                            
                            # If we have output and a chat message, process it through the chat
                            if chat_msg:
                                self.prompt = chat_msg
                                self.prompt_as = "text"
                                st.info("✓ Analyzing GitHub Actions output...")
                        
                        else:
                            # Run without feedback
                            stdout, stderr, chat_msg = self.shell_handler.run_shell_command(
                                command, 
                                share_output=share_output
                            )
                            
                            # Display results
                            if stdout:
                                st.text("Command Output:")
                                st.code(stdout)
                                if share_output:
                                    st.info("✓ Output shared with AI")
                            if stderr:
                                st.error("Error Output:")
                                st.code(stderr)
                                if share_output:
                                    st.info("✓ Error shared with AI")
                            
                            if not stdout and not stderr:
                                st.info("Command executed successfully with no output")
                            
                            # Add to chat if sharing is enabled and we have a chat message
                            if share_output and chat_msg:
                                self.prompt = (
                                    f"GitHub command: `{command}`\n\n"
                                    f"{chat_msg}\n\n"
                                    "Please let me know what specific aspects of this output "
                                    "you'd like me to explain or what assistance you need."
                                )
                                self.prompt_as = "text"
                                
                    except Exception as e:
                        st.error(f"Error executing GitHub command: {str(e)}")
            
            # Help text in a container
            with st.container():
                st.markdown("""
                ### GitHub Actions Help
                
                **Available Options:**
                - **Share with AI**: Adds command output to the chat
                - **Get AI Feedback**: Gets AI analysis of the command output
                
                **Example Commands:**
                - `gh workflow list`
                - `gh run list`
                - `gh repo view`
                
                **Note**: Commands require GitHub CLI (`gh`) to be installed and authenticated
                """)

    def do_model_settings(self):
        with st.sidebar.expander("Model Settings", expanded=False):
            # Provider selection
            provider = st.radio(
                "AI Provider",
                ["OpenAI", "Anthropic"],
                key="provider_selection"
            )
            
            # Model selection based on provider
            if provider == "OpenAI":
                model = st.selectbox(
                    "Select Model",
                    [
                        "gpt-4",
                        "gpt-4-32k",
                        "gpt-4-1106-preview",  # GPT-4 Turbo
                        "gpt-4-0125-preview",  # Latest GPT-4 Preview
                        "gpt-3.5-turbo",
                        "gpt-3.5-turbo-16k",
                        "gpt-3.5-turbo-1106"
                    ],
                    index=0,
                    key="openai_model_selection"
                )
            else:  # Anthropic
                model = st.selectbox(
                    "Select Model",
                    [
                        "claude-3-opus-20240229",
                        "claude-3-sonnet-20240229",
                        "claude-3-haiku-20240307",
                        "claude-2.1",
                        "claude-2.0"
                    ],
                    index=0,
                    key="anthropic_model_selection"
                )

            # Model switching
            if st.button("Switch Model"):
                try:
                    # Check API keys before attempting switch
                    if provider == "OpenAI" and not os.getenv("OPENAI_API_KEY"):
                        raise ValueError("OpenAI API key not found. Please set OPENAI_API_KEY environment variable.")
                    elif provider == "Anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
                        raise ValueError("Anthropic API key not found. Please set ANTHROPIC_API_KEY environment variable.")
                    
                    # Store current model info before switching
                    old_model = getattr(self.coder, 'main_model', 'unknown')
                    
                    # Store selected model in session state
                    st.session_state['selected_model'] = model
                    
                    # Clear cache and force reload
                    st.cache_resource.clear()
                    
                    # Create new coder instance with new model
                    self.coder = get_coder()
                    
                    # Update state and display info
                    self.state.init("current_model", model)
                    self.info(f"Successfully switched from {old_model} to {model}")
                    
                    # Add system message about model switch
                    self.state.messages.append({
                        "role": "system",
                        "content": f"Model switched from {old_model} to {model}"
                    })
                    
                    # Force UI update
                    st.rerun()
                    
                except AttributeError as e:
                    self.info(f"Configuration error: {str(e)}")
                except ValueError as e:
                    self.info(f"Invalid model selection: {str(e)}")
                except RuntimeError as e:
                    self.info(f"Streamlit error: {str(e)}")
                except Exception as e:
                    self.info(f"Unexpected error switching model: {str(e)}\nPlease check your API keys and model access.")

            # Model settings
            settings_container = st.container()
            with settings_container:
                st.markdown("### Model Settings")
                
                # Temperature setting
                current_temp = self.coder.temperature if hasattr(self.coder, 'temperature') else 0.7
                # Ensure current_temp is a float
                if isinstance(current_temp, (list, tuple)):
                    current_temp = 0.7  # Default if invalid type

                temperature = st.slider(
                    "Temperature",
                    min_value=0.0,
                    max_value=2.0,
                    value=float(current_temp),  # Convert to float
                    step=0.1,
                    help="Higher values make output more random, lower values more deterministic"
                )
                
                # Max tokens setting
                max_tokens = st.number_input(
                    "Max Tokens",
                    min_value=100,
                    max_value=32000,
                    value=2000,
                    step=100,
                    help="Maximum number of tokens in the response"
                )

                # Apply settings button
                if st.button("Apply Settings"):
                    try:
                        # Update temperature
                        if hasattr(self.coder, 'set_temperature'):
                            self.coder.set_temperature(temperature)
                        else:
                            self.coder.temperature = temperature
                        
                        # Update max tokens if supported
                        if hasattr(self.coder, 'set_max_tokens'):
                            self.coder.set_max_tokens(max_tokens)
                        
                        self.info("Model settings updated successfully")
                    except Exception as e:
                        self.info(f"Error updating settings: {str(e)}")

            # Display current settings
            st.markdown("### Current Model Info")
            st.markdown(f"""
            - **Current Model**: {self.state.current_model if hasattr(self.state, 'current_model') else model}
            - **Temperature**: {temperature}
            - **Max Tokens**: {max_tokens}
            - **Provider**: {provider}
            """)


    def do_security_tools(self):
        """Add security tools panel to sidebar"""
        with st.sidebar.expander("Security Tools", expanded=False):
            # Initialize shell handler if needed
            if not hasattr(self, 'shell_handler'):
                from shell_handler import AiderShellHandler
                self.shell_handler = AiderShellHandler(self.coder)
            elif self.shell_handler is None:
                from shell_handler import AiderShellHandler
                self.shell_handler = AiderShellHandler(self.coder)
                
            # Security scan categories
            scan_categories = {
                "Code Analysis": {
                    "SAST Scan": "semgrep scan .",
                    "Secret Scanner": "gitleaks detect",
                    "Python Security": "bandit -r .",
                    "Dependency Check": "safety check",
                },
                "Web Security": {
                    "OWASP ZAP Scan": "zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true'",
                    "SSL Check": "sslyze --regular localhost",
                    "Port Scan": "nmap -sV localhost",
                },
                "Config Security": {
                    "File Permissions": "find . -type f -exec ls -l {} \\;",
                    "Environment Check": "env | grep -i key",
                    "Docker Security": "docker scan .",
                    "Git Leaks": "gitleaks detect -v"
                }
            }
            
            # Category selection
            selected_category = st.selectbox(
                "Scan Category",
                options=["Select category..."] + list(scan_categories.keys()),
                key="security_category"
            )
            
            if selected_category and selected_category != "Select category...":
                # Scan selection
                selected_scan = st.selectbox(
                    f"{selected_category} Scans",
                    options=["Select scan..."] + list(scan_categories[selected_category].keys()),
                    key="security_scan"
                )
                
                # Command input with auto-fill from selection
                command = st.text_input(
                    "Security Command:", 
                    value=scan_categories[selected_category].get(selected_scan, ""),
                    placeholder="Select or enter security scan command",
                    help="Enter a security scanning command to execute."
                )
                
                # Scan options
                col1, col2 = st.columns(2)
                with col1:
                    share_output = st.checkbox("Share with AI", value=True, key="security_share")
                with col2:
                    get_feedback = st.checkbox("Get AI Feedback", value=True, key="security_feedback")
                
                # Run button
                if st.button("Run Security Scan") and command:
                    with st.spinner("Running security scan..."):
                        try:
                            if get_feedback:
                                stdout, stderr, chat_msg = self.shell_handler.run_with_ai_feedback(command)
                            else:
                                stdout, stderr, chat_msg = self.shell_handler.run_shell_command(
                                    command, 
                                    share_output=share_output
                                )
                            
                            # Check for common installation errors in stderr
                            if stderr and any(x in stderr.lower() for x in ['not found', 'no such', 'command not found']):
                                st.error("Tool not installed:")
                                st.code(stderr)
                                
                                # Determine which tool is missing
                                tool_name = command.split()[0]
                                install_commands = {
                                    'zap-cli': {
                                        'pip': 'pip install python-owasp-zap-v2.4 zaproxy',
                                        'apt': 'sudo apt-get install -y zaproxy',
                                        'brew': 'brew install zaproxy'
                                    },
                                    'semgrep': {
                                        'pip': 'pip install semgrep',
                                        'apt': 'sudo apt-get install -y semgrep',
                                        'brew': 'brew install semgrep'
                                    },
                                    'bandit': {
                                        'pip': 'pip install bandit',
                                        'apt': 'sudo apt-get install -y bandit',
                                        'brew': 'brew install bandit'
                                    },
                                    'gitleaks': {
                                        'pip': 'pip install gitleaks',
                                        'apt': 'sudo apt-get install -y gitleaks',
                                        'brew': 'brew install gitleaks'
                                    },
                                    'safety': {
                                        'pip': 'pip install safety',
                                        'apt': 'sudo apt-get install -y safety',
                                        'brew': 'brew install safety'
                                    },
                                    'sslyze': {
                                        'pip': 'pip install sslyze',
                                        'apt': 'sudo apt-get install -y sslyze',
                                        'brew': 'brew install sslyze'
                                    },
                                    'nmap': {
                                        'apt': 'sudo apt-get install -y nmap',
                                        'brew': 'brew install nmap',
                                        'yum': 'sudo yum install -y nmap'
                                    }
                                }
                                
                                if tool_name in install_commands:
                                    st.info("Installation options:")
                                    
                                    # Show installation commands
                                    col1, col2 = st.columns(2)
                                    with col1:
                                        if 'pip' in install_commands[tool_name]:
                                            if st.button(f"Install with pip", key=f"pip_{tool_name}"):
                                                install_cmd = install_commands[tool_name]['pip']
                                                with st.spinner(f"Installing {tool_name}..."):
                                                    result = subprocess.run(install_cmd.split(), capture_output=True, text=True)
                                                    if result.returncode == 0:
                                                        st.success(f"✓ {tool_name} installed successfully")
                                                    else:
                                                        st.error(f"Failed to install: {result.stderr}")
                                    
                                    with col2:
                                        if 'apt' in install_commands[tool_name]:
                                            if st.button(f"Install with apt", key=f"apt_{tool_name}"):
                                                install_cmd = install_commands[tool_name]['apt']
                                                with st.spinner(f"Installing {tool_name}..."):
                                                    result = subprocess.run(install_cmd.split(), capture_output=True, text=True)
                                                    if result.returncode == 0:
                                                        st.success(f"✓ {tool_name} installed successfully")
                                                    else:
                                                        st.error(f"Failed to install: {result.stderr}")
                                    
                                    # Show manual installation instructions
                                    st.markdown(f"""
                                    ### Manual Installation for {tool_name}:
                                    
                                    **Using pip:**
                                    ```bash
                                    {install_commands[tool_name].get('pip', '# Not available via pip')}
                                    ```
                                    
                                    **Using apt (Ubuntu/Debian):**
                                    ```bash
                                    {install_commands[tool_name].get('apt', '# Not available via apt')}
                                    ```
                                    
                                    **Using brew (macOS):**
                                    ```bash
                                    {install_commands[tool_name].get('brew', '# Not available via brew')}
                                    ```
                                    """)
                            else:
                                # Display normal results
                                if stdout:
                                    st.text("Scan Output:")
                                    st.code(stdout)
                                if stderr:
                                    st.error("Scan Errors:")
                                    st.code(stderr)
                            
                            # Handle AI feedback/sharing
                            if chat_msg:
                                self.prompt = chat_msg
                                self.prompt_as = "text"
                                if get_feedback:
                                    st.info("✓ Analyzing security scan results...")
                                elif share_output:
                                    st.info("✓ Scan results shared with AI")
                                    
                        except Exception as e:
                            st.error(f"Error executing security scan: {str(e)}")
            

    def do_dev_tools(self):
        with st.sidebar.expander("Developer Tools", expanded=False):
            # Specialized command categories
            dev_commands = {
                "Code Analysis": {
                    "Find TODOs": "grep -r 'TODO' .",
                    "Count Lines of Code": "find . -name '*.py' | xargs wc -l",
                    "List Python Files": "find . -name '*.py' | sort",
                    "Check Python Style": "pylint .",
                    "Run Security Scan": "bandit -r .",
                    "Find Large Files": "find . -type f -size +10M",
                },
                "Dependencies": {
                    "List Python Packages": "pip list",
                    "Show Outdated Packages": "pip list --outdated",
                    "Check Dependencies": "pip check",
                    "Generate Requirements": "pip freeze > requirements.txt",
                    "Install Requirements": "pip install -r requirements.txt",
                },
                "Docker": {
                    "List Containers": "docker ps",
                    "List Images": "docker images",
                    "Show Docker Disk": "docker system df",
                    "Prune Docker": "docker system prune -f",
                    "Container Logs": "docker logs $(docker ps -q)",
                },
                "Security": {
                    "Find Secrets": "gitleaks detect",
                    "SAST Scan": "semgrep scan",
                    "Check File Permissions": "ls -la",
                    "List Open Ports": "netstat -tuln",
                    "Show SSH Keys": "ls -la ~/.ssh",
                },
                "Performance": {
                    "CPU Usage": "top -b -n 1",
                    "Memory Usage": "free -h",
                    "Disk Space": "df -h",
                    "IO Stats": "iostat",
                    "Network Stats": "netstat -s",
                },
                "Git Advanced": {
                    "Show Large Files": "git rev-list --objects --all | git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' | awk '/^blob/ {print substr($0,6)}' | sort -n",
                    "List Contributors": "git shortlog -sn",
                    "Branch History": "git log --graph --oneline --all",
                    "Find Merge Conflicts": "git diff --check",
                    "Clean Repo": "git clean -xfd",
                }
            }
            
            # Category selection
            selected_category = st.selectbox(
                "Command Category",
                options=["Select category..."] + list(dev_commands.keys()),
                key="dev_tools_category"
            )
            
            # Command selection based on category
            if selected_category and selected_category != "Select category...":
                selected_command = st.selectbox(
                    f"{selected_category} Commands",
                    options=["Select command..."] + list(dev_commands[selected_category].keys()),
                    key="dev_tools_command"
                )
                
                # Command input with auto-fill from selection
                command = st.text_input(
                    "Developer Command:", 
                    value=dev_commands[selected_category].get(selected_command, ""),
                    placeholder="Select or enter command",
                    help="Enter a development tool command to execute."
                )
                
                # Command options
                col1, col2 = st.columns(2)
                with col1:
                    share_output = st.checkbox("Share with AI", value=True, key="dev_share")
                with col2:
                    get_feedback = st.checkbox("Get AI Feedback", value=True, key="dev_feedback")
                
                # Run button
                if st.button("Run Dev Command") and command:
                    with st.spinner("Running command..."):
                        try:
                            if get_feedback:
                                stdout, stderr, chat_msg = self.shell_handler.run_with_ai_feedback(command)
                            else:
                                stdout, stderr, chat_msg = self.shell_handler.run_shell_command(
                                    command, 
                                    share_output=share_output
                                )
                            
                            # Display results
                            if stdout:
                                st.text("Command Output:")
                                st.code(stdout)
                            if stderr:
                                st.error("Error Output:")
                                st.code(stderr)
                            
                            # Handle AI feedback/sharing
                            if chat_msg:
                                self.prompt = chat_msg
                                self.prompt_as = "text"
                                if get_feedback:
                                    st.info("✓ Analyzing command output...")
                                elif share_output:
                                    st.info("✓ Output shared with AI")
                                    
                        except Exception as e:
                            st.error(f"Error executing command: {str(e)}")
            
            # Help text
            with st.container():
                st.markdown("""
                ### Developer Tools Help
                
                **Categories:**
                - **Code Analysis**: Find issues and analyze code
                - **Dependencies**: Manage project dependencies
                - **Docker**: Container management
                - **Security**: Security scanning and checks
                - **Performance**: System monitoring
                - **Git Advanced**: Advanced git operations
                
                **Note**: Some commands require additional tools to be installed. Run:
                ```
                pip install -r gui/requirements.txt
                ```
                For system-level tools like iostat, use your system's package manager:
                - Ubuntu/Debian: sudo apt-get install sysstat net-tools
                - CentOS/RHEL: sudo yum install sysstat net-tools
                - macOS: brew install sysstat
                """)

    def do_undo(self, commit_hash):
        self.last_undo_empty.empty()

        if (
            self.state.last_aider_commit_hash != commit_hash
            or self.coder.last_aider_commit_hash != commit_hash
        ):
            self.info(f"Commit `{commit_hash}` is not the latest commit.")
            return

        self.coder.commands.io.get_captured_lines()
        reply = self.coder.commands.cmd_undo(None)
        lines = self.coder.commands.io.get_captured_lines()

        lines = "\n".join(lines)
        lines = lines.splitlines()
        lines = "  \n".join(lines)
        self.info(lines, echo=False)

        self.state.last_undone_commit_hash = commit_hash

        if reply:
            self.prompt_as = None
            self.prompt = reply

def gui_main():
    try:
        # Set dark theme and custom styles
        st.set_page_config(
            layout="wide",
            page_title="Aider",
            page_icon=urls.favicon,
            menu_items={
                "Get Help": urls.website,
                "Report a bug": "https://agentic-security.io/support",
                "About": "# Aider\nAI pair programming in your browser.",
            },
            initial_sidebar_state="expanded",
        )

        # Enable dark mode globally
        st.markdown("""
          
        """, unsafe_allow_html=True)

        # Apply custom CSS for dark mode hacker style
        st.markdown("""
        <style>
        /* Dark mode background and text colors */
        .stApp {
            background-color: #050505;
            color: #00ff00;
            font-family: 'Courier New', monospace;
        }
        
        /* Sidebar styling */
        .css-1d391kg {
            background-color: #080808;
        }
        
        /* Input fields */
        .stTextInput input {
            background-color: #0a0a0a;
            color: #00ff00;
            border-color: #00ff00;
            font-family: 'Courier New', monospace;
        }
        
        /* Buttons */
        .stButton button {
            background-color: #0d0d0d;
            color: #00ff00;
            border: 1px solid #00ff00;
            font-family: 'Courier New', monospace;
        }
        
        .stButton button:hover {
            background-color: #00ff00;
            color: #0a0a0a;
        }
        
        /* Chat messages */
        .stChatMessage {
            background-color: #0a0a0a;
            border: 1px solid #00ff00;
            font-family: 'Courier New', monospace;
        }
        
        /* Code blocks */
        .stCodeBlock {
            background-color: #0d0d0d;
            font-family: 'Courier New', monospace;
        }
        
        /* Links */
        a {
            color: #00ff00 !important;
            text-decoration: none !important;
        }
        
        a:hover {
            color: #33ff33 !important;
            text-decoration: underline !important;
        }
        
        /* Expander */
        .streamlit-expanderHeader {
            background-color: #0d0d0d;
            color: #00ff00;
            font-family: 'Courier New', monospace;
        }
        
        /* Select boxes */
        .stSelectbox {
            background-color: #0d0d0d;
            color: #00ff00;
            font-family: 'Courier New', monospace;
        }

        /* Multiselect */
        .stMultiSelect {
            background-color: #0d0d0d;
            color: #00ff00;
            font-family: 'Courier New', monospace;
        }

        /* Header/top bar styling */
        header[data-testid="stHeader"] {
            background-color: #050505 !important;
            border-bottom: 1px solid #00ff00;
        }

        /* Progress bar - the gradient at the top */
        .stProgress > div > div > div > div {
            background-image: linear-gradient(to right, #050505, #00ff00) !important;
        }

        /* Scrollbars */
        ::-webkit-scrollbar {
            width: 10px;
            height: 10px;
        }

        ::-webkit-scrollbar-track {
            background: #0a0a0a;
        }

        ::-webkit-scrollbar-thumb {
            background: #00ff00;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: #33ff33;
        }

        /* Text selection */
        ::selection {
            background: #00ff00;
            color: #0a0a0a;
        }

        /* Sidebar specific styles */
        .css-1d391kg, [data-testid="stSidebar"] {
            background-color: #080808 !important;
            border-right: 1px solid #00ff00;
        }

        /* Sidebar title */
        .css-1d391kg h1 {
            color: #00ff00 !important;
        }

        /* Sidebar navigation items */
        .css-1d391kg .streamlit-expanderHeader {
            background-color: #0a0a0a;
            color: #00ff00 !important;
        }

        /* Sidebar labels and text */
        .css-1d391kg label, .css-1d391kg .stMarkdown {
            color: #00ff00 !important;
        }

        /* Sidebar select boxes and dropdowns */
        .css-1d391kg select, .css-1d391kg .stSelectbox {
            background-color: #0a0a0a !important;
            color: #00ff00 !important;
            border-color: #00ff00 !important;
        }

        /* Sidebar warning box */
        .css-1d391kg .stAlert {
            background-color: #0a0a0a !important;
            color: #00ff00 !important;
            border-color: #00ff00 !important;
        }

        /* Sidebar divider */
        .css-1d391kg hr {
            border-color: #00ff00 !important;
        }

       /* Chat input container */
        .stChatInput {
            padding: 10px;
            background-color: #0a0a0a !important;
            border-radius: 10px;
            border: 1px solid #00ff00 !important;
        }

        /* Chat input textarea */
        .stChatInput textarea {
            color: #00FF00 !important;
            font-family: 'Courier New', monospace !important;
            font-size: 16px !important;
            font-style: italic !important;
            background-color: transparent !important;
            border: none !important;
            padding: 8px !important;
            width: 100% !important;
        }

        /* Chat input textarea placeholder */
        .stChatInput textarea::placeholder {
            color: #00ff00 !important;
            opacity: 0.5 !important;
            font-style: italic !important;
        }

        /* Submit button */
        .stChatInput button {
            border: 1px solid #00FF00 !important;
            border-radius: 50% !important;
            padding: 8px !important;
            background-color: transparent !important;
            margin-left: 10px !important;
            width: 40px !important;
            height: 40px !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
        }

        /* Submit button hover */
        .stChatInput button:hover {
            background-color: #00ff00 !important;
        }

        /* Submit button hover icon */
        .stChatInput button:hover svg {
            color: #0a0a0a !important;
        }

        /* Submit button icon */
        .stChatInput button svg {
            color: #00FF00 !important;
            width: 20px !important;
            height: 20px !important;
        }

        /* Chat input container background */
        [data-testid="stChatInputContainer"], 
        [data-testid="stChatInputContainer"] > div,
        .stBottom.st-emotion-cache-1p2n2i4.ea3mdgi7,
        .st-emotion-cache-abycrm {
            background-color: #000 !important;
            border-top: 1px solid #00ff00 !important;
            padding-top: 1rem !important;
        }

        /* Ensure all nested divs in chat input are dark */
        [data-testid="stChatInputContainer"] div,
        .stBottom.st-emotion-cache-1p2n2i4.ea3mdgi7 div,
        .st-emotion-cache-abycrm div {
            background-color: #000 !important;
        }
                    
                    
        </style>
    """, unsafe_allow_html=True)

        GUI()
    except Exception as e:
        st.error(f"Error running GUI: {str(e)}")
        return 1
    return 0

if __name__ == "__main__":
    status = gui_main()
    sys.exit(status)
