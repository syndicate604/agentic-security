#!/usr/bin/env python

import os
import random
import sys
import io
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
            st.title("Aider")
            self.do_add_to_chat()
            self.do_recent_msgs()
            self.do_clear_chat_history()
            self.do_model_settings()
            self.do_shell_commands()
            st.warning(
                "This browser version of aider is experimental. Please share feedback in [GitHub"
                " issues](https://github.com/Aider-AI/aider/issues)."
            )

    def do_add_to_chat(self):
        self.do_add_files()
        self.do_add_web_page()

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
                elif role in ("user", "assistant"):
                    with st.chat_message(role):
                        st.write(msg["content"])
                else:
                    st.dict(msg)

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
        self.coder = get_coder()
        self.state = get_state()

        self.coder.yield_stream = True
        self.coder.stream = True
        self.coder.pretty = False

        self.initialize_state()

        self.do_messages_container()
        self.do_sidebar()

        user_inp = st.chat_input("Say something")
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
        with st.sidebar.expander("Shell Commands", expanded=False):
            command = st.text_input("Shell Command:", placeholder="/run python test.py")
            share_output = st.checkbox("Share output with AI", value=True)
            
            if st.button("Run Command") and command:  # Only run if command is not empty
                with st.spinner("Running command..."):
                    try:
                        # Strip /run prefix if present
                        cmd = command.strip()
                        if cmd.startswith('/run '):
                            cmd = cmd[5:]
                        
                        # Clear any existing output
                        self.coder.commands.io.get_captured_lines()
                        
                        # Run the command and capture output
                        self.coder.commands.io.tool_output(f"Running: {cmd}")
                        result = self.coder.commands.cmd_run(cmd)
                        
                        # Get all captured output
                        output_lines = self.coder.commands.io.get_captured_lines()
                        output = "\n".join(output_lines) if output_lines else ""
                        
                        # Always show the command output in the UI
                        if output or result:  # Show output if we have any
                            final_output = output
                            if result and str(result).strip():
                                final_output += f"\nResult: {result}"
                            
                            # Display in Streamlit UI
                            st.text("Command Output:")
                            st.code(final_output)
                            
                            # If share output is enabled, also add to chat
                            if share_output:
                                self.prompt = f"Command output:\n```\n{final_output}\n```"
                                self.prompt_as = "text"
                        else:
                            st.info("Command executed successfully with no output")
                    except Exception as e:
                        st.error(f"Error executing command: {str(e)}")

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
                    # Store current model info before switching
                    old_model = getattr(self.coder, 'main_model', 'unknown')
                    
                    # Validate model exists before switching
                    if not hasattr(self.coder.commands, 'cmd_model'):
                        raise AttributeError("Model switching not supported in current configuration")
                    
                    # Attempt to switch model
                    result = self.coder.commands.cmd_model(model)
                    if not result:
                        raise ValueError(f"Failed to switch to model {model}")
                    
                    # Force reload coder with new model
                    if hasattr(st, 'cache_resource'):
                        st.cache_resource.clear()
                        self.coder = get_coder()
                    else:
                        raise RuntimeError("Cache resource not available")
                    
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
    # Set dark theme and custom styles
    st.set_page_config(
        layout="wide",
        page_title="Aider",
        page_icon=urls.favicon,
        menu_items={
            "Get Help": urls.website,
            "Report a bug": "https://github.com/Aider-AI/aider/issues",
            "About": "# Aider\nAI pair programming in your browser.",
        },
    )

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
        </style>
    """, unsafe_allow_html=True)

    GUI()

if __name__ == "__main__":
    status = gui_main()
    sys.exit(status)
