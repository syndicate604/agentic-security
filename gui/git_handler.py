import streamlit as st
from typing import Optional, Tuple, List
from aider.coders import Coder
from aider.repo import ANY_GIT_ERROR

class GitHandler:
    def __init__(self, coder: Coder):
        """Initialize with an existing coder instance"""
        self.coder = coder
        self.repo = coder.repo
    
    def get_status(self) -> Tuple[str, Optional[str]]:
        """Get git status with error handling"""
        try:
            return self.repo.git_status(), None
        except ANY_GIT_ERROR as e:
            return "", str(e)
    
    def get_recent_commits(self, num: int = 5) -> Tuple[List[dict], Optional[str]]:
        """Get recent commit history"""
        try:
            output = self.repo.run_git_command(f"log --oneline -n {num}")
            commits = []
            for line in output.splitlines():
                if line.strip():
                    hash_, *msg_parts = line.split(' ')
                    commits.append({
                        'hash': hash_,
                        'message': ' '.join(msg_parts)
                    })
            return commits, None
        except ANY_GIT_ERROR as e:
            return [], str(e)
    
    def create_commit(self, message: str) -> Tuple[bool, Optional[str]]:
        """Create a new commit"""
        try:
            self.coder.commands.cmd_commit(message)
            return True, None
        except ANY_GIT_ERROR as e:
            return False, str(e)
    
    def get_diff(self, file: Optional[str] = None) -> Tuple[str, Optional[str]]:
        """Get diff for staged/unstaged changes"""
        try:
            if file:
                return self.repo.run_git_command(f"diff {file}"), None
            return self.repo.run_git_command("diff"), None
        except ANY_GIT_ERROR as e:
            return "", str(e)
    
    def get_branches(self) -> Tuple[List[str], Optional[str]]:
        """Get list of branches"""
        try:
            output = self.repo.run_git_command("branch")
            branches = [b.strip('* ') for b in output.splitlines()]
            return branches, None
        except ANY_GIT_ERROR as e:
            return [], str(e)
    
    def switch_branch(self, branch: str) -> Tuple[bool, Optional[str]]:
        """Switch to specified branch"""
        try:
            self.repo.run_git_command(f"checkout {branch}")
            return True, None
        except ANY_GIT_ERROR as e:
            return False, str(e)
    
    def create_branch(self, branch: str) -> Tuple[bool, Optional[str]]:
        """Create and switch to new branch"""
        try:
            self.repo.run_git_command(f"checkout -b {branch}")
            return True, None
        except ANY_GIT_ERROR as e:
            return False, str(e)

def render_git_sidebar(git_handler: GitHandler):
    """Render git controls in streamlit sidebar"""
    with st.sidebar.expander("Git Operations", expanded=False):
        # Status section
        st.markdown("### Git Status")
        status, error = git_handler.get_status()
        if error:
            st.error(f"Error getting status: {error}")
        elif status:
            with st.expander("Current Status", expanded=True):
                st.code(status)
        
        # Branch management
        st.markdown("### Branch Management")
        branches, error = git_handler.get_branches()
        if error:
            st.error(f"Error getting branches: {error}")
        else:
            current_branch = next((b for b in branches if b.startswith('* ')), '').strip('* ')
            selected_branch = st.selectbox("Switch Branch", branches)
            if selected_branch != current_branch:
                if st.button(f"Switch to {selected_branch}"):
                    success, error = git_handler.switch_branch(selected_branch)
                    if error:
                        st.error(f"Error switching branch: {error}")
                    else:
                        st.success(f"Switched to {selected_branch}")
                        st.rerun()
        
        # New branch creation
        new_branch = st.text_input("New Branch Name")
        if new_branch and st.button("Create Branch"):
            success, error = git_handler.create_branch(new_branch)
            if error:
                st.error(f"Error creating branch: {error}")
            else:
                st.success(f"Created and switched to {new_branch}")
                st.rerun()
        
        # Commit section
        st.markdown("### Commit Changes")
        commit_msg = st.text_input("Commit Message")
        if commit_msg and st.button("Commit"):
            success, error = git_handler.create_commit(commit_msg)
            if error:
                st.error(f"Error creating commit: {error}")
            else:
                st.success("Changes committed successfully")
                st.rerun()
        
        # Recent commits
        st.markdown("### Recent Commits")
        commits, error = git_handler.get_recent_commits()
        if error:
            st.error(f"Error getting commits: {error}")
        else:
            for commit in commits:
                with st.expander(f"{commit['hash']}: {commit['message'][:40]}...", expanded=False):
                    st.code(f"Hash: {commit['hash']}\nMessage: {commit['message']}")
        
        # Diff viewer
        st.markdown("### View Changes")
        diff, error = git_handler.get_diff()
        if error:
            st.error(f"Error getting diff: {error}")
        elif diff:
            with st.expander("Current Changes", expanded=False):
                st.code(diff)
        
        # Help section
        with st.expander("Git Help", expanded=False):
            st.markdown("""
            ### Available Operations
            - View current git status
            - Switch between branches
            - Create new branches
            - Commit changes
            - View recent commit history
            - View current changes (diff)
            
            For more complex operations, please use the terminal or your git client.
            """)
