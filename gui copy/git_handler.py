import streamlit as st
import subprocess
from typing import Optional, List, Tuple

class SimpleGitHandler:
    def get_status(self) -> str:
        """Get git status"""
        try:
            result = subprocess.run(['git', 'status'], capture_output=True, text=True)
            return result.stdout
        except Exception as e:
            return f"Error: {str(e)}"
    
    def get_recent_commits(self, num: int = 5) -> List[dict]:
        """Get recent commits"""
        try:
            result = subprocess.run(
                ['git', 'log', f'-{num}', '--oneline'], 
                capture_output=True, 
                text=True
            )
            commits = []
            for line in result.stdout.splitlines():
                if line.strip():
                    hash_, *msg_parts = line.split(' ')
                    commits.append({
                        'hash': hash_,
                        'message': ' '.join(msg_parts)
                    })
            return commits
        except Exception:
            return []

    def get_current_branch(self) -> str:
        """Get current branch name"""
        try:
            result = subprocess.run(
                ['git', 'branch', '--show-current'],
                capture_output=True,
                text=True
            )
            return result.stdout.strip()
        except Exception:
            return "unknown"

def render_git_sidebar():
    """Render simple git info in sidebar"""
    git = SimpleGitHandler()
    
    with st.sidebar.expander("Git Info", expanded=False):
        # Current branch
        st.markdown(f"**Current Branch:** {git.get_current_branch()}")
        
        # Git status
        st.markdown("### Git Status")
        status = git.get_status()
        if status:
            with st.expander("Show Status", expanded=False):
                st.code(status)
        
        # Recent commits
        st.markdown("### Recent Commits")
        commits = git.get_recent_commits(5)
        for commit in commits:
            with st.expander(f"{commit['hash']}: {commit['message'][:40]}...", expanded=False):
                st.code(f"Hash: {commit['hash']}\nMessage: {commit['message']}")
