import subprocess
from typing import Tuple, Optional, List, Dict
from aider.coders import Coder

class GitHubActionsHandler:
    def __init__(self, coder: Coder):
        """Initialize with an existing coder instance"""
        self.coder = coder
        self.repo_path = coder.repo.git_dir.parent if coder.repo else None
        
    def list_workflows(self) -> Tuple[Optional[List[Dict]], Optional[str]]:
        """List GitHub Actions workflows"""
        try:
            result = subprocess.run(
                ['gh', 'workflow', 'list'],
                capture_output=True,
                text=True,
                cwd=self.repo_path
            )
            if result.returncode == 0:
                workflows = []
                for line in result.stdout.splitlines():
                    if line.strip():
                        # Parse workflow line into name and state
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            workflows.append({
                                'name': parts[0].strip(),
                                'state': parts[1].strip()
                            })
                return workflows, None
            return None, result.stderr
        except Exception as e:
            return None, str(e)

    def get_workflow_runs(self, workflow_name: str) -> Tuple[Optional[List[Dict]], Optional[str]]:
        """Get recent runs for a specific workflow"""
        try:
            result = subprocess.run(
                ['gh', 'run', 'list', '-w', workflow_name],
                capture_output=True,
                text=True,
                cwd=self.repo_path
            )
            if result.returncode == 0:
                runs = []
                for line in result.stdout.splitlines():
                    if line.strip():
                        # Parse run line into components
                        parts = line.split('\t')
                        if len(parts) >= 3:
                            runs.append({
                                'status': parts[0].strip(),
                                'title': parts[1].strip(),
                                'id': parts[2].strip()
                            })
                return runs, None
            return None, result.stderr
        except Exception as e:
            return None, str(e)

    def run_workflow(self, workflow_name: str) -> Tuple[Optional[str], Optional[str]]:
        """Manually trigger a workflow"""
        try:
            result = subprocess.run(
                ['gh', 'workflow', 'run', workflow_name],
                capture_output=True,
                text=True,
                cwd=self.repo_path
            )
            return result.stdout.strip() if result.stdout else None, \
                   result.stderr.strip() if result.stderr else None
        except Exception as e:
            return None, str(e)

    def get_run_logs(self, run_id: str) -> Tuple[Optional[str], Optional[str]]:
        """Get logs for a specific workflow run"""
        try:
            result = subprocess.run(
                ['gh', 'run', 'view', run_id, '--log'],
                capture_output=True,
                text=True,
                cwd=self.repo_path
            )
            return result.stdout.strip() if result.stdout else None, \
                   result.stderr.strip() if result.stderr else None
        except Exception as e:
            return None, str(e)
