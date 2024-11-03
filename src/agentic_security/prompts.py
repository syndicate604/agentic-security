from typing import Dict, Optional

class PromptManager:
    DEFAULT_PROMPTS = {
        'architecture_review': """Review the architecture for security vulnerabilities and suggest improvements:
1. Identify potential security weaknesses
2. Suggest architectural improvements
3. Recommend security best practices
Analysis:""",
        
        'fix_generation': """Generate secure fixes for the following vulnerability:
{vulnerability_type} in file {file_path}
Consider:
1. Security best practices
2. Performance impact
3. Maintainability
Proposed fix:""",
        
        'pr_description': """Create a pull request description for the following security changes:
{changes}
Include:
1. Summary of changes
2. Security impact
3. Testing notes
Description:"""
    }

    def __init__(self, custom_prompts: Optional[Dict[str, str]] = None):
        self.prompts = self.DEFAULT_PROMPTS.copy()
        if custom_prompts:
            self.prompts.update(custom_prompts)

    def get_prompt(self, prompt_type: str, **kwargs) -> str:
        """Get formatted prompt"""
        if prompt_type not in self.prompts:
            raise ValueError(f"Unknown prompt type: {prompt_type}")
        return self.prompts[prompt_type].format(**kwargs)
