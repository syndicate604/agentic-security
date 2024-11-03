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
        
        'pr_description': """Create a detailed pull request description for these security changes:
{changes}

Please include:
1. Summary of Security Changes
   - List each vulnerability fixed
   - Impact of each fix
   - Files modified

2. Security Impact Analysis
   - Risk level before/after changes
   - Attack vectors addressed
   - Potential side effects

3. Testing & Validation
   - Security tests performed
   - Manual validation steps
   - Regression testing results

4. Implementation Notes
   - Security best practices applied
   - Dependencies updated
   - Configuration changes

Description:"""
    }

    def __init__(self, custom_prompts: Optional[Dict[str, str]] = None):
        self.prompts = self.DEFAULT_PROMPTS.copy()
        if custom_prompts:
            self.prompts.update(custom_prompts)

    def sanitize_input(self, input_str: str) -> str:
        """Sanitize input strings for AI prompts
        
        Args:
            input_str: Input string to sanitize
            
        Returns:
            Sanitized string safe for AI prompts
        """
        if not isinstance(input_str, str):
            input_str = str(input_str)
            
        # Remove any potentially problematic characters
        sanitized = input_str.replace('"', '\\"')  # Escape quotes
        sanitized = sanitized.replace('$', '\\$')  # Escape dollar signs
        sanitized = sanitized.replace('`', '\\`')  # Escape backticks
        
        # Limit length
        max_length = 8000  # Reasonable limit for most AI models
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length] + "..."
            
        return sanitized
        
    def get_prompt(self, prompt_type: str, **kwargs) -> str:
        """Get formatted prompt"""
        if prompt_type not in self.prompts:
            raise ValueError(f"Unknown prompt type: {prompt_type}")
        return self.prompts[prompt_type].format(**kwargs)
