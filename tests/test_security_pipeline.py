import pytest
import os
import yaml
import time
from datetime import datetime
from pathlib import Path
from src.agentic_security.security_pipeline import SecurityPipeline
from src.agentic_security.cache import SecurityCache
from src.agentic_security.progress import ProgressReporter
from src.agentic_security.prompts import PromptManager

@pytest.fixture
def test_config(tmp_path):
    """Create a test configuration file"""
    config = {
        'security': {
            'critical_threshold': 7.0,
            'max_fix_attempts': 3,
            'scan_targets': [
                {'type': 'web', 'url': 'http://localhost:8080'},
                {'type': 'code', 'path': './src'}
            ]
        }
    }
    config_file = tmp_path / 'test_config.yml'
    with open(config_file, 'w') as f:
        yaml.dump(config, f)
    return str(config_file)

@pytest.fixture
def pipeline(test_config):
    """Create a SecurityPipeline instance"""
    return SecurityPipeline(test_config)

def test_pipeline_initialization(pipeline, test_config):
    """Test pipeline initialization"""
    assert pipeline.config['security']['critical_threshold'] == 7.0
    assert pipeline.config['security']['max_fix_attempts'] == 3
    assert len(pipeline.config['security']['scan_targets']) == 2

def test_code_security_checks(pipeline, tmp_path):
    """Test code security scanning"""
    # Create test file with known vulnerabilities
    test_file = tmp_path / "test_vuln.py"
    test_file.write_text("""
import os

def process_input(user_input):
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_input}"
    
    # Command Injection vulnerability
    os.system(f"echo {user_input}")
    
    # XSS vulnerability
    html = f"<div>{user_input}</div>"
    """)

    results = pipeline._run_code_security_checks(str(tmp_path))
    
    # Check for expected vulnerabilities
    assert 'sql_injection' in results
    assert 'command_injection' in results
    assert any('test_vuln.py' in finding['file'] for finding in results['sql_injection'])

def test_validate_fixes(pipeline, tmp_path):
    """Test fix validation"""
    # Create test file with fixes applied
    test_file = tmp_path / "test_fixed.py"
    test_file.write_text("""
import sqlite3
from html import escape
import subprocess
import shlex

def process_input(user_input):
    # SQL Injection fixed
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))
    
    # Command Injection fixed
    subprocess.run(['echo', user_input], check=True)
    
    # XSS fixed
    html = f"<div>{escape(user_input)}</div>"
    """)

    assert pipeline.validate_fixes()

def test_create_fix_branch(pipeline):
    """Test branch creation"""
    assert pipeline.create_fix_branch()
    # Verify branch exists
    import subprocess
    result = subprocess.run(['git', 'branch', '--list', pipeline.branch_name], 
                          capture_output=True, text=True)
    assert pipeline.branch_name in result.stdout

def test_run_pipeline(pipeline):
    """Test complete pipeline execution"""
    assert pipeline.run_pipeline()

def test_cache_integration(pipeline, tmp_path):
    """Test cache integration in pipeline"""
    # Set cache directory to tmp_path
    pipeline.cache = SecurityCache(str(tmp_path))
    
    # Run pipeline to generate cache
    pipeline.run_pipeline()
    
    # Get today's scan ID
    scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Verify cache exists using correct scan ID
    cached_results = pipeline.cache.get_scan_results(scan_id)
    assert cached_results is not None
    
    # Verify cache cleanup
    pipeline.cache.clear_old_results(days=0)
    assert pipeline.cache.get_scan_results(scan_id) is None

def test_progress_reporting(pipeline, capsys):
    """Test progress reporting integration"""
    pipeline.progress.start("Test progress")
    pipeline.progress.update(50, "Halfway")
    pipeline.progress.finish("Complete")
    
    captured = capsys.readouterr()
    assert "Test progress" in captured.out
    assert "Halfway" in captured.out
    assert "Complete" in captured.out

def test_custom_prompts(pipeline):
    """Test custom prompt integration"""
    custom_prompts = {
        'test_prompt': "Custom test prompt: {test_var}"
    }
    pipeline.prompt_manager = PromptManager(custom_prompts)
    
    # Test default prompt
    arch_prompt = pipeline.prompt_manager.get_prompt('architecture_review')
    assert "Review the architecture" in arch_prompt
    
    # Test custom prompt
    test_prompt = pipeline.prompt_manager.get_prompt('test_prompt', test_var="value")
    assert "Custom test prompt: value" in test_prompt

def test_pipeline_error_handling(pipeline):
    """Test pipeline error handling"""
    # Test invalid config
    invalid_config = pipeline.config.copy()
    invalid_config['security']['critical_threshold'] = -1
    invalid_config_file = Path(test_config).parent / 'invalid_config.yml'
    with open(invalid_config_file, 'w') as f:
        yaml.dump(invalid_config, f)
    with pytest.raises(ValueError):
        # This should raise ValueError during initialization
        SecurityPipeline(str(invalid_config_file))
    
    # Test missing dependencies
    pipeline.config['security']['scan_targets'] = [
        {'type': 'invalid', 'url': 'http://example.com'}
    ]
    assert not pipeline.run_pipeline()

def test_pipeline_performance(pipeline):
    """Test pipeline performance and caching"""
    # First run - should take normal time
    start_time = time.time()
    pipeline.run_pipeline()
    first_run_time = time.time() - start_time
    
    # Second run - should be faster due to caching
    start_time = time.time()
    pipeline.run_pipeline()
    second_run_time = time.time() - start_time
    
    # Second run should be faster due to caching
    assert second_run_time < first_run_time
