import pytest
import os
import yaml
from pathlib import Path
from src.agentic_security.security_pipeline import SecurityPipeline

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
