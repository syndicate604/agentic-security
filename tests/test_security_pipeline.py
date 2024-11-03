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
    
    # Create test results
    test_results = {
        'web': [],
        'code': [{'sql_injection': [{'file': 'test.py', 'type': 'sql_injection'}]}]
    }
    
    # Save test results to cache
    scan_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    pipeline.cache.save_scan_results(scan_id, test_results)
    
    # Verify cache exists using correct scan ID
    cached_results = pipeline.cache.get_scan_results(scan_id)
    assert cached_results is not None
    assert cached_results['results'] == test_results
    
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

def test_pipeline_error_handling(pipeline, test_config):
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

def test_pipeline_performance(pipeline, tmp_path):
    """Test pipeline performance and caching"""
    # Configure clean cache for test
    pipeline.cache = SecurityCache(str(tmp_path))
    
    # Use consistent scan ID
    scan_id = "test_scan_001"
    
    # Create test scan results
    test_results = {
        'web': [{'test': 'data'}],
        'code': [{'test': 'data'}]
    }
    
    # Pre-populate cache with test data
    pipeline.cache.save_scan_results(scan_id, test_results)
    
    # First pipeline run without cache
    pipeline.cache.clear_old_results(days=0)  # Clear cache
    start_time = time.time()
    pipeline.run_pipeline()
    first_run_time = time.time() - start_time
    
    # Second run - with populated cache
    pipeline.cache.save_scan_results(scan_id, test_results)  # Ensure cache is populated
    start_time = time.time()
    pipeline.run_pipeline()
    second_run_time = time.time() - start_time
    
    # Second run should be faster due to caching
    assert second_run_time < first_run_time, \
           f"Second run ({second_run_time:.2f}s) was not faster than first run ({first_run_time:.2f}s) - Cache not working correctly"

def test_review_functionality(pipeline, tmp_path):
    """Test security review functionality"""
    # Create test files with known patterns
    test_file1 = tmp_path / "test_vuln1.py"
    test_file1.write_text("""
    import os
    def unsafe_function():
        user_input = input()
        os.system(f"echo {user_input}")  # Command injection
    """)
    
    test_file2 = tmp_path / "test_vuln2.py"
    test_file2.write_text("""
    import sqlite3
    def db_query(user_id):
        query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL injection
        return query
    """)

    # Test review_paths method
    results = pipeline.review_paths([str(tmp_path)])
    assert results.get('reviews'), "Review results should not be empty"
    assert any('test_vuln1.py' in review['file'] for review in results['reviews'])
    assert any('test_vuln2.py' in review['file'] for review in results['reviews'])
    
    # Test review report generation
    report_file = tmp_path / "security_review.md"
    pipeline.generate_review_report(results, str(report_file))
    assert report_file.exists(), "Review report file should be created"
    
    # Verify report contents
    report_content = report_file.read_text()
    assert "Security Review Report" in report_content
    assert "Command injection" in report_content
    assert "SQL injection" in report_content

def test_review_output_formats(pipeline, tmp_path, capsys):
    """Test different review output formats"""
    # Create test file
    test_file = tmp_path / "test_security.py"
    test_file.write_text("""
    def insecure_function():
        eval(input())  # Dangerous eval usage
    """)
    
    # Test verbose output
    results = pipeline.review_paths([str(tmp_path)], verbose=True)
    pipeline.print_review_results(results, verbose=True)
    captured = capsys.readouterr()
    assert "Type:" in captured.out
    assert "Description:" in captured.out
    assert "Severity:" in captured.out
    
    # Test non-verbose output
    pipeline.print_review_results(results, verbose=False)
    captured = capsys.readouterr()
    assert "Type:" not in captured.out
    assert "-" in captured.out  # Should use simplified format

def test_review_with_cache(pipeline, tmp_path):
    """Test review functionality with caching"""
    # Create test file
    test_file = tmp_path / "cached_test.py"
    test_file.write_text("""
    password = "hardcoded_password"  # Security issue
    """)
    
    # First review - should cache results
    start_time = time.time()
    first_results = pipeline.review_paths([str(tmp_path)])
    first_run_time = time.time() - start_time
    
    # Second review - should use cache
    start_time = time.time()
    second_results = pipeline.review_paths([str(tmp_path)])
    second_run_time = time.time() - start_time
    
    # Verify cache effectiveness
    assert second_run_time < first_run_time, "Cached review should be faster"
    assert first_results == second_results, "Cached results should match"

def test_review_error_handling(pipeline, tmp_path):
    """Test error handling in review functionality"""
    # Test with non-existent path
    with pytest.raises(Exception) as exc_info:
        pipeline.review_paths([str(tmp_path / "non_existent")])
    assert "not found" in str(exc_info.value).lower()
    
    # Test with invalid file type
    invalid_file = tmp_path / "test.invalid"
    invalid_file.write_text("some content")
    results = pipeline.review_paths([str(tmp_path)])
    assert not any(review['file'].endswith('.invalid') 
                  for review in results.get('reviews', []))

def test_cli_review_integration(pipeline, tmp_path):
    """Test CLI review command integration"""
    # Create test file
    test_file = tmp_path / "cli_test.py"
    test_file.write_text("""
    import pickle
    def unsafe_load(data):
        return pickle.loads(data)  # Insecure deserialization
    """)
    
    # Test CLI review command
    from click.testing import CliRunner
    from src.agentic_security.security_cli import review
    
    runner = CliRunner()
    result = runner.invoke(review, ['--path', str(tmp_path),
                                  '--output', str(tmp_path / 'review.md'),
                                  '--verbose'])
    
    assert result.exit_code == 0
    assert (tmp_path / 'review.md').exists()
    
    # Test without output file
    result = runner.invoke(review, ['--path', str(tmp_path)])
    assert result.exit_code == 0
    assert "Security Review" in result.output

@pytest.mark.parametrize('test_file,expected_findings', [
    ('sql_injection.py', ['sql_injection']),
    ('command_injection.py', ['command_injection']),
    ('xss_vulnerability.py', ['xss']),
    ('crypto_weak.py', ['weak_crypto']),
])
def test_specific_vulnerability_detection(pipeline, tmp_path, test_file, expected_findings):
    """Test detection of specific vulnerability types"""
    # Create test files with specific vulnerabilities
    vulnerability_samples = {
        'sql_injection.py': 'query = f"SELECT * FROM users WHERE id = {user_id}"',
        'command_injection.py': 'os.system(f"echo {user_input}")',
        'xss_vulnerability.py': 'html = f"<div>{user_input}</div>"',
        'crypto_weak.py': 'hashlib.md5(password.encode()).hexdigest()',
    }
    
    test_path = tmp_path / test_file
    test_path.write_text(vulnerability_samples[test_file])
    
    results = pipeline.review_paths([str(tmp_path)])
    findings = [finding['type'] for review in results['reviews'] 
               for finding in review['findings']]
    
    for expected in expected_findings:
        assert expected in findings, f"Failed to detect {expected} vulnerability"
