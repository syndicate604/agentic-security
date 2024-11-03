import pytest
from pathlib import Path
from src.agentic_security.cache import SecurityCache
from src.agentic_security.prompts import PromptManager
from src.agentic_security.progress import ProgressReporter

def test_security_cache(tmp_path):
    """Test cache functionality"""
    cache = SecurityCache(str(tmp_path))
    
    # Test saving results
    results = {"test": "data"}
    cache.save_scan_results("test_scan", results)
    
    # Test retrieving results
    cached = cache.get_scan_results("test_scan")
    assert cached['results'] == results
    
    # Test clearing old results
    cache.clear_old_results(days=0)
    assert cache.get_scan_results("test_scan") is None

def test_prompt_manager():
    """Test prompt management"""
    custom_prompts = {
        'custom_review': "Custom review prompt"
    }
    
    manager = PromptManager(custom_prompts)
    
    # Test default prompt
    arch_prompt = manager.get_prompt('architecture_review')
    assert "Review the architecture" in arch_prompt
    
    # Test custom prompt
    custom_prompt = manager.get_prompt('custom_review')
    assert custom_prompt == "Custom review prompt"
    
    # Test formatted prompt
    fix_prompt = manager.get_prompt('fix_generation', 
                                  vulnerability_type="SQL Injection",
                                  file_path="test.py")
    assert "SQL Injection" in fix_prompt
    assert "test.py" in fix_prompt

def test_progress_reporter(capsys):
    """Test progress reporting"""
    reporter = ProgressReporter(total_steps=100)
    
    # Test progress updates
    reporter.start("Starting")
    captured = capsys.readouterr()
    assert "Starting" in captured.out
    assert "0%" in captured.out
    
    reporter.update(50, "Halfway")
    captured = capsys.readouterr()
    assert "Halfway" in captured.out
    assert "50%" in captured.out
    
    reporter.finish("Done")
    captured = capsys.readouterr()
    assert "Done" in captured.out
    assert "100%" in captured.out
