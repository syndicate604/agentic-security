import pytest
import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch
import subprocess
import run

@pytest.fixture
def mock_env():
    """Mock environment variables"""
    original_env = os.environ.copy()
    os.environ.update({
        "HACKERONE_API_USERNAME": "test_user",
        "HACKERONE_API_TOKEN": "test_token",
        "OPENAI_API_KEY": "test_key"
    })
    yield
    os.environ.clear()
    os.environ.update(original_env)

@pytest.fixture
def mock_dependencies():
    """Mock dependency imports"""
    with patch.dict('sys.modules', {
        'streamlit': Mock(),
        'litellm': Mock(),
        'markdown': Mock()
    }):
        yield

def test_check_dependencies(mock_dependencies):
    """Test dependency checking"""
    assert run.check_dependencies() is True
    
    # Test missing dependency
    with patch.dict('sys.modules', {'streamlit': None}):
        assert run.check_dependencies() is False

@patch('subprocess.check_call')
def test_install_dependencies(mock_subprocess):
    """Test dependency installation"""
    # Test successful installation
    mock_subprocess.return_value = 0
    assert run.install_dependencies() is True
    
    # Test failed installation
    mock_subprocess.side_effect = subprocess.CalledProcessError(1, 'pip')
    assert run.install_dependencies() is False

def test_setup_environment(mock_env, tmp_path):
    """Test environment setup"""
    # Mock config directories
    with patch('run.REPORTS_DIR', tmp_path / "reports"):
        with patch('run.CACHE_DIR', tmp_path / "cache"):
            run.setup_environment()
            
            # Check directories were created
            assert (tmp_path / "reports").exists()
            assert (tmp_path / "cache").exists()
            
            # Check environment variables
            assert os.getenv("HACKERONE_API_USERNAME") == "test_user"
            assert os.getenv("HACKERONE_API_TOKEN") == "test_token"
            assert os.getenv("OPENAI_API_KEY") == "test_key"

@patch('subprocess.run')
def test_run_app(mock_subprocess):
    """Test application startup"""
    # Test normal startup
    run.run_app(port=8501)
    mock_subprocess.assert_called_once()
    
    # Verify command arguments
    args = mock_subprocess.call_args[0][0]
    assert "streamlit" in args
    assert "8501" in args
    
    # Test debug mode
    run.run_app(port=8501, debug=True)
    assert os.getenv("STREAMLIT_DEBUG") == "true"
    assert "--logger.level=debug" in mock_subprocess.call_args[0][0]
    
    # Test subprocess error
    mock_subprocess.side_effect = Exception("Test error")
    with pytest.raises(SystemExit):
        run.run_app()

@patch('run.run_app')
@patch('run.check_dependencies')
@patch('run.setup_environment')
def test_main(mock_setup, mock_check, mock_run):
    """Test main entry point"""
    # Test normal execution
    mock_check.return_value = True
    sys.argv = ["run.py"]
    run.main()
    
    mock_check.assert_called_once()
    mock_setup.assert_called_once()
    mock_run.assert_called_once_with(port=8501, debug=False)
    
    # Test with custom port and debug mode
    sys.argv = ["run.py", "--port", "8502", "--debug"]
    run.main()
    mock_run.assert_called_with(port=8502, debug=True)
    
    # Test dependency check failure
    mock_check.return_value = False
    with pytest.raises(SystemExit):
        run.main()

@patch('run.install_dependencies')
def test_main_install_deps(mock_install):
    """Test dependency installation from main"""
    # Test successful installation
    mock_install.return_value = True
    sys.argv = ["run.py", "--install-deps"]
    
    with patch('run.check_dependencies', return_value=True):
        with patch('run.setup_environment'):
            with patch('run.run_app'):
                run.main()
                mock_install.assert_called_once()
    
    # Test failed installation
    mock_install.return_value = False
    with pytest.raises(SystemExit):
        run.main()

def test_script_execution():
    """Test script execution as main"""
    with patch('run.main') as mock_main:
        # Execute the script
        exec(open('run.py').read())
        mock_main.assert_called_once()

if __name__ == '__main__':
    pytest.main([__file__, "-v"])
