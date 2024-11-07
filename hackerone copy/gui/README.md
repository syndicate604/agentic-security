# AI Hacker Fix - HackerOne Submission GUI

A Streamlit-based GUI application for analyzing vulnerabilities and submitting bug reports to HackerOne with AI-powered assistance.

## Features

- 🎨 Dark mode interface
- 🤖 AI-powered vulnerability analysis using LiteLLM
- 📊 Interactive report generation
- 🔄 Real-time code analysis
- 📝 Markdown support for reports
- 🔒 Secure API credential handling
- 📋 Multi-tab report management

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure environment:
```bash
cp ../.env.example .env
```

3. Edit `.env` with your API keys:
```env
HACKERONE_API_USERNAME=your_username
HACKERONE_API_TOKEN=your_token
OPENAI_API_KEY=your_openai_key
```

## Usage

Start the Streamlit app:
```bash
streamlit run app.py
```

Or use the run script:
```bash
./run.py
```

## Development

### Project Structure

```
gui/
├── app.py              # Main Streamlit application
├── config.py           # Configuration settings
├── utils.py           # Utility functions
├── run.py             # Application runner
├── requirements.txt   # Dependencies
└── tests/            # Test suite
```

### Testing

The project includes a comprehensive test suite with:
- Unit tests
- Integration tests
- UI component tests
- Coverage reporting

#### Running Tests

Using Python script (cross-platform):
```bash
./run_tests.py [options]
```

Options:
- `--fail-fast`: Stop on first failure
- `--last-failed`: Run only failed tests
- `--markers`: Run tests with specific markers (e.g., "streamlit" or "integration")

Using shell script (Unix/Linux):
```bash
./run_tests.sh
```

#### Test Structure

1. **Unit Tests**
   - `test_utils.py`: Utility function tests
   - `test_config.py`: Configuration tests
   - `test_run.py`: Runner script tests

2. **Integration Tests**
   - `test_app.py`: Main application tests
   - Tests marked with `@pytest.mark.integration`

3. **UI Tests**
   - Streamlit component tests
   - Tests marked with `@pytest.mark.streamlit`

#### Test Configuration

- `pytest.ini`: Test settings and markers
- `conftest.py`: Shared fixtures and configuration
- Coverage settings in `pytest.ini`

#### Test Reports

Running tests generates:
1. Terminal output with test results
2. Coverage report (`htmlcov/index.html`)
3. Coverage badge (`coverage-badge.svg`)
4. Test report (`test-report.md`)

### Test Markers

- `@pytest.mark.streamlit`: UI component tests
- `@pytest.mark.integration`: Integration tests
- `@pytest.mark.slow`: Long-running tests

### Fixtures

Common test fixtures in `conftest.py`:
- `test_env`: Environment variables
- `mock_streamlit`: Streamlit components
- `mock_litellm`: AI responses
- `mock_hackerone_api`: API client
- `temp_dir`: Temporary directory
- `sample_report_file`: Test report data

## Features in Detail

### Settings Page
- HackerOne API configuration
- OpenAI/LiteLLM configuration
- Interface customization

### Analysis Page
- Code input area
- Vulnerability type selection
- AI-powered analysis
- Real-time feedback

### Reports Page
- Multi-tab report view
- Report editing
- Severity adjustment
- Impact assessment

### Submit Page
- Report selection
- Submission status tracking
- Response viewing
- Error handling

## AI Analysis

The application uses LiteLLM to:
1. Analyze code for vulnerabilities
2. Generate detailed reports
3. Suggest security fixes
4. Assess severity and impact

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

### Development Guidelines

1. **Code Style**
   - Follow PEP 8
   - Use type hints
   - Add docstrings

2. **Testing**
   - Write tests for new features
   - Maintain coverage above 80%
   - Include integration tests

3. **Documentation**
   - Update README as needed
   - Document new features
   - Add code comments

## Support

For issues and questions:
1. Check existing issues
2. Review documentation
3. Run tests with `-v` flag
4. Submit detailed bug reports

## License

MIT License - See parent project for details
