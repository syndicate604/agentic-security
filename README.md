# Agentic Security

Automated security scanning and fixing (code,arch,ml/devops) pipeline using AI-powered tools with a cyberpunk-themed interface.

The pipeline combines OWASP ZAP scans with AI-driven analysis, catching architectural flaws through explicit prompting at design, implementation, and testing phases. For red teaming, it integrates automated vulnerability assessments with AI-guided fixes, which are deployed to a new branch for manual review.

**Created by rUv, cause he could.**

## Documentation

📚 [View Full Documentation](docs/README.md)

### Quick Links
- 🏗️ [Architecture Guide](docs/architecture/README.md)
- 🛠️ [Implementation Guide](docs/implementation/README.md)
- 📖 [User Guide](docs/user-guide/README.md)
- 🚀 [Future Enhancements](docs/future/README.md)

## Capabilities & Roadmap

### Current Features
### Architecture & Code Analysis

| Emoji | Feature                 | Description                                         | Status | Documentation                                                                                   |
|-------|--------------------------|-----------------------------------------------------|--------|-------------------------------------------------------------------------------------------------|
| 🧠    | AI Architecture Analysis | Ai powered security architecture review and recommendations (Over 120+ Ai models)))| ✅    | [Documentation](docs/implementation/README.md#ai-integration)                                     |
| 🛠️    | Auto AI Code Generation       | Claude-3 Sonnet 3.5 powered secure code generation             | ✅    | [User Guide](docs/user-guide/README.md#advanced-features)                                        |
| 🎭    | Context Analysis         | AI-powered code context understanding               | ✅    | [Documentation](docs/implementation/README.md#security-patterns)                                 |
| 📚    | Code Documentation       | AI-generated security documentation                 | ✅    | [Documentation](docs/implementation/README.md#ai-integration)                                     |

### Vulnerability Detection & Analysis

| Emoji | Feature                 | Description                                         | Status | Documentation                                                                                   |
|-------|--------------------------|-----------------------------------------------------|--------|-------------------------------------------------------------------------------------------------|
| 🔍    | AI Pattern Recognition   | Context-aware vulnerability pattern detection       | ✅    | [Documentation](docs/implementation/README.md#security-patterns)                                 |
| 📈    | Risk Assessment          | AI-based security risk scoring and analysis         | ✅    | [User Guide](docs/user-guide/README.md#pattern-based-security-analysis)                          |
| 📊    | AI Severity Analysis     | CVSS-based vulnerability assessment and prioritization | ✅    | [User Guide](docs/user-guide/README.md#pattern-based-security-analysis)                          |
| 🔍    | SQL Injection AI         | Machine learning pattern matching for SQL vulnerabilities | ✅    | [Documentation](docs/implementation/README.md#security-patterns)                                 |
| 🛡️    | Command Injection AI     | AI-powered shell injection detection                | ✅    | [Documentation](docs/implementation/README.md#security-patterns)                                 |
| 🌐    | XSS AI Detection         | Neural pattern matching for XSS vulnerabilities     | ✅    | [Documentation](docs/implementation/README.md#security-patterns)                                 |
| 🔒    | Crypto AI Analysis       | AI-driven cryptographic weakness detection          | ✅    | [Documentation](docs/implementation/README.md#security-patterns)                                 |

### Fixes & Remediation

| Emoji | Feature                   | Description                                           | Status | Documentation                                                                                   |
|-------|----------------------------|-------------------------------------------------------|--------|-------------------------------------------------------------------------------------------------|
| 🎯    | AI Fix Validation          | Automated fix verification with test generation       | ✅    | [User Guide](docs/user-guide/README.md#advanced-features)                                        |
| 🔄    | Recursive Fix Logic        | AI-driven iterative fix attempts with validation      | ✅    | [Documentation](docs/implementation/README.md#ai-integration)                                     |
| 🎯    | Smart Fix Suggestions      | Context-aware security fix recommendations            | ✅    | [User Guide](docs/user-guide/README.md#advanced-features)                                        |
| 🔄    | Auto Branch Creation       | AI-managed fix branch workflow                        | ✅    | [Documentation](docs/implementation/README.md#git-integration)                                   |
| 🎯    | Fix Prioritization         | AI-based vulnerability prioritization                 | ✅    | [User Guide](docs/user-guide/README.md#advanced-features)                                        |

### Test & Validation

| Emoji | Feature                 | Description                                         | Status | Documentation                                                                                   |
|-------|--------------------------|-----------------------------------------------------|--------|-------------------------------------------------------------------------------------------------|
| 📝    | Smart PR Generation      | AI-generated security-focused pull request descriptions | ✅    | [Documentation](docs/implementation/README.md#git-integration)                                   |
| 🧪    | AI Test Generation       | Automated security test case creation               | ✅    | [Documentation](docs/implementation/README.md#security-patterns)                                 |

### Workflow & Pipeline Management

| Emoji | Feature                   | Description                                           | Status | Documentation                                                                                   |
|-------|----------------------------|-------------------------------------------------------|--------|-------------------------------------------------------------------------------------------------|
| 🤖    | Multi-Model Pipeline       | Orchestrated GPT-4 and Claude-3 workflow              | ✅    | [Documentation](docs/implementation/README.md#ai-model-configuration)                            |
| 🎨    | Smart CLI                  | AI-powered command suggestions and help               | ✅    | [User Guide](docs/user-guide/README.md#cli-interface)                                           |
| 📋    | Progress Analysis          | AI-driven progress tracking and estimation            | ✅    | [User Guide](docs/user-guide/README.md#cli-interface)                                           |
| ⚡    | Smart Caching              | AI-optimized result caching system                    | ✅    | [Documentation](docs/implementation/README.md#cache-configuration)                               |
| 🔔    | Intelligent Alerts         | Context-aware security notifications                  | ✅    | [Documentation](docs/implementation/README.md#notifications)                                     |

### Reporting & Documentation

| Emoji | Feature                   | Description                                           | Status | Documentation                                                                                   |
|-------|----------------------------|-------------------------------------------------------|--------|-------------------------------------------------------------------------------------------------|
| 📊    | Report Generation          | AI-enhanced security report creation                  | ✅    | [User Guide](docs/user-guide/README.md#review-system)                                           |
| 🔍    | Dependency Analysis        | AI-powered dependency vulnerability assessment        | ✅    | [User Guide](docs/user-guide/README.md#advanced-features)                                        |

### Coming Soon

| Emoji | Feature | Description | Timeline | Details |
|-------|---------|-------------|----------|----------|
| 📡 | Real-time Monitoring | Live vulnerability monitoring system | 2024-Q2 | [Future Plans](docs/future/README.md#next-steps) |
| 🧠 | ML Pattern Detection | Machine learning-based vulnerability detection | 2024-Q2 | [AI Components](docs/future/README.md#ai-components) |
| ✔️ | Enhanced Validation | Advanced fix validation system | 2024-Q2 | [Future Plans](docs/future/README.md#automation-features) |
| ☁️ | Cloud Security | Cloud infrastructure security scanning | 2024-Q3 | [Security Components](docs/future/README.md#infrastructure-security) |
| 🔒 | SAST Integration | Static Application Security Testing integration | 2024-Q2 | [Security Components](docs/future/README.md#advanced-vulnerability-assessment) |
| 🛡️ | Container Security | Advanced container scanning and protection | 2024-Q3 | [Security Components](docs/future/README.md#container-security) |
| 🤝 | DevSecOps Pipeline | Enhanced security pipeline integration | 2024-Q3 | [Integration Points](docs/future/README.md#devsecops-pipeline) |
| 📈 | Analytics Dashboard | Security metrics and trend analysis | 2024-Q4 | [Automation Features](docs/future/README.md#reporting-and-analytics) |
| 🔄 | Rollback System | Automated rollback for failed fixes | 2024-Q2 | [Automation Features](docs/future/README.md#rollback-mechanisms) |
| 🧪 | Advanced Testing | Comprehensive security testing suite | 2024-Q3 | [Automation Features](docs/future/README.md#advanced-testing) |

## Features

1. **Comprehensive Security Checks**:
   - **OWASP ZAP** for web vulnerability scanning
   - **Nuclei** for known vulnerability detection
   - **Dependency checking** for outdated components

2. **Intelligent Fix Pipeline**:
   - Uses **OpenAI's `o1-preview`** as an architect to analyze issues
   - Employs **Claude 3.5 Sonnet** for code implementation
   - **Recursive fix attempts** with test validation

3. **Security Best Practices**:
   - Follows **OWASP Top 10** vulnerability checks
   - Implements proper **access controls** and **authentication**
   - Uses **secure communication protocols**

4. **Automated Workflow**:
   - Creates **separate branch** for fixes
   - Runs **daily automated checks**
   - **Notifies admin** of results
   - Creates **pull request** for review

5. **Severity-Based Decision Making**:
   - Uses **CVSS scoring** for vulnerability assessment
   - Only applies fixes for **critical issues**
   - Prevents unnecessary changes for **low-risk issues**

6. **Cyberpunk Interface**:
   - **ASCII Art Banner** with neon-styled colors
   - **Color-coded status messages**:
     * Cyan [>] for information
     * Green [+] for success
     * Yellow [!] for warnings
     * Red [x] for errors
   - **Retro-futuristic command layout**
   - **Visual progress indicators**

## Quick Start

### Prerequisites

- **Python 3.10+**
- **Docker**
- **Git**
- **GitHub CLI**
- **Slack Account** (for notifications)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/ruvnet/agentic-security.git
   cd agentic-security
   ```

2. **Run the cyberpunk-styled installer**:
   ```bash
   chmod +x install.sh
   ./install.sh
   ```

3. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys:
   # - OPENAI_API_KEY
   # - ANTHROPIC_API_KEY
   # - SLACK_WEBHOOK (optional)
   ```

4. **Activate environment**:
   ```bash
   source venv/bin/activate
   ```

5. **Install the CLI**:
   ```bash
   pip install -e .
   ```

### CLI Usage

The CLI provides a cyberpunk-themed interface with the following commands:

```bash
╔══════════════════════════════════════════════════════════════╗
║                     Available Commands                      ║
╚══════════════════════════════════════════════════════════════╝

[>] scan     - Run security scans
[>] analyze  - AI-powered analysis
[>] run      - Full pipeline execution
[>] validate - Config validation
[>] version  - Show version
```

### Command Options

1. **scan**: Run security scans
   ```bash
   # Basic scan
   agentic-security scan

   # Scan specific paths
   agentic-security scan --path ./src --path ./tests

   # Scan with custom config
   agentic-security scan --config custom-config.yml

   # Scan with auto-fix
   agentic-security scan --auto-fix

   # Generate scan report
   agentic-security scan --output report.md
   ```

2. **analyze**: AI-powered analysis
   ```bash
   # Basic analysis
   agentic-security analyze

   # Analysis with auto-fix
   agentic-security analyze --auto-fix

   # Analysis with custom config
   agentic-security analyze --config custom-config.yml
   ```

3. **run**: Full pipeline execution
   ```bash
   # Run pipeline
   agentic-security run

   # Run with architecture review
   agentic-security run --with-architecture-review

   # Run with custom config
   agentic-security run --config custom-config.yml
   ```

4. **validate**: Configuration validation
   ```bash
   # Validate default config
   agentic-security validate

   # Validate custom config
   agentic-security validate --config custom-config.yml

   # Full validation including API checks
   agentic-security validate --full
   ```

5. **Global Options**:
   - `--config, -c`: Path to configuration file
   - `--verbose, -v`: Enable verbose output
   - `--help`: Show help message

### Docker Support

Build and run using Docker:
```bash
docker build -t agentic-security .
docker run --env-file .env agentic-security run --config config.yml
```

## References

- [OWASP ZAP](https://www.zaproxy.org/)
- [Nuclei](https://nuclei.projectdiscovery.io/)
- [Dependency-Check](https://owasp.org/www-project-dependency-check/)
- [Aider](https://github.com/paul-gauthier/aider)
- [OpenAI](https://openai.com/)
- [Anthropic](https://www.anthropic.com/)

---

**Created by rUv, cause he could.**
