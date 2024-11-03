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
   ./install.sh
   ```

3. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

4. **Activate environment**:
   ```bash
   source venv/bin/activate
   ```

### Usage

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

Example usage:
```bash
# Run a security scan
agentic-security scan --config config.yml

# Run the complete pipeline
agentic-security run --config config.yml
```

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
