# HackerOne Bug Reports

This directory contains vulnerability reports and tools for submitting them to HackerOne's bug bounty program.

## Reports

1. **Command Injection** ([View Report](command_injection_report.md))
   - Severity: Low to Medium
   - Bounty Range: $100-$1,000
   - CWE-77: Command Injection

2. **SQL Injection** ([View Report](sql_injection_report.md))
   - Severity: Low to Medium
   - Bounty Range: $100-$1,000
   - CWE-89: SQL Injection

3. **Cross-Site Scripting (XSS)** ([View Report](xss_report.md))
   - Severity: Low
   - Bounty Range: $100-$1,000
   - CWE-79: Cross-site Scripting

4. **Weak Cryptography** ([View Report](weak_crypto_report.md))
   - Severity: Low to Medium
   - Bounty Range: $100-$1,000
   - CWE-326: Inadequate Encryption Strength

## API Submission Tool

### Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure environment:
```bash
cp .env.example .env
```

3. Edit `.env` with your HackerOne API credentials:
```bash
HACKERONE_API_USERNAME=your_username
HACKERONE_API_TOKEN=your_api_token
```

### Usage

Submit all reports:
```bash
python submit_reports.py
```

The script will:
1. Submit each report in priority order
2. Handle rate limiting automatically
3. Upload any attachments
4. Check submission status
5. Log results

### Features

- Rate limiting compliance
- Automatic markdown conversion
- File attachment support
- Status checking
- Detailed logging
- Error handling

### Rate Limits

- Read operations: 600 requests per minute
- Write operations: 25 requests per 20 seconds

### Files

- `submit_reports.py` - Main submission script
- `requirements.txt` - Python dependencies
- `.env.example` - Environment variable template
- `SUBMISSION_GUIDE.md` - Detailed submission guidelines

## Manual Submission

If you prefer to submit reports manually, see [SUBMISSION_GUIDE.md](SUBMISSION_GUIDE.md) for step-by-step instructions.

## Best Practices

1. **Before Submission**
   - Verify all proof of concepts
   - Test fixes in isolated environment
   - Check for duplicate reports
   - Review program scope and rules

2. **During Submission**
   - Submit one vulnerability per report
   - Provide clear reproduction steps
   - Include impact analysis
   - Attach relevant files

3. **After Submission**
   - Monitor report status
   - Respond promptly to questions
   - Help validate fixes
   - Follow disclosure policies

## Resources

- [HackerOne API Documentation](https://api.hackerone.com/docs/v1)
- [Program Guidelines](https://hackerone.com/security)
- [Disclosure Guidelines](https://www.hackerone.com/disclosure-guidelines)
- [Report Writing Tips](https://www.hackerone.com/blog/how-write-good-vulnerability-report)

## Total Potential Bounty
- Minimum: $400 (if all rated as low severity)
- Maximum: $4,000 (if all rated as medium severity)

## Support

If you encounter any issues:
1. Check the logs for error messages
2. Verify your API credentials
3. Ensure you're within rate limits
4. Review the API documentation
