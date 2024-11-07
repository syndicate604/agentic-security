# How to Submit Bug Reports to HackerOne

## Prerequisites
1. Create a HackerOne account at https://hackerone.com/sign_up
2. Complete your profile with required information
3. Read the platform's disclosure guidelines

## Submission Process

### Step 1: Find the Program
1. Go to https://hackerone.com/directory/programs
2. Search for the program you want to submit to (e.g., "HackerOne")
3. Click on the program to view their security page

### Step 2: Check Program Requirements
1. Read the program's scope
2. Review their security page
3. Check eligible vulnerability types
4. Verify bounty ranges
5. Note any specific submission requirements

### Step 3: Submit Report
1. Click "Submit Report" button on the program's security page
2. Fill out the report form:
   - Title: Clear, concise description (e.g., "SQL Injection in User Query Endpoint")
   - Severity: Select appropriate level based on impact
   - Description: Copy from our prepared reports:
     - Vulnerability Details
     - Steps to Reproduce
     - Impact
     - Proof of Concept
   - Attachments: Include any relevant screenshots or files

### Step 4: Submit Reports in Priority Order
1. Command Injection Report
   - Highest security impact
   - Clear exploit path
   - Copy content from `command_injection_report.md`

2. SQL Injection Report
   - Database access risk
   - Easy to verify
   - Copy content from `sql_injection_report.md`

3. XSS Report
   - Affects all users
   - Client-side impact
   - Copy content from `xss_report.md`

4. Weak Cryptography Report
   - Foundational security
   - Copy content from `weak_crypto_report.md`

## Best Practices

### Do's
1. Submit one vulnerability per report
2. Provide clear reproduction steps
3. Include proof of concept code
4. Be professional and courteous
5. Respond promptly to questions
6. Follow the program's disclosure policy

### Don'ts
1. Don't include multiple vulnerabilities in one report
2. Don't share vulnerabilities publicly
3. Don't perform DoS testing without permission
4. Don't access or modify other users' data
5. Don't use automated tools without permission

## After Submission

1. Monitor your report status
2. Respond to any questions from the team
3. Be patient - typical response times vary by program
4. If accepted:
   - Work with the team on verification
   - Help validate fixes if requested
   - Follow responsible disclosure guidelines

## Report Status Meanings

- **New**: Just submitted
- **Triaged**: Under investigation
- **Needs More Info**: Additional information requested
- **Resolved**: Fix implemented
- **Closed**: Report processed and completed

## Communication Tips

1. Be professional and clear
2. Use technical language appropriately
3. Respond promptly to questions
4. Provide additional details when requested
5. Be patient during the review process

## Resources

- [HackerOne Guidelines](https://www.hackerone.com/disclosure-guidelines)
- [Report Writing Tips](https://www.hackerone.com/blog/how-write-good-vulnerability-report)
- [Severity Guidelines](https://www.hackerone.com/severity-guidelines)

Remember: Quality over quantity. Well-documented reports with clear impact are more likely to be rewarded.
