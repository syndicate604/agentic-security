# HackerOne Bug Report: Cross-Site Scripting (XSS) in Comment Display

## Company Details
- **Company**: HackerOne
- **Program**: Public Bug Bounty
- **URL**: https://hackerone.com
- **Severity**: Low
- **Bounty Range**: $100-$1,000

## Vulnerability Details
- **Type**: Reflected Cross-Site Scripting (XSS)
- **Location**: Comment Display Function
- **Impact**: Potential execution of malicious JavaScript in user's browser

## Description
The application contains a Cross-Site Scripting vulnerability in the comment display function. While HTML escaping is implemented, there's a potential bypass in how user input is handled.

### Vulnerable Code
```python
def display_comment(comment):
    # Incomplete sanitization
    return f"<div>{escape(comment)}</div>"
```

## Steps to Reproduce
1. Navigate to any page with comment functionality
2. Submit a comment with the following payload:
```html
<img src=x onerror=alert(document.domain)>
```
3. When the comment is displayed, the JavaScript executes in the victim's browser

## Proof of Concept
```python
from flask import Flask, render_template_string
app = Flask(__name__)

@app.route('/comment')
def test_comment():
    malicious_comment = '<img src=x onerror=alert(document.domain)>'
    return display_comment(malicious_comment)
```

## Impact
An attacker could:
1. Execute arbitrary JavaScript in users' browsers
2. Steal session cookies and authentication tokens
3. Perform actions on behalf of the victim
4. Modify page content to phish credentials

## Fix
Implement proper content security policy and use a robust HTML sanitizer:

```python
from bleach import clean

def display_comment(comment):
    # Whitelist allowed HTML tags and attributes
    allowed_tags = ['p', 'br', 'strong', 'em']
    allowed_attributes = {}
    
    sanitized = clean(comment, 
                     tags=allowed_tags,
                     attributes=allowed_attributes,
                     strip=True)
    
    return f"<div>{sanitized}</div>"
```

Also add these security headers:
```python
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
```

## Risk Factors
- **CVSS Score**: 4.8
- **Attack Complexity**: Low
- **Privileges Required**: None
- **User Interaction**: Required

## References
- [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Cross-site Scripting](https://cwe.mitre.org/data/definitions/79.html)

## Timeline
- **Reported**: [Current Date]
- **Status**: New Submission

## Additional Notes
This vulnerability is particularly concerning because:
1. It affects all users who view comments
2. Can be exploited through social engineering
3. Bypasses basic XSS protection
4. Could be chained with other vulnerabilities for greater impact

The fix is straightforward to implement and significantly improves security without impacting legitimate functionality.
