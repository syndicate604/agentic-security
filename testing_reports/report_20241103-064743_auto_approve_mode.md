# Security Test Report: auto_approve_mode

**Date:** 2024-11-03 06:47:43

## Test Summary
- Test Name: auto_approve_mode
- Repository Path: /tmp/pytest-of-codespace/pytest-112/test_auto_approve_mode0/test_repo

## Security Findings

### File: app.py
- **SQL Injection**
  - Location: get_users() function
  - Severity: High
  - Description: Direct string interpolation in SQL query

## Applied Fixes

### File: app.py
- **SQL Injection Fix**
  ```diff
  - query = f"SELECT * FROM users WHERE name = '{name}'"
  + query = "SELECT * FROM users WHERE name = ?"
    cursor.execute(query, (name,))
  ```

## Git Changes

```diff
commit 049f056a6c30c6e7f30e16074be71a1efbc5d0ea
Author: Test User <test@example.com>
Date:   Sun Nov 3 06:47:43 2024 +0000

    [SECURITY] Fix SQL injection vulnerability

diff --git a/app.py b/app.py
index 5a2f18f..a7457d8 100644
--- a/app.py
+++ b/app.py
@@ -58,7 +58,8 @@ app = Flask(__name__)
 def get_users():
     # Vulnerable to SQL injection
     name = request.args.get('name')
-    query = f"SELECT * FROM users WHERE name = '{name}'"
+    query = "SELECT * FROM users WHERE name = ?"
+    cursor.execute(query, (name,))
     
     conn = sqlite3.connect('database.db')
     cursor = conn.cursor()
```
