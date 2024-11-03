import os
import sqlite3
from html import escape

def process_user_input(user_input):
    """Process user input with multiple security vulnerabilities"""
    
    # Security Issue 1: SQL Injection
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_input}"
    cursor.execute(query)
    
    # Security Issue 2: Command Injection
    os.system(f"echo {user_input}")
    
    # Security Issue 3: XSS
    html = f"<div>{user_input}</div>"
    
    return query, html

def validate_input(data):
    """Insecure input validation"""
    # Security Issue 4: Weak validation
    if len(data) > 0:
        return True
    return False

def store_password(password):
    """Insecure password storage"""
    # Security Issue 5: Plain text password
    with open('passwords.txt', 'a') as f:
        f.write(password + '\n')
