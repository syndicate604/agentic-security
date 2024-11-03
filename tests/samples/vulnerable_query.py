import sqlite3

def get_user_data(user_id, table_name):
    """
    Vulnerable function with SQL injection
    DO NOT USE IN PRODUCTION
    
    Issues:
    1. Direct string formatting in SQL query
    2. No input validation
    3. No error handling
    4. Table name injection possible
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable query construction
    query = f"SELECT * FROM {table_name} WHERE id = {user_id}"
    cursor.execute(query)
    
    result = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return result

def search_users(keyword):
    """
    Another vulnerable function with SQL injection
    DO NOT USE IN PRODUCTION
    
    Issues:
    1. No parameter binding
    2. Direct string concatenation
    3. No input sanitization
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # Vulnerable query construction
    query = "SELECT * FROM users WHERE name LIKE '%" + keyword + "%'"
    cursor.execute(query)
    
    result = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return result

if __name__ == "__main__":
    # Example usage (VULNERABLE!)
    print(get_user_data("1 OR 1=1", "users"))  # SQL Injection possible
    print(search_users("' OR '1'='1"))  # SQL Injection possible
