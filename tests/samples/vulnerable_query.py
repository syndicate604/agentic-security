import sqlite3
from typing import List, Optional
import re

# Whitelist of allowed table names
ALLOWED_TABLES = {'users', 'profiles', 'settings'}

class DatabaseError(Exception):
    """Custom exception for database operations"""
    pass

def validate_table_name(table_name: str) -> bool:
    """
    Validate if table name is in the allowed list
    """
    return table_name in ALLOWED_TABLES

def validate_user_id(user_id: str) -> bool:
    """
    Validate if user_id contains only digits
    """
    return bool(re.match(r'^\d+$', str(user_id)))

def get_user_data(user_id: str, table_name: str) -> Optional[List[tuple]]:
    """
    Safely get user data using parameterized queries and prepared statements
    
    Args:
        user_id: The user ID to query
        table_name: The table to query from
        
    Returns:
        List of tuples containing user data or None if error occurs
        
    Raises:
        DatabaseError: If invalid input or database error occurs
    """
    # Validate inputs before processing
    if not isinstance(table_name, str) or not isinstance(user_id, str):
        raise DatabaseError("Invalid input types")
        
    if not validate_table_name(table_name):
        raise DatabaseError(f"Invalid table name: {table_name}")
        
    if not validate_user_id(user_id):
        raise DatabaseError(f"Invalid user ID format: {user_id}")
    
    # Map of allowed tables to their valid columns
    table_queries = {
        'users': 'SELECT id, name, email FROM users WHERE id = ?',
        'profiles': 'SELECT id, bio, avatar FROM profiles WHERE id = ?',
        'settings': 'SELECT id, preferences FROM settings WHERE id = ?'
    }
    
    if table_name not in table_queries:
        raise DatabaseError("Table not allowed")
        
    try:
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            # Use pre-defined query for the table
            query = table_queries[table_name]
            cursor.execute(query, (user_id,))
            results = cursor.fetchall()
            
            if not results:
                return None
                
            return results
            
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error occurred: {str(e)}")
    finally:
        if 'conn' in locals():
            conn.close()

def search_users(keyword: str) -> Optional[List[tuple]]:
    """
    Safely search users using parameterized queries with input validation
    
    Args:
        keyword: Search term for user names
        
    Returns:
        List of tuples containing matching users or None if error occurs
        
    Raises:
        DatabaseError: If database error occurs or invalid input
    """
    if not isinstance(keyword, str):
        raise DatabaseError("Search keyword must be a string")
        
    # Validate keyword contains only allowed characters
    if not re.match(r'^[a-zA-Z0-9\s-]{1,50}$', keyword):
        raise DatabaseError("Invalid search keyword format")
    
    try:
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            # Use parameterized query with specific columns
            query = """
                SELECT id, name, email 
                FROM users 
                WHERE name LIKE ? 
                LIMIT 100
            """
            cursor.execute(query, (f"%{keyword}%",))
            results = cursor.fetchall()
            
            if not results:
                return None
                
            return results
            
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error occurred: {str(e)}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    try:
        # Safe usage examples
        print(get_user_data("123", "users"))
        print(search_users("John"))
    except DatabaseError as e:
        print(f"Error: {e}")
