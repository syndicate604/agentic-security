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
    Safely get user data using parameterized queries
    
    Args:
        user_id: The user ID to query
        table_name: The table to query from
        
    Returns:
        List of tuples containing user data or None if error occurs
        
    Raises:
        DatabaseError: If invalid input or database error occurs
    """
    if not validate_table_name(table_name):
        raise DatabaseError(f"Invalid table name: {table_name}")
        
    if not validate_user_id(user_id):
        raise DatabaseError(f"Invalid user ID format: {user_id}")
        
    try:
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            # Use parameterized query with ? placeholder
            query = f"SELECT * FROM {table_name} WHERE id = ?"
            cursor.execute(query, (user_id,))
            return cursor.fetchall()
            
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error occurred: {str(e)}")

def search_users(keyword: str) -> Optional[List[tuple]]:
    """
    Safely search users using parameterized queries
    
    Args:
        keyword: Search term for user names
        
    Returns:
        List of tuples containing matching users or None if error occurs
        
    Raises:
        DatabaseError: If database error occurs
    """
    try:
        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            # Use parameterized query with ? placeholder
            query = "SELECT * FROM users WHERE name LIKE ?"
            cursor.execute(query, (f"%{keyword}%",))
            return cursor.fetchall()
            
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error occurred: {str(e)}")

if __name__ == "__main__":
    try:
        # Safe usage examples
        print(get_user_data("123", "users"))
        print(search_users("John"))
    except DatabaseError as e:
        print(f"Error: {e}")
