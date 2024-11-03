import sqlite3
from typing import List, Optional, Dict
import re
from contextlib import contextmanager

# Whitelist of allowed tables and their columns
ALLOWED_TABLES: Dict[str, List[str]] = {
    'users': ['id', 'name', 'email'],
    'profiles': ['id', 'bio', 'avatar'],
    'settings': ['id', 'preferences']
}

# Database configuration
DB_CONFIG = {
    'timeout': 5.0,
    'isolation_level': 'EXCLUSIVE',
    'check_same_thread': False
}

class DatabaseError(Exception):
    """Custom exception for database operations"""
    pass

@contextmanager
def get_db_connection():
    """
    Context manager for database connections with proper configuration
    """
    conn = None
    try:
        conn = sqlite3.connect('users.db', **DB_CONFIG)
        yield conn
    finally:
        if conn:
            conn.close()

def validate_table_name(table_name: str) -> bool:
    """
    Validate if table name is in the allowed list
    """
    return table_name in ALLOWED_TABLES.keys()

def validate_columns(table_name: str, columns: List[str]) -> bool:
    """
    Validate if requested columns are allowed for the table
    """
    return all(col in ALLOWED_TABLES[table_name] for col in columns)

def validate_user_id(user_id: str) -> bool:
    """
    Validate if user_id contains only digits
    """
    return bool(re.match(r'^\d+$', str(user_id)))

def get_user_data(user_id: str, table_name: str, columns: Optional[List[str]] = None) -> Optional[List[tuple]]:
    """
    Safely get user data using parameterized queries and prepared statements
    
    Args:
        user_id: The user ID to query
        table_name: The table to query from
        columns: Optional list of columns to retrieve
        
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
    
    # Use all columns if none specified
    if columns is None:
        columns = ALLOWED_TABLES[table_name]
    elif not validate_columns(table_name, columns):
        raise DatabaseError("Invalid columns requested")
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Construct safe query using validated columns
            columns_str = ', '.join(columns)
            query = f"SELECT {columns_str} FROM {table_name} WHERE id = ?"
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

def search_users(keyword: str, columns: Optional[List[str]] = None) -> Optional[List[tuple]]:
    """
    Safely search users using parameterized queries with input validation
    
    Args:
        keyword: Search term for user names
        columns: Optional list of columns to retrieve
        
    Returns:
        List of tuples containing matching users or None if error occurs
        
    Raises:
        DatabaseError: If database error occurs or invalid input
    """
    if not isinstance(keyword, str):
        raise DatabaseError("Search keyword must be a string")
        
    # Stricter keyword validation
    if not re.match(r'^[a-zA-Z0-9\s-]{3,50}$', keyword):
        raise DatabaseError("Invalid search keyword format - must be 3-50 chars, alphanumeric with spaces and hyphens only")
    
    # Use all columns if none specified
    if columns is None:
        columns = ALLOWED_TABLES['users']
    elif not validate_columns('users', columns):
        raise DatabaseError("Invalid columns requested")
    
    try:
        with get_db_connection() as conn:
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
