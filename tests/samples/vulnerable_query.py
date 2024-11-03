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
    Validate if user_id contains only digits and is within reasonable length
    """
    try:
        # Convert to string if not already
        user_id_str = str(user_id)
        # Check format and length
        if not re.match(r'^\d{1,10}$', user_id_str):
            return False
        # Verify value range
        user_id_int = int(user_id_str)
        return 0 < user_id_int < 1000000000
    except (ValueError, TypeError):
        return False

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
    if not all(isinstance(x, str) for x in [table_name, user_id]):
        raise DatabaseError("Invalid input types")
        
    if not validate_table_name(table_name):
        raise DatabaseError("Invalid table name")
        
    if not validate_user_id(user_id):
        raise DatabaseError("Invalid user ID format")
    
    # Use all columns if none specified
    if columns is None:
        columns = ALLOWED_TABLES[table_name]
    elif not validate_columns(table_name, columns):
        raise DatabaseError("Invalid columns requested")
    
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Construct query with validated column names
            column_names = ','.join(columns)  # Safe since columns are validated
            query = f'SELECT {column_names} FROM {table_name} WHERE id = ?'
            
            # Execute with properly bound parameter for user_id only
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
    Safely search users using fully parameterized queries with strict input validation
    
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
        
    # Very strict keyword validation
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
            
            # Build query with validated column names
            column_names = ','.join(columns)  # Safe since columns are validated
            query = f"""
                SELECT {column_names}
                FROM users 
                WHERE name LIKE ? 
                LIMIT 100
            """
            
            # Properly escape LIKE pattern and bind parameter
            search_pattern = f"%{keyword}%"
            cursor.execute(query, (search_pattern,))
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
