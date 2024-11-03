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
    Validate if table name is in the allowed list and contains only valid characters
    
    Args:
        table_name: The table name to validate
        
    Returns:
        bool: True if table name is valid, False otherwise
    """
    if not isinstance(table_name, str):
        return False
    # Strict validation against whitelist and character set
    return (table_name in ALLOWED_TABLES.keys() and 
            bool(re.match(r'^[a-zA-Z][a-zA-Z0-9_]{0,63}$', table_name)))

def validate_columns(table_name: str, columns: List[str]) -> bool:
    """
    Validate if requested columns are allowed for the table and contain only valid characters
    """
    if not isinstance(columns, list) or not all(isinstance(col, str) for col in columns):
        return False
    
    # Validate each column name format and presence in allowed list
    return all(col in ALLOWED_TABLES[table_name] and 
              bool(re.match(r'^[a-zA-Z0-9_]+$', col)) 
              for col in columns)

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
    Safely get user data using fully parameterized queries and prepared statements
    
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
            
            # Use parameterized query with validated table/column names
            allowed_tables = list(ALLOWED_TABLES.keys())
            if table_name not in allowed_tables:
                raise DatabaseError("Invalid table access attempt")
                
            column_list = [col for col in columns if col in ALLOWED_TABLES[table_name]]
            if not column_list:
                raise DatabaseError("No valid columns specified")
                
            # Build query with validated table and column names
            placeholders = []
            params = []
            
            # Create safe column selection
            column_params = []
            for col in column_list:
                if col not in ALLOWED_TABLES[table_name]:
                    raise DatabaseError(f"Invalid column: {col}")
                column_params.append(f'"{col}"')
            columns_str = ','.join(column_params)
            
            # Create parameterized query
            query = f"""
                SELECT {columns_str}
                FROM "{table_name}"
                WHERE id = :user_id 
                AND active = 1
            """
            
            # Execute with named parameters
            cursor.execute(query, {"user_id": user_id})
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
        
    # Enhanced keyword validation with additional security checks
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
            
            # Get validated column list
            column_list = [col for col in columns if col in ALLOWED_TABLES['users']]
            if not column_list:
                raise DatabaseError("No valid columns specified")
            
            # Build query with validated columns
            column_params = []
            for col in column_list:
                if col not in ALLOWED_TABLES['users']:
                    raise DatabaseError(f"Invalid column: {col}")
                column_params.append(f'"{col}"')
            columns_str = ','.join(column_params)
            
            # Create parameterized query with named parameters
            query = f"""
                SELECT {columns_str}
                FROM "users" 
                WHERE name LIKE :pattern ESCAPE '\\' 
                AND active = 1
                ORDER BY id ASC 
                LIMIT 100
            """
            
            # Use named parameter with properly escaped LIKE pattern
            search_pattern = f"%{re.escape(keyword)}%"
            cursor.execute(query, {"pattern": search_pattern})
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
