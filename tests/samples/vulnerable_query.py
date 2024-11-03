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

# Cache for prepared statements
STMT_CACHE = {}

def get_prepared_statement(conn: sqlite3.Connection, sql: str) -> sqlite3.Cursor:
    """
    Get or create a prepared statement with proper parameter binding
    
    Args:
        conn: Database connection
        sql: SQL query string
        
    Returns:
        sqlite3.Cursor: Prepared statement cursor
    """
    if sql not in STMT_CACHE:
        STMT_CACHE[sql] = conn.cursor()
        STMT_CACHE[sql].execute(f"PREPARE stmt_{len(STMT_CACHE)} AS {sql}")
    return STMT_CACHE[sql]

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

def validate_table_name(table_name: str) -> str:
    """
    Validate if table name is in the allowed list with strict validation
    
    Args:
        table_name: The table name to validate
        
    Returns:
        str: The validated table name
        
    Raises:
        DatabaseError: If table name is invalid
    """
    if not isinstance(table_name, str):
        raise DatabaseError("Table name must be a string")
        
    table_name = table_name.lower().strip()
    
    # Check against whitelist first
    if table_name not in ALLOWED_TABLES:
        raise DatabaseError(f"Table '{table_name}' not in allowed tables list")
    
    # Strict format validation - only allow lowercase alphanumeric and underscore
    if not re.match(r'^[a-z][a-z0-9_]{0,62}[a-z0-9]$', table_name):
        raise DatabaseError("Invalid table name format")
    
    # Length check
    if len(table_name) > 63:
        raise DatabaseError("Table name too long")
        
    return table_name

def validate_columns(table_name: str, columns: List[str]) -> List[str]:
    """
    Validate if requested columns are allowed for the table and contain only valid characters
    
    Args:
        table_name: The table to validate columns against
        columns: List of column names to validate
        
    Returns:
        List[str]: List of validated column names
        
    Raises:
        DatabaseError: If any column is invalid
    """
    if not isinstance(columns, list):
        raise DatabaseError("Columns must be provided as a list")
        
    if not columns:
        raise DatabaseError("At least one column must be specified")
        
    if not all(isinstance(col, str) for col in columns):
        raise DatabaseError("All column names must be strings")
    
    # Get allowed columns for the table
    allowed_cols = ALLOWED_TABLES.get(table_name.lower(), [])
    if not allowed_cols:
        raise DatabaseError(f"No columns defined for table '{table_name}'")
    
    validated_columns = []
    for col in columns:
        col = col.lower().strip()
        
        if col not in allowed_cols:
            raise DatabaseError(f"Column '{col}' not allowed for table '{table_name}'")
            
        # Strict format validation - only allow lowercase alphanumeric and underscore
        if not re.match(r'^[a-z][a-z0-9_]{0,63}$', col):
            raise DatabaseError(f"Invalid column name format: {col}")
            
        validated_columns.append(col)
    
    return validated_columns

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
    try:
        # Validate inputs
        if not all(isinstance(x, str) for x in [table_name, user_id]):
            raise DatabaseError("Invalid input types")
            
        table_name = validate_table_name(table_name)
        
        if not validate_user_id(user_id):
            raise DatabaseError("Invalid user ID format")
        
        # Use all columns if none specified
        if columns is None:
            columns = ALLOWED_TABLES[table_name]
        columns = validate_columns(table_name, columns)
        
        with get_db_connection() as conn:
            conn.execute("BEGIN TRANSACTION")
            try:
                # Use parameterized query with validated column names
                placeholders = {
                    'cols': ', '.join(f'"{col}"' for col in columns),
                    'table': f'"{table_name}"'
                }
                
                query = """
                    SELECT %(cols)s 
                    FROM %(table)s 
                    WHERE id = ? 
                    AND active = 1 
                    AND deleted_at IS NULL
                """ % placeholders
                
                # Get prepared statement
                stmt = get_prepared_statement(conn, query)
                results = stmt.execute(query, (user_id,)).fetchall()
                
                conn.commit()
                return results if results else None
                
            except Exception:
                conn.rollback()
                raise
            
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
    try:
        if not isinstance(keyword, str):
            raise DatabaseError("Search keyword must be a string")
            
        # Enhanced keyword validation
        keyword = keyword.strip()
        if not re.match(r'^[a-zA-Z0-9\s-]{3,50}$', keyword):
            raise DatabaseError("Invalid search keyword format - must be 3-50 chars, alphanumeric with spaces and hyphens only")
        
        # Use all columns if none specified
        if columns is None:
            columns = ALLOWED_TABLES['users']
        columns = validate_columns('users', columns)
        
        with get_db_connection() as conn:
            conn.execute("BEGIN TRANSACTION")
            try:
                # Use parameterized query with validated column names
                placeholders = {
                    'cols': ', '.join(f'"{col}"' for col in columns)
                }
                
                query = """
                    SELECT %(cols)s
                    FROM users
                    WHERE name LIKE ? ESCAPE '\\' 
                    AND active = 1
                    ORDER BY id ASC
                    LIMIT 100
                """ % placeholders
                
                # Get prepared statement and properly escape LIKE pattern
                stmt = get_prepared_statement(conn, query)
                search_pattern = ''.join(c if c.isalnum() or c.isspace() 
                                       else '\\' + c for c in keyword)
                search_pattern = f"%{search_pattern}%"
                
                results = stmt.execute(query, (search_pattern,)).fetchall()
                
                conn.commit()
                return results if results else None
                
            except Exception:
                conn.rollback()
                raise
            
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
