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

def get_prepared_statement(conn: sqlite3.Connection, sql: str, params: tuple = None) -> sqlite3.Cursor:
    """
    Get or create a prepared statement with proper parameter binding and caching
    
    Args:
        conn: Database connection
        sql: SQL query string
        params: Query parameters
        
    Returns:
        sqlite3.Cursor: Prepared statement cursor
    """
    cursor = conn.cursor()
    
    # Use query template as cache key
    cache_key = hash(sql)
    
    if cache_key not in STMT_CACHE:
        # Prepare the statement
        cursor.execute("EXPLAIN " + sql)
        STMT_CACHE[cache_key] = sql
    
    # Execute with parameters
    if params:
        cursor.execute(STMT_CACHE[cache_key], params)
    else:
        cursor.execute(STMT_CACHE[cache_key])
        
    return cursor

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
    
    # Strict whitelist validation using constant time comparison
    def constant_time_compare(val1: str, val2: str) -> bool:
        if len(val1) != len(val2):
            return False
        result = 0
        for x, y in zip(val1, val2):
            result |= ord(x) ^ ord(y)
        return result == 0
    
    if not any(constant_time_compare(table_name, allowed) 
              for allowed in ALLOWED_TABLES):
        raise DatabaseError("Table not in allowed list")
    
    # Enhanced format validation with strict pattern
    if not re.match(r'^[a-z][a-z0-9_]{1,62}[a-z0-9]$', table_name, re.ASCII):
        raise DatabaseError("Invalid table name format")
        
    # Additional security checks
    if any(char in table_name for char in "\"';-/\\"):
        raise DatabaseError("Invalid characters in table name")
        
    # Prevent SQL injection attempts
    if any(keyword.lower() in table_name.lower() 
           for keyword in ['select', 'insert', 'update', 'delete', 'drop', 'union']):
        raise DatabaseError("Invalid table name - contains SQL keywords")
    
    # Length check
    if len(table_name) > 63:
        raise DatabaseError("Table name too long")
        
    # Verify table exists in database
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
        if not cursor.fetchone():
            raise DatabaseError(f"Table '{table_name}' does not exist in database")
        
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
        
        # Whitelist check
        if col not in allowed_cols:
            raise DatabaseError(f"Column '{col}' not allowed for table '{table_name}'")
            
        # Enhanced format validation
        if not re.match(r'^[a-z][a-z0-9_]{0,63}$', col):
            raise DatabaseError(f"Invalid column name format: {col}")
            
        # Additional security checks
        if any(char in col for char in "\"';-/\\"):
            raise DatabaseError("Invalid characters in column name")
            
        # Prevent SQL injection via column names
        if any(keyword.lower() in col.lower() 
               for keyword in ['select', 'insert', 'update', 'delete', 'drop', 'union']):
            raise DatabaseError("Invalid column name - contains SQL keywords")
            
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
                # Build parameterized query
                cols = validate_columns(table_name, columns)
                placeholders = ','.join('?' * len(cols))
                
                query = """
                    SELECT * FROM (
                        SELECT ? || '.' || ? AS col_name, ? as value 
                        FROM (VALUES {})
                    ) t JOIN {} ON 1=1
                    WHERE id = ?
                    AND active = 1 
                    AND deleted_at IS NULL
                """.format(','.join(['(?)'] * len(cols)), table_name)
                
                # Parameters for both column names and user_id
                params = []
                for col in cols:
                    params.extend([table_name, col, col])
                params.append(user_id)
                
                # Get prepared statement with parameters
                stmt = get_prepared_statement(conn, query, params)
                results = stmt.fetchall()
                
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
                # Build parameterized query with validated columns
                cols = validate_columns('users', columns)
                placeholders = ','.join('?' * len(cols))
                
                query = """
                    WITH RECURSIVE split(word, str) AS (
                        SELECT '', ? || ' '
                        UNION ALL
                        SELECT substr(str, 0, instr(str, ' ')),
                               substr(str, instr(str, ' ')+1)
                        FROM split WHERE str!=''
                    )
                    SELECT * FROM (
                        SELECT ? || '.' || ? AS col_name, ? as value 
                        FROM (VALUES {})
                    ) t JOIN users ON 1=1
                    WHERE EXISTS (
                        SELECT 1 FROM split 
                        WHERE word != '' 
                        AND name LIKE '%' || replace(replace(replace(word, 
                            '\', '\\'), 
                            '%', '\%'), 
                            '_', '\_') || '%' ESCAPE '\'
                    )
                    AND active = 1
                    ORDER BY id ASC
                    LIMIT 100
                """.format(','.join(['(?)'] * len(cols)))
                
                # Parameters for both column names and search terms
                params = [keyword]
                for col in cols:
                    params.extend(['users', col, col])
                
                # Get prepared statement with parameters
                stmt = get_prepared_statement(conn, query, params)
                results = stmt.fetchall()
                
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
