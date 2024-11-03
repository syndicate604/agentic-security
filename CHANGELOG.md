# Changelog

## [1.1.0] - 2024-03-21

### Added
- New FixCycle class for automated code fixing with test generation
  - Implements iterative fix strategies with test validation
  - Supports multiple fix attempts and strategies
  - Includes automatic unit test generation and validation
  - CLI interface for easy integration

### Changed
- Updated __init__.py to expose FixCycle class
- Added comprehensive unit tests for FixCycle functionality

## [1.0.0] - Initial Release

### Added
- Initial implementation of SecurityPipeline
- Basic CLI interface
- Security scanning and fixing capabilities

## Security Fix
- Applied security fixes to: tests/samples/vulnerable_query.py
- Changes made based on provided instructions

## Security Fix
- Applied security fixes to: tests/samples/vulnerable_query.py
- Changes made based on provided instructions

Changes in tests/samples/vulnerable_query.py:
Added:
  - # Additional security checks...
  - if any(char in table_name for char in "\"';-/\\"):...
  - # Prevent SQL injection attempts...
  - if any(keyword.lower() in table_name.lower()...
  - for keyword in ['select', 'insert', 'update', 'delete', 'drop', 'union']):...
  - # Whitelist check...
  - # Additional security checks...
  - if any(char in col for char in "\"';-/\\"):...
  - if any(keyword.lower() in col.lower()...
  - for keyword in ['select', 'insert', 'update', 'delete', 'drop', 'union']):...
  - cols = validate_columns(table_name, columns)...
  - SELECT """ + cols_str + """...
  - FROM """ + table_name + """...
  - """...
  - cols = validate_columns('users', columns)...
  - SELECT """ + cols_str + """...
  - """...
  - # More robust LIKE pattern escaping...
  - New function: escape_like_pattern
  - return f"%{s}%"...

Modified:
  - Changed: # Check against whitelist first → # Strict whitelist validation
  - Changed: raise DatabaseError(f"Table '{table_name}' not in allowed tables list") → raise DatabaseError("Invalid characters in table name")
  - Changed: raise DatabaseError(f"Table '{table_name}' not in allowed tables list") → raise DatabaseError("Invalid table name - contains SQL keywords")
  - Changed: raise DatabaseError(f"Table '{table_name}' not in allowed tables list") → raise DatabaseError("Invalid characters in column name")
  - Changed: raise DatabaseError(f"Table '{table_name}' not in allowed tables list") → raise DatabaseError("Invalid column name - contains SQL keywords")
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed: # Additional format validation for defense in depth → # Enhanced format validation
  - Changed: # Additional format validation for defense in depth → # Enhanced format validation
  - Changed: # Build query safely with proper parameter binding → # Build query with proper column and table validation
  - Changed: # Build query safely with proper parameter binding → # Build query with validated columns
  - Changed: cols_str = ', '.join('?' for _ in columns) → cols_str = ', '.join(cols)  # Safe since validated
  - Changed: cols_str = ', '.join('?' for _ in columns) → cols_str = ', '.join(cols)  # Safe since validated
  - Changed: WHERE id = ? → WHERE id = ?
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed: # Prepare parameters including column names → raise DatabaseError("Invalid characters in column name")
  - Changed: # Prepare parameters including column names → # Prevent SQL injection via column names
  - Changed: # Prepare parameters including column names → # Only user_id needs parameterization since table/columns are validated
  - Changed: params = tuple(columns) + (user_id,) → params = (user_id,)
  - Changed: params = tuple(columns) + (user_id,) → params = (search_pattern,)
  - Changed: # Build query safely with proper parameter binding → # Build query with proper column and table validation
  - Changed: # Build query safely with proper parameter binding → # Build query with validated columns
  - Changed: cols_str = ', '.join('?' for _ in columns) → cols_str = ', '.join(cols)  # Safe since validated
  - Changed: cols_str = ', '.join('?' for _ in columns) → cols_str = ', '.join(cols)  # Safe since validated
  - Changed: WHERE name LIKE ? ESCAPE '^' → WHERE name LIKE ? ESCAPE '\'
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed: # Escape special characters in LIKE pattern → raise DatabaseError("Invalid characters in table name")
  - Changed: # Escape special characters in LIKE pattern → raise DatabaseError("Invalid characters in column name")
  - Changed: escaped_keyword = keyword.replace('^', '^^') → s = s.replace('\\', '\\\\')
  - Changed: escaped_keyword = keyword.replace('^', '^^') → s = s.replace('%', '\\%')
  - Changed: escaped_keyword = keyword.replace('^', '^^') → s = s.replace('_', '\\_')
  - Changed: escaped_keyword = escaped_keyword.replace('%', '^%') → s = s.replace('\\', '\\\\')
  - Changed: escaped_keyword = escaped_keyword.replace('%', '^%') → s = s.replace('%', '\\%')
  - Changed: escaped_keyword = escaped_keyword.replace('%', '^%') → s = s.replace('_', '\\_')
  - Changed: escaped_keyword = escaped_keyword.replace('_', '^_') → s = s.replace('\\', '\\\\')
  - Changed: escaped_keyword = escaped_keyword.replace('_', '^_') → s = s.replace('%', '\\%')
  - Changed: escaped_keyword = escaped_keyword.replace('_', '^_') → s = s.replace('_', '\\_')
  - Changed: search_pattern = f"%{escaped_keyword}%" → search_pattern = escape_like_pattern(keyword)
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed: # Prepare parameters including column names → raise DatabaseError("Invalid characters in column name")
  - Changed: # Prepare parameters including column names → # Prevent SQL injection via column names
  - Changed: # Prepare parameters including column names → # Only user_id needs parameterization since table/columns are validated
  - Changed: params = tuple(columns) + (search_pattern,) → params = (user_id,)
  - Changed: params = tuple(columns) + (search_pattern,) → params = (search_pattern,)

Removed:
  - # Strict format validation - only allow exact matches from whitelist
  - if table_name not in ALLOWED_TABLES:
  - # Strict format validation - only allow lowercase alphanumeric and underscore
  - SELECT {}
  - FROM {}
  - """.format(cols_str, table_name)
  - SELECT {}
  - """.format(cols_str)

## Security Fix
- Applied security fixes to: tests/samples/vulnerable_query.py
- Changes made based on provided instructions

Changes in tests/samples/vulnerable_query.py:
Added:
  - # Use query template as cache key...
  - cache_key = hash(sql)...
  - try:...
  - # Validate the SQL before caching...
  - STMT_CACHE[cache_key] = sql...
  - except sqlite3.Error as e:...
  - try:...
  - # Execute with parameters using proper binding...
  - except sqlite3.Error as e:...
  - New function: constant_time_compare
  - if len(val1) != len(val2):...
  - result = 0...
  - for x, y in zip(val1, val2):...
  - result |= ord(x) ^ ord(y)...
  - return result == 0...
  - if not any(constant_time_compare(table_name, allowed)...
  - try:...
  - conn.execute("BEGIN TRANSACTION")...
  - # Use prepared statement...
  - stmt = get_prepared_statement(...
  - conn,...
  - (table_name,)...
  - except Exception:...
  - conn.rollback()...
  - # Build safe parameterized query...
  - # Create dynamic column selection safely...
  - column_list = ', '.join(f'"{col}"' for col in cols)...
  - # Build safe parameterized query...
  - column_list = ', '.join(f'"{col}"' for col in cols)...
  - # Split search terms and escape LIKE patterns...
  - search_terms = [term.strip() for term in keyword.split()]...
  - escaped_terms = []...
  - escaped_term = term.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')...
  - escaped_terms.append(f"%{escaped_term}%")...
  - # Build WHERE clause for each search term...
  - where_clauses = []...
  - for _ in escaped_terms:...
  - params.append(_)...
  - WHERE {' AND '.join(where_clauses)}...

Modified:
  - Changed: Get or create a prepared statement with proper parameter binding → Get or create a prepared statement with proper parameter binding and caching
  - Changed: if params: → if params:
  - Changed: if params: → params = []
  - Changed: cursor.execute(sql, params) → cursor.execute("EXPLAIN QUERY PLAN " + sql)
  - Changed: cursor.execute(sql, params) → cursor.execute(STMT_CACHE[cache_key], tuple(params))
  - Changed: cursor.execute(sql, params) → cursor.execute(STMT_CACHE[cache_key])
  - Changed: else: → else:
  - Changed: cursor.execute(sql) → cursor.execute("EXPLAIN QUERY PLAN " + sql)
  - Changed: cursor.execute(sql) → cursor.execute(STMT_CACHE[cache_key])
  - Changed: cursor.execute(sql) → cursor = conn.cursor()
  - Changed: # Strict whitelist validation → # Strict whitelist validation using constant time comparison
  - Changed: if table_name not in ALLOWED_TABLES: → if cache_key not in STMT_CACHE:
  - Changed: if table_name not in ALLOWED_TABLES: → for allowed in ALLOWED_TABLES):
  - Changed: raise DatabaseError(f"Table '{table_name}' not in allowed tables list") → raise DatabaseError(f"Invalid SQL statement: {str(e)}")
  - Changed: raise DatabaseError(f"Table '{table_name}' not in allowed tables list") → raise DatabaseError(f"Error executing statement: {str(e)}")
  - Changed: raise DatabaseError(f"Table '{table_name}' not in allowed tables list") → raise DatabaseError("Table not in allowed list")
  - Changed: raise DatabaseError(f"Table '{table_name}' not in allowed tables list") → raise DatabaseError(f"Table '{table_name}' does not exist in database")
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed: # Enhanced format validation → # Enhanced format validation with strict pattern
  - Changed: if not re.match(r'^[a-z][a-z0-9_]{0,62}[a-z0-9]$', table_name): → if not re.match(r'^[a-z][a-z0-9_]{1,62}[a-z0-9]$', table_name, re.ASCII):
  - Changed: # Verify table exists in database → # Verify table exists in database with transaction
  - Changed: # Verify table exists in database → raise DatabaseError(f"Table '{table_name}' does not exist in database")
  - Changed: cursor = conn.cursor() → cursor = conn.cursor()
  - Changed: cursor = conn.cursor() → conn.commit()
  - Changed: cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,)) → "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? AND sql NOT LIKE '%--'",
  - Changed: if not cursor.fetchone(): → if not stmt.fetchone():
  - Changed: raise DatabaseError(f"Table '{table_name}' does not exist in database") → raise DatabaseError(f"Invalid SQL statement: {str(e)}")
  - Changed: raise DatabaseError(f"Table '{table_name}' does not exist in database") → raise DatabaseError(f"Error executing statement: {str(e)}")
  - Changed: raise DatabaseError(f"Table '{table_name}' does not exist in database") → raise DatabaseError("Table not in allowed list")
  - Changed: raise DatabaseError(f"Table '{table_name}' does not exist in database") → raise DatabaseError(f"Table '{table_name}' does not exist in database")
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed: query = """ → query = f"""
  - Changed: query = """ → query = f"""
  - Changed: SELECT """ + cols_str + """ → SELECT {column_list}
  - Changed: SELECT """ + cols_str + """ → SELECT {column_list}
  - Changed: FROM """ + table_name + """ → FROM "{table_name}"
  - Changed: # Only user_id needs parameterization since table/columns are validated → # Only user_id needs to be parameterized
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed: query = """ → query = f"""
  - Changed: query = """ → query = f"""
  - Changed: SELECT """ + cols_str + """ → SELECT {column_list}
  - Changed: SELECT """ + cols_str + """ → SELECT {column_list}
  - Changed: WHERE name LIKE ? ESCAPE '\' → where_clauses.append('name LIKE ? ESCAPE "\\"')
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed: return f"%{s}%" → return False
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed:  → 
  - Changed: params = (search_pattern,) → for term in search_terms:

Removed:
  - # Build query with proper column and table validation
  - cols_str = ', '.join(cols)  # Safe since validated
  - # Build query with validated columns
  - cols_str = ', '.join(cols)  # Safe since validated
  - # More robust LIKE pattern escaping
  - def escape_like_pattern(s: str) -> str:
  - s = s.replace('\\', '\\\\')
  - s = s.replace('%', '\\%')
  - s = s.replace('_', '\\_')
  - search_pattern = escape_like_pattern(keyword)
