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
