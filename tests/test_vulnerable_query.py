import unittest
import sqlite3
from unittest.mock import patch, MagicMock
import sys
import os

# Add the parent directory to the path to import the module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.samples.vulnerable_query import (
    validate_table_name, 
    validate_user_id,
    get_user_data,
    search_users,
    DatabaseError
)

class TestVulnerableQuery(unittest.TestCase):
    def setUp(self):
        """Set up test database and sample data"""
        self.conn = sqlite3.connect(':memory:')
        self.cursor = self.conn.cursor()
        
        # Create test table
        self.cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                name TEXT
            )
        ''')
        
        # Insert test data
        self.cursor.execute("INSERT INTO users VALUES (1, 'John Doe')")
        self.cursor.execute("INSERT INTO users VALUES (2, 'Jane Smith')")
        self.conn.commit()

    def tearDown(self):
        """Clean up test database"""
        self.conn.close()

    def test_validate_table_name_valid(self):
        """Test validate_table_name with valid table names"""
        self.assertTrue(validate_table_name('users'))
        self.assertTrue(validate_table_name('profiles'))
        self.assertTrue(validate_table_name('settings'))

    def test_validate_table_name_invalid(self):
        """Test validate_table_name with invalid table names"""
        self.assertFalse(validate_table_name('invalid_table'))
        self.assertFalse(validate_table_name(''))
        self.assertFalse(validate_table_name('DROP TABLE users;'))
        self.assertFalse(validate_table_name(None))

    def test_validate_user_id_valid(self):
        """Test validate_user_id with valid user IDs"""
        self.assertTrue(validate_user_id('123'))
        self.assertTrue(validate_user_id('0'))
        self.assertTrue(validate_user_id(456))

    def test_validate_user_id_invalid(self):
        """Test validate_user_id with invalid user IDs"""
        self.assertFalse(validate_user_id('abc'))
        self.assertFalse(validate_user_id('12.3'))
        self.assertFalse(validate_user_id(''))
        self.assertFalse(validate_user_id('1; DROP TABLE users;'))
        self.assertFalse(validate_user_id(None))

    @patch('sqlite3.connect')
    def test_get_user_data_success(self, mock_connect):
        """Test get_user_data with valid inputs"""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [(1, 'John Doe')]

        result = get_user_data('1', 'users')
        self.assertEqual(result, [(1, 'John Doe')])
        mock_cursor.execute.assert_called_once_with(
            "SELECT * FROM users WHERE id = ?", 
            ('1',)
        )

    def test_get_user_data_invalid_table(self):
        """Test get_user_data with invalid table name"""
        with self.assertRaises(DatabaseError) as context:
            get_user_data('1', 'invalid_table')
        self.assertIn('Invalid table name', str(context.exception))

    def test_get_user_data_invalid_user_id(self):
        """Test get_user_data with invalid user ID"""
        with self.assertRaises(DatabaseError) as context:
            get_user_data('1; DROP TABLE users;', 'users')
        self.assertIn('Invalid user ID format', str(context.exception))

    @patch('sqlite3.connect')
    def test_get_user_data_db_error(self, mock_connect):
        """Test get_user_data handling database errors"""
        mock_connect.side_effect = sqlite3.Error('Database error')
        
        with self.assertRaises(DatabaseError) as context:
            get_user_data('1', 'users')
        self.assertIn('Database error occurred', str(context.exception))

    @patch('sqlite3.connect')
    def test_search_users_success(self, mock_connect):
        """Test search_users with valid input"""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_connect.return_value = mock_conn
        mock_conn.cursor.return_value = mock_cursor
        mock_cursor.fetchall.return_value = [(1, 'John Doe')]

        result = search_users('John')
        self.assertEqual(result, [(1, 'John Doe')])
        mock_cursor.execute.assert_called_once_with(
            "SELECT * FROM users WHERE name LIKE ?",
            ('%John%',)
        )

    @patch('sqlite3.connect')
    def test_search_users_db_error(self, mock_connect):
        """Test search_users handling database errors"""
        mock_connect.side_effect = sqlite3.Error('Database error')
        
        with self.assertRaises(DatabaseError) as context:
            search_users('John')
        self.assertIn('Database error occurred', str(context.exception))

    def test_search_users_empty_keyword(self):
        """Test search_users with empty search term"""
        result = search_users('')
        self.assertIsInstance(result, list)

    def test_search_users_special_characters(self):
        """Test search_users with special characters"""
        result = search_users('%_')  # SQL wildcard characters
        self.assertIsInstance(result, list)

if __name__ == '__main__':
    unittest.main()
