import unittest
import os
import sqlite3
from vulnerable_query import *

class TestVulnerable_Query(unittest.TestCase):
    def setUp(self):
        # Set up test database
        self.db_name = 'test_users.db'
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        
        # Create test table
        self.cursor.execute(
            'CREATE TABLE users (                id INTEGER PRIMARY KEY,                name TEXT,                email TEXT            )'
        )
        
        # Insert test data
        self.cursor.executemany(
            'INSERT INTO users (name, email) VALUES (?, ?)',
            [
                ('Alice', 'alice@test.com'),
                ('Bob', 'bob@test.com'),
                ('Charlie', 'charlie@test.com')
            ]
        )
        self.conn.commit()

    def tearDown(self):
        # Clean up test database
        self.conn.close()
        if os.path.exists(self.db_name):
            os.remove(self.db_name)

    def test_valid_input(self):
        """Test with valid input"""
        # Test get_user_data with valid inputs
        result = get_user_data("1", "users", ["name", "email"])
        self.assertIsNotNone(result)
        self.assertEqual(result[0][0], "Alice")
        
        # Test search_users with valid input
        result = search_users("Alice")
        self.assertIsNotNone(result)
        self.assertEqual(result[0][0], "Alice")
        
        # Test with valid column subset
        result = get_user_data("1", "users", ["name"])
        self.assertIsNotNone(result)
        self.assertEqual(len(result[0]), 1)

    def test_sql_injection_prevention(self):
        """Test SQL injection prevention"""
        # Test SQL injection attempts in user_id
        with self.assertRaises(DatabaseError):
            get_user_data("1 OR 1=1", "users")
            
        # Test SQL injection in table name
        with self.assertRaises(DatabaseError):
            get_user_data("1", "users; DROP TABLE users")
            
        # Test SQL injection in search
        with self.assertRaises(DatabaseError):
            search_users("' OR '1'='1")
            
        # Test SQL injection in column names
        with self.assertRaises(DatabaseError):
            get_user_data("1", "users", ["name; DROP TABLE users;--"])

    def test_input_validation(self):
        """Test input validation"""
        # Test invalid table name
        with self.assertRaises(DatabaseError):
            get_user_data("1", "invalid_table")
            
        # Test invalid user_id format
        with self.assertRaises(DatabaseError):
            get_user_data("abc", "users")
            
        # Test invalid columns
        with self.assertRaises(DatabaseError):
            get_user_data("1", "users", ["invalid_column"])
            
        # Test search keyword validation
        with self.assertRaises(DatabaseError):
            search_users("a" * 51)  # Too long
        with self.assertRaises(DatabaseError):
            search_users("a@")  # Invalid characters
        with self.assertRaises(DatabaseError):
            search_users("ab")  # Too short

    def test_error_handling(self):
        """Test error handling"""
        # Test non-existent user
        result = get_user_data("999", "users")
        self.assertIsNone(result)
        
        # Test non-matching search
        result = search_users("NonexistentUser")
        self.assertIsNone(result)
        
        # Test type validation
        with self.assertRaises(DatabaseError):
            get_user_data(None, "users")
        with self.assertRaises(DatabaseError):
            search_users(123)
            
        # Test empty inputs
        with self.assertRaises(DatabaseError):
            search_users("")

if __name__ == '__main__':
    unittest.main()
