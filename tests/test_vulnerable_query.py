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
        # Test get_user_data with valid input
        result = get_user_data("1", "users", ["name", "email"])
        self.assertIsNotNone(result)
        self.assertEqual(result[0][0], "Alice")
        
        # Test search_users with valid input
        result = search_users("Alice", ["name", "email"])
        self.assertIsNotNone(result)
        self.assertTrue(any("Alice" in row[0] for row in result))

    def test_sql_injection_prevention(self):
        """Test SQL injection prevention"""
        # Test get_user_data with SQL injection attempts
        with self.assertRaises(DatabaseError):
            get_user_data("1 OR 1=1", "users")
        with self.assertRaises(DatabaseError):
            get_user_data("1; DROP TABLE users", "users")
            
        # Test search_users with SQL injection attempts
        with self.assertRaises(DatabaseError):
            search_users("Alice' OR '1'='1")
        with self.assertRaises(DatabaseError):
            search_users("Alice'; DROP TABLE users; --")

    def test_input_validation(self):
        """Test input validation"""
        # Test table name validation
        with self.assertRaises(DatabaseError):
            get_user_data("1", "invalid_table")
        
        # Test column validation
        with self.assertRaises(DatabaseError):
            get_user_data("1", "users", ["invalid_column"])
            
        # Test user_id validation
        with self.assertRaises(DatabaseError):
            get_user_data("not_a_number", "users")
        with self.assertRaises(DatabaseError):
            get_user_data("-1", "users")
        with self.assertRaises(DatabaseError):
            get_user_data("99999999999", "users")
            
        # Test search keyword validation
        with self.assertRaises(DatabaseError):
            search_users("<script>alert(1)</script>")
        with self.assertRaises(DatabaseError):
            search_users("a" * 51)  # Too long
        with self.assertRaises(DatabaseError):
            search_users("ab")  # Too short

    def test_error_handling(self):
        """Test error handling"""
        # Test non-existent user
        result = get_user_data("999", "users")
        self.assertIsNone(result)
        
        # Test non-existent search results
        result = search_users("NonexistentUser")
        self.assertIsNone(result)
        
        # Test type validation
        with self.assertRaises(DatabaseError):
            get_user_data(None, "users")
        with self.assertRaises(DatabaseError):
            search_users(123)  # Non-string input
            
        # Test empty or None columns
        result = get_user_data("1", "users", [])
        self.assertIsNone(result)

if __name__ == '__main__':
    unittest.main()
