import unittest
import os
import sqlite3
from tests.samples.vulnerable_query import *

class TestVulnerable_Query(unittest.TestCase):
    def setUp(self):
        self.db_name = "test_users.db"
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self.cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")
        self.cursor.executemany("INSERT INTO users (name, email) VALUES (?, ?)",
                              [("Alice", "alice@test.com"),
                               ("Bob", "bob@test.com")])
        self.conn.commit()

    def tearDown(self):
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
        result = search_users("Alice", ["name", "email"])
        self.assertIsNotNone(result)
        self.assertEqual(result[0][0], "Alice")

    def test_sql_injection_prevention(self):
        """Test SQL injection prevention"""
        # Test malicious table name
        with self.assertRaises(DatabaseError):
            get_user_data("1", "users; DROP TABLE users;", ["name"])
            
        # Test malicious user_id
        with self.assertRaises(DatabaseError):
            get_user_data("1 OR 1=1", "users", ["name"])
            
        # Test malicious search term
        with self.assertRaises(DatabaseError):
            search_users("' OR '1'='1", ["name"])

    def test_input_validation(self):
        """Test input validation functions"""
        # Test table name validation
        self.assertTrue(validate_table_name("users"))
        self.assertFalse(validate_table_name("users; DROP TABLE users;"))
        self.assertFalse(validate_table_name(""))
        
        # Test column validation
        self.assertTrue(validate_columns("users", ["name", "email"]))
        self.assertFalse(validate_columns("users", ["nonexistent"]))
        self.assertFalse(validate_columns("users", ["name; DROP TABLE users;"]))
        
        # Test user_id validation
        self.assertTrue(validate_user_id("1"))
        self.assertFalse(validate_user_id("1 OR 1=1"))
        self.assertFalse(validate_user_id(""))

    def test_error_handling(self):
        """Test error handling"""
        # Test nonexistent table
        with self.assertRaises(DatabaseError):
            get_user_data("1", "nonexistent_table", ["name"])
            
        # Test nonexistent columns
        with self.assertRaises(DatabaseError):
            get_user_data("1", "users", ["nonexistent_column"])
            
        # Test invalid user_id
        result = get_user_data("999", "users", ["name"])
        self.assertIsNone(result)

    def test_edge_cases(self):
        """Test edge cases"""
        # Test empty columns list
        with self.assertRaises(DatabaseError):
            get_user_data("1", "users", [])
            
        # Test None values
        with self.assertRaises(DatabaseError):
            get_user_data(None, "users", ["name"])
        
        # Test with special characters in search
        result = search_users("%", ["name"])
        self.assertIsNotNone(result)
        
        # Test with very long inputs
        long_input = "a" * 1000
        with self.assertRaises(DatabaseError):
            get_user_data(long_input, "users", ["name"])

if __name__ == "__main__":
    unittest.main()
