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
        self.cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                name TEXT,
                email TEXT
            )
        """)
        
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
        self.assertEqual(len(result[0]), 2)  # Should return name and email

        # Test search_users with valid input
        result = search_users("Alice")
        self.assertIsNotNone(result)
        self.assertTrue(any('Alice' in row for row in result))

        # Test with valid column subset
        result = get_user_data("1", "users", ["name"])
        self.assertIsNotNone(result)
        self.assertEqual(len(result[0]), 1)  # Should only return name

    def test_sql_injection_prevention(self):
        """Test SQL injection prevention"""
        # Test SQL injection attempts in user_id
        with self.assertRaises(DatabaseError):
            get_user_data("1 OR 1=1", "users")
        
        with self.assertRaises(DatabaseError):
            get_user_data("1; DROP TABLE users", "users")

        # Test SQL injection in table name
        with self.assertRaises(DatabaseError):
            get_user_data("1", "users; DROP TABLE users")

        # Test SQL injection in search
        with self.assertRaises(DatabaseError):
            search_users("' OR '1'='1")
        
        with self.assertRaises(DatabaseError):
            search_users("'; DROP TABLE users; --")

    def test_input_validation(self):
        """Test input validation"""
        # Test invalid table name
        with self.assertRaises(DatabaseError):
            get_user_data("1", "invalid_table")

        # Test invalid columns
        with self.assertRaises(DatabaseError):
            get_user_data("1", "users", ["invalid_column"])

        # Test invalid user_id format
        with self.assertRaises(DatabaseError):
            get_user_data("abc", "users")

        # Test invalid search keyword
        with self.assertRaises(DatabaseError):
            search_users("a")  # Too short
        
        with self.assertRaises(DatabaseError):
            search_users("!@#$%")  # Invalid characters

        # Test invalid input types
        with self.assertRaises(DatabaseError):
            get_user_data(123, "users")  # user_id should be string
        
        with self.assertRaises(DatabaseError):
            search_users(123)  # keyword should be string

    def test_error_handling(self):
        """Test error handling"""
        # Test non-existent user
        result = get_user_data("999", "users")
        self.assertIsNone(result)

        # Test non-matching search
        result = search_users("NonexistentUser")
        self.assertIsNone(result)

        # Test database connection error (by temporarily renaming db)
        os.rename(self.db_name, f"{self.db_name}.bak")
        with self.assertRaises(DatabaseError):
            get_user_data("1", "users")
        os.rename(f"{self.db_name}.bak", self.db_name)

    def test_search_users_limit(self):
        """Test search results limit"""
        # Insert 150 test users
        for i in range(100):
            self.cursor.execute(
                'INSERT INTO users (name, email) VALUES (?, ?)',
                (f'TestUser{i}', f'test{i}@test.com')
            )
        self.conn.commit()

        # Search should return maximum 100 results
        result = search_users("TestUser")
        self.assertIsNotNone(result)
        self.assertLessEqual(len(result), 100)

if __name__ == '__main__':
    unittest.main()
