import unittest
import os
import sqlite3
from tests.samples.vulnerable_query import *

class TestVulnerable_Query(unittest.TestCase):
    def setUp(self):
        """Set up test database with sample data"""
        self.db_name = "test_users.db"
        self.conn = sqlite3.connect(self.db_name)
        self.cursor = self.conn.cursor()
        self.cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                name TEXT,
                email TEXT,
                role TEXT
            )""")
        self.cursor.executemany(
            "INSERT INTO users (name, email, role) VALUES (?, ?, ?)",
            [
                ("Alice", "alice@test.com", "admin"),
                ("Bob", "bob@test.com", "user"),
                ("Charlie", "charlie@test.com", "user")
            ]
        )
        self.conn.commit()

    def tearDown(self):
        """Clean up test database"""
        self.conn.close()
        if os.path.exists(self.db_name):
            os.remove(self.db_name)

    # Valid Input Tests
    def test_valid_user_data_retrieval(self):
        """Test retrieving user data with valid input"""
        result = get_user_data("1", "users")
        self.assertIsNotNone(result)
        self.assertEqual(result[1], "Alice")

    def test_valid_column_selection(self):
        """Test retrieving specific columns"""
        result = get_user_data("1", "users", ["name", "email"])
        self.assertEqual(len(result), 2)
        self.assertIn("alice@test.com", result)

    def test_valid_search(self):
        """Test valid search operation"""
        results = search_users("Alice", ["name", "email"])
        self.assertIsNotNone(results)
        self.assertEqual(len(results), 1)

    # SQL Injection Prevention Tests
    def test_sql_injection_user_id(self):
        """Test SQL injection prevention in user_id parameter"""
        malicious_inputs = [
            "1 OR 1=1",
            "1; DROP TABLE users;",
            "1 UNION SELECT * FROM users",
            "1' OR '1'='1",
            "1/**/OR/**/1=1"
        ]
        for malicious_input in malicious_inputs:
            with self.assertRaises(Exception):
                get_user_data(malicious_input, "users")

    def test_sql_injection_table_name(self):
        """Test SQL injection prevention in table_name parameter"""
        malicious_inputs = [
            "users; DROP TABLE users",
            "users UNION SELECT",
            "users--",
            "users/**/UNION/**/SELECT"
        ]
        for malicious_input in malicious_inputs:
            with self.assertRaises(Exception):
                get_user_data("1", malicious_input)

    def test_sql_injection_columns(self):
        """Test SQL injection prevention in columns parameter"""
        malicious_columns = [
            ["name", "email; DROP TABLE users"],
            ["name/**/UNION/**/SELECT"],
            ["name', ''); DROP TABLE users; --"]
        ]
        for malicious_input in malicious_columns:
            with self.assertRaises(Exception):
                get_user_data("1", "users", malicious_input)

    # Input Validation Tests
    def test_invalid_table_name(self):
        """Test validation of table names"""
        invalid_tables = ["", "invalid_table", "123", "users_2"]
        for invalid_table in invalid_tables:
            with self.assertRaises(Exception):
                get_user_data("1", invalid_table)

    def test_invalid_columns(self):
        """Test validation of column names"""
        invalid_column_sets = [
            ["nonexistent_column"],
            ["name", "nonexistent"],
            [""],
            ["id; DROP TABLE users"]
        ]
        for invalid_columns in invalid_column_sets:
            with self.assertRaises(Exception):
                get_user_data("1", "users", invalid_columns)

    # Error Handling Tests
    def test_nonexistent_user(self):
        """Test handling of nonexistent user IDs"""
        result = get_user_data("999", "users")
        self.assertIsNone(result)

    def test_invalid_user_id_format(self):
        """Test handling of invalid user ID formats"""
        invalid_ids = ["abc", "", " ", None]
        for invalid_id in invalid_ids:
            with self.assertRaises(Exception):
                get_user_data(invalid_id, "users")

    def test_search_edge_cases(self):
        """Test search function with edge cases"""
        edge_cases = [
            ("", ["name"]),  # Empty search string
            ("%", ["name"]),  # Wildcard character
            ("_", ["name"]),  # Single character wildcard
            ("'", ["name"]),  # Single quote
            ('"', ["name"])   # Double quote
        ]
        for search_term, columns in edge_cases:
            with self.assertRaises(Exception):
                search_users(search_term, columns)

if __name__ == "__main__":
    unittest.main()
