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
        result = get_user_data(1, "users")
        self.assertIsNotNone(result)

    def test_sql_injection_prevention(self):
        """Test SQL injection prevention"""
        with self.assertRaises(Exception):
            get_user_data("1 OR 1=1", "users")

if __name__ == "__main__":
    unittest.main()
