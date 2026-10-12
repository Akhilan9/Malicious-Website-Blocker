import unittest
import os
import sys

# Add parent directory to path to import modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils import is_valid_email, extract_domain
from auth import hash_string

class TestAuthAndUtils(unittest.TestCase):
    
    def test_is_valid_email(self):
        # TC01: Valid Gmail registration
        self.assertTrue(is_valid_email("test@gmail.com"))
        self.assertTrue(is_valid_email("user.name+label@gmail.com"))
        
        # TC02: Invalid Gmail registration
        self.assertFalse(is_valid_email("test@yahoo.com"))
        self.assertFalse(is_valid_email("invalid-email"))
        self.assertFalse(is_valid_email("@gmail.com"))
        
    def test_hash_string(self):
        # Basic SHA-256 validation
        test_str = "test@gmail.com"
        expected_hash = "87924606b4131a8aceeeae8868531fbb9712aaa07a5d3a756b26ce0f5d6ca674"
        self.assertEqual(hash_string(test_str), expected_hash)
        
    def test_extract_domain(self):
        # Extract domain from various URL formats
        self.assertEqual(extract_domain("https://example.com"), "example.com")
        self.assertEqual(extract_domain("http://www.example.com/path"), "www.example.com")
        self.assertEqual(extract_domain("example.com"), "example.com")
        
        # TC03: Empty URL
        self.assertIsNone(extract_domain(""))
        self.assertIsNone(extract_domain("   "))

if __name__ == '__main__':
    unittest.main()
