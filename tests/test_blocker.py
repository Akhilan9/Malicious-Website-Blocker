import unittest
import os
import sys
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from blocker import is_domain_blocked

class TestBlocker(unittest.TestCase):
    
    @patch('blocker.HOSTS_FILE_PATH', 'dummy_hosts.txt')
    def test_is_domain_blocked(self):
        # Create a dummy hosts file
        with open('dummy_hosts.txt', 'w') as f:
            f.write("127.0.0.1 localhost\n")
            f.write("# Malicious Website Scanner and Blocker\n")
            f.write("127.0.0.1 badsite.com\n")
            
        try:
            self.assertTrue(is_domain_blocked("badsite.com"))
            self.assertFalse(is_domain_blocked("goodsite.com"))
        finally:
            if os.path.exists('dummy_hosts.txt'):
                os.remove('dummy_hosts.txt')
                
    # Further tests would mock create_hosts_backup and write operations 
    # to avoid modifying the real hosts file during automated testing.

if __name__ == '__main__':
    unittest.main()
