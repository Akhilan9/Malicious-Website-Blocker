import unittest
import os
import sys
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner import scan_website

class TestScanner(unittest.TestCase):
    
    @patch('scanner.requests.get')
    @patch('scanner.VIRUSTOTAL_API_KEY', 'dummy_key')
    def test_scan_website_malicious(self, mock_get):
        # Mock the VirusTotal API response for a malicious site
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "harmless": 60,
                        "undetected": 10
                    }
                }
            }
        }
        mock_get.return_value = mock_response
        
        status, message, stats = scan_website("http://malicious.com")
        
        self.assertEqual(status, "MALICIOUS")
        self.assertEqual(stats["malicious"], 5)
        
    @patch('scanner.requests.get')
    @patch('scanner.VIRUSTOTAL_API_KEY', 'dummy_key')
    def test_scan_website_safe(self, mock_get):
        # Mock the VirusTotal API response for a safe site
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 70,
                        "undetected": 10
                    }
                }
            }
        }
        mock_get.return_value = mock_response
        
        status, message, stats = scan_website("http://example.com")
        
        self.assertEqual(status, "SAFE")
        self.assertEqual(stats["harmless"], 70)
        
    @patch('scanner.requests.get')
    @patch('scanner.VIRUSTOTAL_API_KEY', 'dummy_key')
    def test_scan_api_failure(self, mock_get):
        # TC06: VirusTotal API failure
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response
        
        status, message, stats = scan_website("http://example.com")
        self.assertEqual(status, "ERROR")
        self.assertIn("Invalid", message)

if __name__ == '__main__':
    unittest.main()
