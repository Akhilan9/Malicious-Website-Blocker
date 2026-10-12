import re
import urllib.parse
import ctypes
import os
import sys

def is_valid_email(email):
    """
    Validate the email using a regular expression.
    Example accepted format: username@gmail.com
    """
    pattern = r"^[a-zA-Z0-9_.+-]+@gmail\.com$"
    return re.match(pattern, email) is not None

def extract_domain(url):
    """
    Extract the domain from a URL.
    Handles empty URL, missing protocol, malformed URL.
    """
    if not url:
        return None
        
    url = url.strip()
    
    # Add scheme if missing for proper parsing
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
        
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc
        if domain:
            # Remove port if present
            domain = domain.split(":")[0]
            # Convert to lowercase
            return domain.lower()
    except Exception:
        pass
        
    return None

def is_valid_domain(domain):
    """
    Basic validation for a domain name.
    """
    if not domain:
        return False
    # Simple regex for domain name
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return re.match(pattern, domain) is not None

def is_admin():
    """
    Check if the application is running with Administrator privileges.
    """
    try:
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # On Unix-like, check if running as root
            return os.geteuid() == 0
    except Exception:
        return False
