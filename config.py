import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# API Configuration
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# Email Configuration
SMTP_EMAIL = os.getenv("SMTP_EMAIL", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# App Configuration
APP_NAME = "MALICIOUS BLOCKER"
HASH_FILE = "registered_gmail_hash.txt"
PROJECT_INFO_PORT = 8000

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "app.log")

# Platform specific
IS_WINDOWS = sys.platform.startswith("win")
if IS_WINDOWS:
    HOSTS_FILE_PATH = r"C:\Windows\System32\drivers\etc\hosts"
else:
    # Fallback for testing on non-Windows (not fully supported for blocker)
    HOSTS_FILE_PATH = "/etc/hosts"
