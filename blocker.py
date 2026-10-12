import os
import shutil
import datetime
import json
from config import HOSTS_FILE_PATH, BASE_DIR
from utils import extract_domain, is_admin

APP_COMMENT = "# Malicious Website Scanner and Blocker"

def create_hosts_backup():
    """
    Create a backup of the hosts file before modifying it.
    """
    timestamp = datetime.datetime.now().strftime("%Y%md_%H%M%S")
    backup_path = f"{HOSTS_FILE_PATH}.backup_{timestamp}"
    try:
        shutil.copy2(HOSTS_FILE_PATH, backup_path)
        return True, f"Backup created at {backup_path}"
    except Exception as e:
        return False, f"Failed to create backup: {e}"

def is_domain_blocked(domain):
    """
    Check if a domain is already blocked in the hosts file.
    """
    if not domain:
        return False
        
    try:
        with open(HOSTS_FILE_PATH, "r") as f:
            lines = f.readlines()
            
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") and line != APP_COMMENT:
                continue
            
            # Check if domain is in the line (basic check)
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "127.0.0.1" and domain == parts[1]:
                return True
                
        return False
    except FileNotFoundError:
        return False
    except Exception:
        return False

def block_website(url):
    """
    Block a website by adding it to the hosts file.
    """
    if not is_admin():
        return False, "Administrator privileges are required to modify the hosts file."
        
    domain = extract_domain(url)
    if not domain:
        return False, "Invalid URL provided."
        
    if is_domain_blocked(domain):
        return False, "Website is already blocked."
        
    # Create backup first
    backup_success, backup_msg = create_hosts_backup()
    if not backup_success:
        return False, f"Failed to block: {backup_msg}"
        
    # Add www variant if applicable
    domains_to_block = [domain]
    if not domain.startswith("www."):
        domains_to_block.append(f"www.{domain}")
        
    try:
        with open(HOSTS_FILE_PATH, "a") as f:
            f.write(f"\n{APP_COMMENT}\n")
            for d in domains_to_block:
                f.write(f"127.0.0.1 {d}\n")
                
        return True, "Website blocked successfully."
    except PermissionError:
        return False, "Permission denied. Please run the application as Administrator."
    except Exception as e:
        return False, f"An error occurred: {e}"

def unblock_website(url):
    """
    Unblock a website by removing it from the hosts file.
    Removes only entries created by this application.
    """
    if not is_admin():
        return False, "Administrator privileges are required to modify the hosts file."
        
    domain = extract_domain(url)
    if not domain:
        return False, "Invalid URL provided."
        
    if not is_domain_blocked(domain):
        return False, "Website is not currently blocked."
        
    # Create backup first
    backup_success, backup_msg = create_hosts_backup()
    if not backup_success:
        return False, f"Failed to unblock: {backup_msg}"
        
    domains_to_unblock = [domain]
    if not domain.startswith("www."):
        domains_to_unblock.append(f"www.{domain}")
        
    try:
        with open(HOSTS_FILE_PATH, "r") as f:
            lines = f.readlines()
            
        with open(HOSTS_FILE_PATH, "w") as f:
            for line in lines:
                stripped_line = line.strip()
                
                parts = stripped_line.split()
                is_target_line = (len(parts) >= 2 and parts[0] == "127.0.0.1" and parts[1] in domains_to_unblock)
                
                if is_target_line:
                    pass
                else:
                    f.write(line)
                    
        return True, "Website unblocked successfully."
    except PermissionError:
        return False, "Permission denied. Please run the application as Administrator."
    except Exception as e:
        return False, f"An error occurred: {e}"

def load_categories():
    cat_file = os.path.join(BASE_DIR, "categories.json")
    if os.path.exists(cat_file):
        with open(cat_file, "r") as f:
            return json.load(f)
    return {}

def block_category(category_name):
    categories = load_categories()
    if category_name not in categories:
        return False, f"Category '{category_name}' not found."
        
    domains = categories[category_name]
    blocked_count = 0
    
    for domain in domains:
        # Simple hack to reuse existing block_website without URL validation
        # Since domain is already a domain, we can just pass it as 'http://domain'
        success, _ = block_website(f"http://{domain}")
        if success:
            blocked_count += 1
            
    return True, f"Blocked {blocked_count} websites in category '{category_name}'."

