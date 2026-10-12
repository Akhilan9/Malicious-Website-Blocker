import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import SMTP_EMAIL, SMTP_PASSWORD, SMTP_SERVER, SMTP_PORT

# Store the active password in memory for verification
_active_password = None

def generate_password(length=8):
    """
    Generate a random authentication password.
    """
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for i in range(length))

def send_password_email(recipient_email):
    """
    Generate a password and send it via SMTP.
    Returns (success, message)
    """
    global _active_password
    
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        return False, "SMTP credentials are not configured in .env."
        
    password = generate_password()
    _active_password = password
    
    msg = MIMEMultipart()
    msg['From'] = SMTP_EMAIL
    msg['To'] = recipient_email
    msg['Subject'] = "Authentication Password - Malicious Website Blocker"
    
    body = f"Your authentication password is: {password}\n\nPlease use this password to complete your action."
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        # Connect to server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        
        # Send email
        text = msg.as_string()
        server.sendmail(SMTP_EMAIL, recipient_email, text)
        server.quit()
        
        return True, "Password sent successfully."
    except Exception as e:
        return False, f"Failed to send email: {e}"

def verify_password(entered_password):
    """
    Verify the entered password matches the generated one.
    """
    global _active_password
    if not _active_password:
        return False
        
    return entered_password == _active_password

def clear_password():
    """
    Clear the active password after successful authentication.
    """
    global _active_password
    _active_password = None

def send_alert_email(recipient_email, url, threat_level):
    """
    Send an automated security alert email to the registered user.
    """
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        return False
        
    msg = MIMEMultipart()
    msg['From'] = SMTP_EMAIL
    msg['To'] = recipient_email
    msg['Subject'] = f"SECURITY ALERT: {threat_level} Website Blocked"
    
    body = f"Hello,\n\nThe Malicious Website Scanner just intercepted an attempt to access a {threat_level} URL:\n{url}\n\nThis is an automated security alert."
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_EMAIL, SMTP_PASSWORD)
        server.sendmail(SMTP_EMAIL, recipient_email, msg.as_string())
        server.quit()
        return True
    except Exception:
        return False

