import ssl
import socket
import re
import datetime
from urllib.parse import urlparse
from utils import extract_domain

def inspect_certificate(domain):
    """
    Connects to the domain over HTTPS and retrieves the SSL certificate.
    Checks for validity and expiration.
    Returns a dictionary of certificate info or an error string.
    """
    if not domain:
        return {"status": "error", "message": "No domain provided."}
        
    context = ssl.create_default_context()
    conn = None
    try:
        # Timeout to avoid hanging the UI
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.settimeout(5.0)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        
        # Extract basic info
        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])
        
        not_after_str = cert.get('notAfter')
        # e.g., 'Aug 14 12:00:00 2026 GMT'
        not_after_date = datetime.datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
        
        is_expired = datetime.datetime.utcnow() > not_after_date
        
        return {
            "status": "success",
            "issuer": issuer.get('organizationName', issuer.get('commonName', 'Unknown')),
            "subject": subject.get('commonName', 'Unknown'),
            "expires": not_after_date.strftime('%Y-%m-%d'),
            "is_expired": is_expired,
            "secure": not is_expired
        }
        
    except ssl.SSLCertVerificationError as e:
        return {"status": "warning", "message": f"Certificate verification failed: {e.verify_message}"}
    except ssl.SSLError:
        return {"status": "warning", "message": "SSL error or domain does not support HTTPS."}
    except socket.timeout:
        return {"status": "error", "message": "Connection timed out checking certificate."}
    except socket.gaierror:
        return {"status": "error", "message": "Could not resolve domain."}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        if conn:
            conn.close()

def heuristic_analysis(url):
    """
    Analyzes a URL for heuristic phishing and malicious patterns.
    Returns a list of warnings found.
    """
    warnings = []
    
    if not url:
        return ["Empty URL provided."]
        
    # Ensure scheme for parsing
    test_url = url if url.startswith("http") else "http://" + url
    try:
        parsed = urlparse(test_url)
        domain = parsed.netloc.split(":")[0]
    except Exception:
        return ["Unparsable URL."]
        
    # 1. Check if domain is an IP address
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pattern, domain):
        warnings.append("Domain is an IP address instead of a standard hostname (common in phishing).")
        
    # 2. Suspicious keywords in domain
    suspicious_keywords = ['login', 'verify', 'update', 'banking', 'secure', 'account', 'auth', 'signin']
    for keyword in suspicious_keywords:
        # Check if keyword is in domain, but not the primary brand name (simplistic check)
        # e.g., secure-login.paypal.something.com
        if keyword in domain.lower() and domain.lower().count('.') > 1:
            warnings.append(f"Domain contains suspicious keyword: '{keyword}'.")
            
    # 3. Excessive subdomains (more than 3 dots)
    if domain.count('.') >= 3 and not re.match(ip_pattern, domain):
        # Ignore www
        if domain.startswith('www.') and domain.count('.') >= 4:
            warnings.append("URL uses an unusually high number of subdomains.")
        elif not domain.startswith('www.'):
            warnings.append("URL uses an unusually high number of subdomains.")
            
    # 4. Excessive hyphens
    if domain.count('-') >= 3:
        warnings.append("Domain contains excessive hyphens (common in typosquatting).")
        
    # 5. Suspicious TLDs (cheap or commonly abused)
    suspicious_tlds = ['.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.cc']
    for tld in suspicious_tlds:
        if domain.lower().endswith(tld):
            warnings.append(f"Uses a Top-Level Domain ({tld}) frequently abused by spammers.")
            break
            
    return warnings
