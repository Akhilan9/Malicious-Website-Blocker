import requests
import base64
import urllib.parse
from config import VIRUSTOTAL_API_KEY
from utils import extract_domain
from enhancements import inspect_certificate, heuristic_analysis

def scan_website(url):
    """
    Use the VirusTotal API to scan a website URL and return the result.
    Returns: (status, message, stats)
    status can be: "SAFE", "SUSPICIOUS", "MALICIOUS", "UNKNOWN", "ERROR"
    """
    if not VIRUSTOTAL_API_KEY:
        return "ERROR", "VirusTotal API key is missing. Please check your configuration.", None

    if not url:
        return "ERROR", "Empty URL provided.", None
        
    # The new VirusTotal API v3 uses urlsafe base64 encoded URL as the identifier
    try:
        # urlsafe_b64encode adds padding which needs to be removed for VT API
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        response = requests.get(api_url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            # Determine overall status
            if malicious > 0:
                status = "MALICIOUS"
                message = "Warning: This website has been identified as potentially malicious."
            elif suspicious > 0:
                status = "SUSPICIOUS"
                message = "Caution: This website has suspicious activity reported."
            elif harmless > 0:
                status = "SAFE"
                message = "No malicious activity detected by the selected reputation service."
            else:
                status = "UNKNOWN"
                message = "No reputation data found for this website."
                
            # Run future enhancements
            domain = extract_domain(url)
            cert_info = inspect_certificate(domain)
            heuristic_warnings = heuristic_analysis(url)
            
            stats['cert_info'] = cert_info
            stats['heuristic_warnings'] = heuristic_warnings
                
            return status, message, stats
            
        elif response.status_code == 404:
            # URL not found in VT database, we could submit it, but for now just report unknown
            return "UNKNOWN", "URL not found in VirusTotal database. It has not been scanned before.", None
        elif response.status_code == 401:
            return "ERROR", "Invalid VirusTotal API key.", None
        elif response.status_code == 429:
            return "ERROR", "VirusTotal API rate limit exceeded. Try again later.", None
        else:
            return "ERROR", f"VirusTotal API returned error code: {response.status_code}", None
            
    except requests.exceptions.RequestException:
        return "ERROR", "Unable to contact VirusTotal. Please check your internet connection.", None
    except Exception as e:
        return "ERROR", f"An unexpected error occurred: {e}", None
