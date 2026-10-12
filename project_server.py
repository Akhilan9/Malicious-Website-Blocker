import http.server
import socketserver
import threading
import webbrowser
import os
import sys
import json
import urllib.parse
from config import BASE_DIR, PROJECT_INFO_PORT
from ml_model import predict_url_safety

class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)
        
    def log_message(self, format, *args):
        # Suppress logging to avoid cluttering the console
        pass

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        if parsed_url.path == '/api/check':
            query = urllib.parse.parse_qs(parsed_url.query)
            target_url = query.get('url', [''])[0]
            
            is_malicious, confidence = predict_url_safety(target_url) if target_url else (False, 0)
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            response = {
                "url": target_url,
                "is_malicious": bool(is_malicious),
                "confidence": confidence
            }
            self.wfile.write(json.dumps(response).encode())
            return
            
        super().do_GET()

def start_server():
    """
    Start the local HTTP server in a daemon thread.
    """
    os.chdir(BASE_DIR)
    try:
        Handler = RequestHandler
        # Allow address reuse to prevent OS errors on rapid restarts
        socketserver.TCPServer.allow_reuse_address = True
        httpd = socketserver.TCPServer(("", PROJECT_INFO_PORT), Handler)
        
        # Run server in a daemon thread
        server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        server_thread.start()
        print(f"Project info server started on port {PROJECT_INFO_PORT}")
        return True, httpd
    except OSError as e:
        if "Address already in use" in str(e):
            print(f"Server is already running on port {PROJECT_INFO_PORT}")
            return True, None
        return False, f"Failed to start server: {e}"
    except Exception as e:
        return False, f"Failed to start server: {e}"

def open_project_info():
    """
    Open the project info page in the default web browser.
    """
    url = f"http://localhost:{PROJECT_INFO_PORT}/projectinfo.html"
    webbrowser.open(url)
