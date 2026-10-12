import sys
import logging
from config import LOG_FILE
from project_server import start_server
from gui import Application

def setup_logging():
    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.info("Application started")

def main():
    # Setup application logging
    setup_logging()
    
    # Start the local project info server
    server_started, msg = start_server()
    if not server_started:
        logging.error(f"Project server failed to start: {msg}")
        
    try:
        # Initialize and run the Tkinter GUI
        app = Application()
        app.mainloop()
    except Exception as e:
        logging.error(f"Unhandled exception in GUI: {e}")
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
