import logging
import time
import os
import shutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from entropy_engine import calculate_entropy

# Configuration
THRESHOLD = 6.5
PROTECTED_DIR = "./protected_folder"
QUARANTINE_DIR = "./quarantine"

# Configure logging to save events to sentinel.log
logging.basicConfig(
    filename='sentinel.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Ensure required directories exist
if not os.path.exists(PROTECTED_DIR):
    os.makedirs(PROTECTED_DIR)
if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

def quarantine_file(file_path):
    """Moves a suspicious file to the quarantine directory."""
    try:
        file_name = os.path.basename(file_path)
        dest_path = os.path.join(QUARANTINE_DIR, file_name)
        shutil.move(file_path, dest_path)
        msg = f"THREAT NEUTRALIZED: {file_name} moved to {QUARANTINE_DIR}"
        print(f"[!!!] {msg}")
        logging.warning(msg)
    except Exception as e:
        error_msg = f"ERROR: Could not quarantine {file_path}: {e}"
        print(f"[!] {error_msg}")
        logging.error(error_msg)

class SentinelHandler(FileSystemEventHandler):
    def on_deleted(self, event):
        if not event.is_directory:
            logging.info(f"File deleted: {event.src_path}")
            print(f"[*] ALERT: File deleted: {event.src_path}")

    def on_created(self, event):
        if not event.is_directory:
            logging.info(f"New file detected: {event.src_path}")
            print(f"[*] New file detected: {event.src_path}")

    def on_modified(self, event):
        file_name = os.path.basename(event.src_path)
        
        # Ignore hidden files (starting with .)
        if file_name.startswith('.'):
            return
        
        # Ignore events inside the quarantine folder to prevent loops
        if QUARANTINE_DIR in event.src_path:
            return

        if not event.is_directory:
            entropy = calculate_entropy(event.src_path)
            print(f"[!] Monitoring: {event.src_path} | Entropy: {entropy:.2f}")
            
            # If threshold is exceeded, trigger neutralization
            if entropy > THRESHOLD:
                msg = f"Potential Ransomware Detected in {event.src_path} | Entropy: {entropy:.2f}"
                print(f"[!!!] ALERT: {msg}")
                logging.warning(msg)
                quarantine_file(event.src_path)

if __name__ == "__main__":
    event_handler = SentinelHandler()
    observer = Observer()
    observer.schedule(event_handler, PROTECTED_DIR, recursive=False)
    
    print(f"[*] Sentinel started. Monitoring {PROTECTED_DIR}...")
    logging.info("Sentinel started.")
    
    # Start the observer background thread
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping Sentinel...")
        observer.stop()
    
    # Safely join the thread
    observer.join()
