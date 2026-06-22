import logging
import time
import os
import shutil
import requests
from multiprocessing import Process
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from entropy_engine import calculate_entropy

# Configuration
THRESHOLD = 6.5
PROTECTED_DIR = "./protected_folder"
QUARANTINE_DIR = "./quarantine"
SENSITIVE_EXTENSIONS = {'.docx', '.pdf', '.jpg', '.xlsx', '.txt', '.zip', '.bin'}
WEBHOOK_URL = "https://discord.com/api/webhooks/1518483866229407765/ntwAteDgjx1ahsqYdGZETe5jQLSeCmE6LXQ68rGXFp2dMYa-nDGN2Xw3S0B3G0Tx_xxo"

# Configure logging
logging.basicConfig(
    filename='sentinel.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def send_alert(message):
    try:
        data = {"content": f"🚨 **Sentinel Security Alert:** {message}"}
        requests.post(WEBHOOK_URL, json=data)
    except Exception as e:
        logging.error(f"Failed to send Discord alert: {e}")

def quarantine_file(file_path):
    try:
        file_name = os.path.basename(file_path)
        dest_path = os.path.join(QUARANTINE_DIR, file_name)
        shutil.move(file_path, dest_path)
        msg = f"THREAT NEUTRALIZED: {file_name} moved to {QUARANTINE_DIR}"
        print(f"[!!!] {msg}")
        logging.warning(msg)
        send_alert(msg)
    except Exception as e:
        error_msg = f"ERROR: Could not quarantine {file_path}: {e}"
        print(f"[!] {error_msg}")
        logging.error(error_msg)

if not os.path.exists(PROTECTED_DIR):
    os.makedirs(PROTECTED_DIR)
if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

class SentinelHandler(FileSystemEventHandler):
    def process_file(self, file_path):
        """Heavy lifting function to run in a separate process."""
        entropy = calculate_entropy(file_path)
        print(f"[!] Monitoring: {file_path} | Entropy: {entropy:.2f}")
        if entropy > THRESHOLD:
            msg = f"Potential Ransomware Detected in {file_path} | Entropy: {entropy:.2f}"
            print(f"[!!!] ALERT: {msg}")
            logging.warning(msg)
            quarantine_file(file_path)

    def on_modified(self, event):
        file_name = os.path.basename(event.src_path)
        if file_name.startswith('.') or QUARANTINE_DIR in event.src_path:
            return

        _, ext = os.path.splitext(file_name)
        if ext.lower() not in SENSITIVE_EXTENSIONS:
            return

        if not event.is_directory:
            # Offload heavy work to a separate process to keep the loop responsive
            p = Process(target=self.process_file, args=(event.src_path,))
            p.start()

if __name__ == "__main__":
    event_handler = SentinelHandler()
    observer = Observer()
    observer.schedule(event_handler, PROTECTED_DIR, recursive=False)
    
    print(f"[*] Sentinel started. Monitoring {PROTECTED_DIR}...")
    logging.info("Sentinel started.")
    
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping Sentinel...")
        observer.stop()
    observer.join()
