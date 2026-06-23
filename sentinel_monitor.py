import logging
import time
import os
import shutil
import requests
import hashlib
import threading
from multiprocessing import Process
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from entropy_engine import calculate_entropy
from config import * # Importing all configuration settings

# Configure logging
logging.basicConfig(
    filename='sentinel.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def integrity_heartbeat():
    """Background thread to perform periodic integrity scans."""
    while True:
        time.sleep(300) 
        for root, dirs, files in os.walk(PROTECTED_DIR):
            for file in files:
                file_path = os.path.join(root, file)
                if any(file.lower().endswith(ext) for ext in SENSITIVE_EXTENSIONS):
                    file_hash = calculate_file_hash(file_path)
                    if file_hash and file_hash not in TRUSTED_HASHES:
                        if calculate_entropy(file_path) > THRESHOLD:
                            quarantine_file(file_path)

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
        logging.warning(msg)
        send_alert(msg)
    except Exception as e:
        logging.error(f"ERROR: Could not quarantine {file_path}: {e}")

if not os.path.exists(PROTECTED_DIR): os.makedirs(PROTECTED_DIR)
if not os.path.exists(QUARANTINE_DIR): os.makedirs(QUARANTINE_DIR)

class SentinelHandler(FileSystemEventHandler):
    def process_file(self, file_path):
        if calculate_file_hash(file_path) in TRUSTED_HASHES:
            return
        
        entropy = calculate_entropy(file_path)
        if entropy > THRESHOLD:
            logging.warning(f"Ransomware Detected: {file_path} | Entropy: {entropy:.2f}")
            quarantine_file(file_path)

    def on_modified(self, event):
        file_name = os.path.basename(event.src_path)
        if file_name.startswith('.') or os.path.abspath(QUARANTINE_DIR) in os.path.abspath(event.src_path):
            return
        _, ext = os.path.splitext(file_name)
        if ext.lower() in SENSITIVE_EXTENSIONS and not event.is_directory:
            Process(target=self.process_file, args=(event.src_path,)).start()

if __name__ == "__main__":
    threading.Thread(target=integrity_heartbeat, daemon=True).start()
    
    observer = Observer()
    observer.schedule(SentinelHandler(), PROTECTED_DIR, recursive=True)
    observer.start()
    
    print(f"[*] Sentinel active. Monitoring {PROTECTED_DIR}...")
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
