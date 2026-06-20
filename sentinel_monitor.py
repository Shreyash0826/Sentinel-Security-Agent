import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from entropy_engine import calculate_entropy

# The threshold for detection (6.5 is a common starting point for encryption)
THRESHOLD = 6.5

class SentinelHandler(FileSystemEventHandler):
    def on_deleted(self, event):
        if not event.is_directory:
            print(f"[*] ALERT: File deleted: {event.src_path}")

    def on_created(self, event):
        if not event.is_directory:
            print(f"[*] New file detected: {event.src_path}")

    def on_modified(self, event):
        if event.src_path.split('/')[-1].startswith('.'):
            return
        if not event.is_directory:
            # When a file is modified, calculate its entropy
            entropy = calculate_entropy(event.src_path)
            print(f"[!] Monitoring: {event.src_path} | Entropy: {entropy:.2f}")
            
            if entropy > THRESHOLD:
                print(f"[!!!] ALERT: Potential Ransomware Detected in {event.src_path}!")

if __name__ == "__main__":
    path_to_watch = "./protected_folder"  # Make sure this folder exists!
    
    # Create the folder if it doesn't exist
    import os
    if not os.path.exists(path_to_watch):
        os.makedirs(path_to_watch)

    event_handler = SentinelHandler()
    observer = Observer()
    observer.schedule(event_handler, path_to_watch, recursive=False)
    
    print(f"[*] Sentinel started. Monitoring {path_to_watch}...")
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
