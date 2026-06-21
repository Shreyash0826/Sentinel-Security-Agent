import os
import time

def simulate_attack():
    target_dir = "./protected_folder"
    file_path = os.path.join(target_dir, "malicious_payload.bin")
    
    print(f"[*] Starting simulated attack: {file_path}...")
    
    # Writing random bytes (High entropy)
    with open(file_path, "wb") as f:
        f.write(os.urandom(1024 * 1024)) # 1MB of random data
        
    print("[*] Attack simulation finished.")

if __name__ == "__main__":
    simulate_attack()
