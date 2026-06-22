import re

def generate_report(log_file='sentinel.log'):
    print("--- Sentinel Forensic Report ---")
    try:
        with open(log_file, 'r') as f:
            logs = f.readlines()
            
        threats = [line for line in logs if "THREAT NEUTRALIZED" in line]
        total_threats = len(threats)
        
        print(f"Total Threats Neutralized: {total_threats}")
        print("\nRecent Incident Details:")
        for threat in threats[-5:]: # Show last 5
            print(f"- {threat.strip()}")
            
    except FileNotFoundError:
        print("No log file found. Has the Sentinel run yet?")

if __name__ == "__main__":
    generate_report()
