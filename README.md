# Sentinel: Automated File Integrity & Ransomware Defender

Sentinel is a lightweight, Python-based security agent designed to monitor file system integrity in real-time, detect high-entropy threats (potential ransomware), and perform automated quarantine.

## Features
* **Recursive Monitoring:** Real-time protection across nested directory structures using the `watchdog` library.
* **Entropy Analysis:** Detects encrypted or compressed patterns in sensitive files, a key indicator of ransomware activity.
* **SHA-256 Whitelisting:** Prevents false positives by verifying file integrity against a trusted hash database.
* **Integrity Heartbeat:** An independent background thread that performs periodic "cold scans" to catch unauthorized changes made while the agent was inactive.
* **Automated Response:** Immediate Discord notifications and automated quarantine of suspicious files to prevent data loss.

## Technical Architecture
* **Event-Driven:** Uses `watchdog` to react instantly to file modifications.
* **Asynchronous Processing:** Offloads heavy entropy calculations to a separate `Process` to ensure the monitor remains responsive.
* **Modular Design:** Separation of configuration (settings) and execution (logic) for clean, maintainable code.

## Requirements
* Python 3.x
* Dependencies:
  ```bash
  pip install watchdog requests
  ```

## Setup & Configuration
1. **Clone the repository.**
2. **Configure:** Open `config.py` and update the following:
   - `WEBHOOK_URL`: Your Discord webhook link.
   - `TRUSTED_HASHES`: A set of SHA-256 hashes for your known-safe files.
3. **Run:**
   ```bash
   python3 sentinel_monitor.py
   ```

## Security Disclaimer
*This tool is intended for educational purposes in security engineering and threat detection research. It is designed to demonstrate automated defense mechanisms and should be tested in a controlled environment.*
