#!/usr/bin/env python3
"""
NShieldOps Asset Agent
"""
import argparse
import hashlib
import json
import os
import platform
import socket
import sys
import time
import uuid
from pathlib import Path

try:
    import psutil
    import requests
except ImportError:
    print("[-] Missing dependencies. Please run:")
    print("    pip install requests psutil")
    sys.exit(1)

# Configuration
STATE_FILE = Path.home() / ".nshieldops_agent.json"
HEARTBEAT_INTERVAL = 15  # seconds

def get_fingerprint():
    """Gather basic asset info to identify this machine."""
    return {
        "hostname": socket.gethostname(),
        "mac": hex(uuid.getnode()),
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine()
    }

def generate_token(fp):
    """
    Generate a unique token using random bytes and the asset fingerprint.
    Format: <random_hex>_<fingerprint_hash>
    """
    random_part = os.urandom(16).hex()
    fp_string = json.dumps(fp, sort_keys=True)
    fp_hash = hashlib.sha256(fp_string.encode()).hexdigest()[:16]
    return f"{random_part}_{fp_hash}"

def save_state(asset_id, token, base_url):
    """Save the credentials locally so we don't have to enroll again."""
    state = {
        "asset_id": asset_id,
        "token": token,
        "base_url": base_url,
        "enrolled_at": time.time()
    }
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)
    # Secure the file so only the current user can read it
    os.chmod(STATE_FILE, 0o600)
    print(f"[+] Saved credentials to {STATE_FILE}")

def load_state():
    if STATE_FILE.exists():
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    return None

def enroll(enroll_url):
    print(f"[*] Starting enrollment for {enroll_url}")
    fp = get_fingerprint()
    token = generate_token(fp)
    
    # We need the base URL for heartbeats later.
    # If the URL is http://localhost:3000/enroll/abc, base is http://localhost:3000
    base_url = enroll_url.split("/enroll/")[0]
    
    # The backend expects POST /api/enroll/:id/claim
    api_claim_url = enroll_url.replace("/enroll/", "/api/enroll/") + "/claim"
    
    payload = {
        "token": token,
        "fingerprint": fp
    }
    
    try:
        print(f"[*] Sending enrollment request (Hostname: {fp['hostname']})...")
        resp = requests.post(api_claim_url, json=payload, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            print(f"[+] Enrollment successful! Asset ID: {data['asset_id']}")
            save_state(data["asset_id"], token, base_url)
            return True
        elif resp.status_code == 409:
            print("[-] Error: This enrollment link has already been used.")
        elif resp.status_code == 410:
            print("[-] Error: This enrollment link has expired (30-minute limit).")
        else:
            print(f"[-] Error: {resp.status_code} - {resp.text}")
            
    except requests.exceptions.ConnectionError:
        print("[-] Error: Could not connect to the server. Is the Node app running?")
        
    return False

def get_metrics():
    """Gather system metrics for the heartbeat."""
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    return {
        "cpu": psutil.cpu_percent(interval=None),
        "mem": vm.percent,
        "disk": disk.percent,
        "uptime": int(time.time() - psutil.boot_time())
    }

def run_heartbeat():
    state = load_state()
    if not state:
        print("[-] No credentials found. Please enroll first using:")
        print("    python agent.py --enroll <URL>")
        sys.exit(1)
        
    token = state["token"]
    base_url = state["base_url"]
    asset_id = state["asset_id"]
    
    url = f"{base_url}/api/heartbeat"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    print(f"[*] Starting heartbeat loop (every {HEARTBEAT_INTERVAL}s)")
    print(f"[*] Press Ctrl+C to stop.")
    
    try:
        while True:
            try:
                metrics = get_metrics()
                resp = requests.post(url, json=metrics, headers=headers, timeout=5)
                
                if resp.status_code == 200:
                    now = time.strftime("%H:%M:%S")
                    print(f"[{now}] Heartbeat OK - CPU: {metrics['cpu']}% | RAM: {metrics['mem']}%")
                elif resp.status_code == 401:
                    print("[-] Error: Token rejected by server. You may need to re-enroll.")
                    sys.exit(1)
                else:
                    print(f"[-] Heartbeat failed: {resp.status_code}")
            except requests.exceptions.RequestException:
                print("[-] Network error. Retrying...")
                
            time.sleep(HEARTBEAT_INTERVAL)
            
    except KeyboardInterrupt:
        print("\n[*] Heartbeat stopped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NShieldOps Asset Agent")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--enroll", metavar="URL", help="Enroll using the generated URL")
    group.add_argument("--start", action="store_true", help="Start heartbeat using saved credentials")
    
    args = parser.parse_args()
    
    if args.enroll:
        if enroll(args.enroll):
            # Automatically transition to heartbeat after enrolling
            print("-" * 40)
            run_heartbeat()
    elif args.start:
        run_heartbeat()
