#!/usr/bin/env python3
import argparse
import hashlib
import json
import logging
import os
import platform
import socket
import sys
import time
import uuid
from pathlib import Path
import psutil
import requests
import geocoder  # NEW: For location

# --- Configuration ---
STATE_FILE = Path.home() / ".nshieldops" / "agent.json"
LOG_FILE = Path.home() / ".nshieldops" / "agent.log"
HEARTBEAT_INTERVAL = 15

# --- Setup Logging ---
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def get_fingerprint():
    return {
        "hostname": socket.gethostname(),
        "mac": hex(uuid.getnode()),
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine()
    }

def generate_token(fp):
    return f"{os.urandom(16).hex()}_{hashlib.sha256(json.dumps(fp, sort_keys=True).encode()).hexdigest()[:16]}"

def enroll(enroll_url):
    logging.info(f"Starting enrollment for {enroll_url}")
    fp = get_fingerprint()
    token = generate_token(fp)
    base_url = enroll_url.split("/enroll/")[0]
    api_claim_url = enroll_url.replace("/enroll/", "/api/enroll/") + "/claim"
    
    try:
        resp = requests.post(api_claim_url, json={"token": token, "fingerprint": fp}, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            logging.info(f"Enrollment successful! Asset ID: {data['asset_id']}")
            
            STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(STATE_FILE, "w") as f:
                json.dump({"asset_id": data["asset_id"], "token": token, "base_url": base_url}, f)
            os.chmod(STATE_FILE, 0o600)
            return True
        logging.error(f"Enrollment failed: {resp.status_code} - {resp.text}")
    except requests.exceptions.ConnectionError:
        logging.error("Could not connect to the server. Is it running?")
    return False

def get_metrics():
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    
    # Get Location (approximate via IP)
    try:
        g = geocoder.ip('me')
        lat, lng = g.latlng if g.latlng else (0.0, 0.0)
    except Exception:
        lat, lng = 0.0, 0.0

    return {
        "cpu": psutil.cpu_percent(interval=None), 
        "mem": vm.percent, 
        "disk": disk.percent, 
        "uptime": int(time.time() - psutil.boot_time()),
        "latitude": lat,      
        "longitude": lng      
    }

def run_heartbeat():
    if not STATE_FILE.exists():
        logging.error("No credentials found. Please enroll first.")
        return False
        
    with open(STATE_FILE, "r") as f:
        state = json.load(f)
        
    url = f"{state['base_url']}/api/heartbeat"
    headers = {"Authorization": f"Bearer {state['token']}", "Content-Type": "application/json"}
    
    logging.info("Starting background heartbeat loop.")
    while True:
        try:
            metrics = get_metrics()
            resp = requests.post(url, json=metrics, headers=headers, timeout=10)
            if resp.status_code == 200:
                logging.info(f"Heartbeat OK - CPU: {metrics['cpu']}% | RAM: {metrics['mem']}% | Loc: {metrics['latitude']},{metrics['longitude']}")
            elif resp.status_code in [401, 403]:
                logging.error("Token rejected by server. You may need to re-enroll.")
                return False
            else:
                logging.warning(f"Heartbeat failed: {resp.status_code}")
        except requests.exceptions.RequestException as e:
            logging.warning(f"Network error: {e}")
            
        for _ in range(HEARTBEAT_INTERVAL):
            time.sleep(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--enroll", metavar="URL")
    group.add_argument("--start", action="store_true")
    args = parser.parse_args()
    
    if args.enroll:
        if enroll(args.enroll): 
            run_heartbeat()
    elif args.start:
        run_heartbeat()
