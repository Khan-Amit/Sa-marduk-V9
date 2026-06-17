#!/usr/bin/env python3
# guard_daemon.py – Sa Akhran® Sluice Gate Daemon
# All rights reserved – Seliim Ahmed (amit.khanna.1082@gmail.com)

import os
import sys
import time
import json
import shutil
import logging
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import magic  # pip install python-magic-bin (or libmagic-dev)

from sa_akhran_core import process_query, GROUPS

# ---- CONFIG ----
CONFIG_FILE = 'config.json'
QUARANTINE_DIR = '/var/quarantine/sa_akhran'
LOG_FILE = '/var/log/sa_akhran/guard.log'

os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ---- Load Segregation Rules ----
def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

# ---- Map MIME type to Group ID ----
def mime_to_group(mime_type, filename):
    # Executables (Group 7-12)
    if mime_type.startswith('application/x-executable') or mime_type.startswith('application/x-msdownload'):
        return 7
    if filename.endswith(('.sh', '.bash', '.py', '.pl', '.rb', '.js')):
        return 9
    if filename.endswith(('.dll', '.so', '.dylib')):
        return 8
    if filename.endswith(('.apk', '.ipa')):
        return 11
    
    # Media / UI (Group 19-24)
    if mime_type.startswith('audio/') or mime_type.startswith('video/') or mime_type.startswith('image/'):
        return 19
    if filename.endswith(('.mp3', '.wav', '.mp4', '.avi', '.mkv', '.jpg', '.png', '.gif')):
        return 19

    # Archives / Storage (Group 25-30)
    if mime_type in ('application/zip', 'application/x-tar', 'application/x-gzip', 'application/x-iso9660-image'):
        return 25
    if filename.endswith(('.tar', '.gz', '.bz2', '.xz', '.zip', '.rar', '.7z', '.iso')):
        return 25

    # Default fallback – treat as General (Group 0)
    return 0

# ---- File Event Handler ----
class SluiceGateHandler(FileSystemEventHandler):
    def __init__(self, config):
        self.config = config
        # Reverse map: allowed_group_ids per watch path
        self.path_map = {}
        for entry in config['watches']:
            path = os.path.abspath(entry['path'])
            allowed = entry['allowed_group_ids']
            self.path_map[path] = allowed
            logging.info(f"Guard active on {path} -> Allowed groups: {allowed}")

    def on_created(self, event):
        if event.is_directory:
            return
        self.process_file(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        self.process_file(event.dest_path)

    def process_file(self, file_path):
        # Check if file still exists
        if not os.path.exists(file_path):
            return

        # Find which watch path this belongs to
        parent_dir = os.path.dirname(file_path)
        watch_path = None
        allowed_groups = None
        for path in self.path_map:
            if parent_dir.startswith(path):
                watch_path = path
                allowed_groups = self.path_map[path]
                break
        
        if allowed_groups is None:
            logging.warning(f"File {file_path} not under any watched path. Ignoring.")
            return

        # ---- Step 1: SEGREGATION (The Sluice Gate) ----
        try:
            mime = magic.from_file(file_path, mime=True)
        except:
            mime = 'application/octet-stream'
        
        file_group_id = mime_to_group(mime, os.path.basename(file_path))
        
        # Check if file group is allowed in this drive
        if file_group_id not in allowed_groups and file_group_id != 0:
            # REJECT – Move to quarantine immediately (Energy Saver!)
            dest = os.path.join(QUARANTINE_DIR, f"{os.path.basename(file_path)}.rejected_{int(time.time())}")
            shutil.move(file_path, dest)
            logging.warning(f"REJECTED: {file_path} (MIME:{mime}) -> Group {file_group_id} not allowed for {watch_path}")
            return

        # ---- Step 2: DEEP SCAN (Only for allowed types) ----
        # Build query from filename and a small read of the first 1KB
        filename = os.path.basename(file_path)
        try:
            with open(file_path, 'rb') as f:
                header = f.read(1024).decode('utf-8', errors='ignore')
        except:
            header = ""
        
        query_text = f"File: {filename} | Magic: {mime} | Header: {header[:200]}"
        result = process_query(query_text)

        if result['verdict'] == 'MALICIOUS':
            dest = os.path.join(QUARANTINE_DIR, f"{os.path.basename(file_path)}.malicious_{int(time.time())}")
            shutil.move(file_path, dest)
            logging.warning(f"MALICIOUS: {file_path} -> Quarantined. Query: {query_text}")
        else:
            logging.info(f"PASSED: {file_path} -> Verdict: {result['verdict']}")

# ---- Main ----
if __name__ == "__main__":
    if not os.path.exists(CONFIG_FILE):
        print(f"ERROR: {CONFIG_FILE} not found.")
        sys.exit(1)

    config = load_config()
    event_handler = SluiceGateHandler(config)
    observer = Observer()

    for entry in config['watches']:
        path = os.path.abspath(entry['path'])
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
        observer.schedule(event_handler, path, recursive=True)
        logging.info(f"Watching: {path}")

    print(f"Sa Akhran® Sluice Gate running. Watching {len(config['watches'])} drives.")
    print(f"Quarantine: {QUARANTINE_DIR}")
    print(f"Logs: {LOG_FILE}")
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
