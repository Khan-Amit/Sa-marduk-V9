#!/usr/bin/env python3
# guard_daemon.py – Sa Akhran® Sluice Gate
# All rights reserved – Seliim Ahmed (amit.khanna.1082@gmail.com)

import os
import sys
import time
import json
import shutil
import sqlite3
import logging
import subprocess
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import magic

from sa_akhran_core import process_query, GROUPS
from sensors.metrics_collector import collect_metrics

CONFIG_FILE = 'config.json'
QUARANTINE_DIR = '/var/quarantine/sa_akhran'
LOG_FILE = '/var/log/sa_akhran/guard.log'
DB_FILE = '/var/log/sa_akhran/sluice.db'

os.makedirs(QUARANTINE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ---- Database Setup ----
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS rejections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file TEXT,
            drive TEXT,
            reason TEXT,
            timestamp TEXT,
            file_hash TEXT,
            file_size INTEGER
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS quarantine (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path TEXT,
            quarantined_path TEXT,
            reason TEXT,
            timestamp TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS energy_spikes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            drive TEXT,
            cpu_percent REAL,
            disk_mb REAL,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_rejection(file, drive, reason, file_hash='', size=0):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT INTO rejections (file, drive, reason, timestamp, file_hash, file_size) VALUES (?,?,?,?,?,?)',
              (file, drive, reason, datetime.now().isoformat(), file_hash, size))
    conn.commit()
    conn.close()

def log_quarantine(original, quarantined, reason):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT INTO quarantine (original_path, quarantined_path, reason, timestamp) VALUES (?,?,?,?)',
              (original, quarantined, reason, datetime.now().isoformat()))
    conn.commit()
    conn.close()

def log_energy_spike(drive, cpu, disk):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT INTO energy_spikes (drive, cpu_percent, disk_mb, timestamp) VALUES (?,?,?,?)',
              (drive, cpu, disk, datetime.now().isoformat()))
    conn.commit()
    conn.close()

# ---- Load Config ----
def load_config():
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

# ---- MIME to Group ----
def mime_to_group(mime_type, filename, size=0):
    if mime_type.startswith('application/x-executable') or mime_type.startswith('application/x-msdownload'):
        return 7
    if filename.endswith(('.sh', '.bash', '.py', '.pl', '.rb', '.js')):
        return 9
    if filename.endswith(('.dll', '.so', '.dylib')):
        return 8
    if filename.endswith(('.apk', '.ipa')):
        return 11
    if mime_type.startswith('audio/') or mime_type.startswith('video/') or mime_type.startswith('image/'):
        return 19
    if filename.endswith(('.mp3', '.wav', '.mp4', '.avi', '.mkv', '.jpg', '.png', '.gif')):
        return 19
    if mime_type in ('application/zip', 'application/x-tar', 'application/x-gzip'):
        return 25
    if filename.endswith(('.tar', '.gz', '.bz2', '.xz', '.zip', '.rar', '.7z', '.iso')):
        return 25
    if filename.endswith(('.encrypted', '.crypted', '.locked', '.ransom')):
        return 35
    return 0

# ---- Energy Spike Monitor ----
def check_energy_spike(drive_path, config):
    metrics = collect_metrics()
    cpu = metrics['cpu_percent']
    disk_write = metrics['disk_write_mb']
    
    for watch in config['watches']:
        if watch['path'] == drive_path:
            threshold = watch.get('cpu_threshold', 80)
            if cpu > threshold and disk_write > 50:
                log_energy_spike(drive_path, cpu, disk_write)
                logging.warning(f"⚠️ Energy spike on {drive_path}: CPU={cpu}%, Disk={disk_write:.2f}MB")
                return True
    return False

# ---- File Event Handler ----
class SluiceGateHandler(FileSystemEventHandler):
    def __init__(self, config):
        self.config = config
        self.path_map = {}
        for entry in config['watches']:
            path = os.path.abspath(entry['path'])
            allowed = entry['allowed_groups']
            self.path_map[path] = allowed
            logging.info(f"Watching {path} -> Allowed groups: {allowed}")

    def on_created(self, event):
        if event.is_directory:
            return
        self.process_file(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return
        self.process_file(event.dest_path)

    def process_file(self, file_path):
        if not os.path.exists(file_path):
            return

        parent_dir = os.path.dirname(file_path)
        watch_path = None
        allowed_groups = None
        for path in self.path_map:
            if parent_dir.startswith(path):
                watch_path = path
                allowed_groups = self.path_map[path]
                break

        if allowed_groups is None:
            return

        # ---- ENERGY SPIKE CHECK ----
        if check_energy_spike(watch_path, self.config):
            dest = os.path.join(QUARANTINE_DIR, f"{os.path.basename(file_path)}.spike_{int(time.time())}")
            shutil.move(file_path, dest)
            log_quarantine(file_path, dest, f"Energy spike on {watch_path}")
            logging.warning(f"⚡ Spike quarantine: {file_path}")
            return

        # ---- SEGREGATION ----
        try:
            mime = magic.from_file(file_path, mime=True)
        except:
            mime = 'application/octet-stream'

        file_group_id = mime_to_group(mime, os.path.basename(file_path), os.path.getsize(file_path))

        if file_group_id not in allowed_groups and file_group_id != 0:
            dest = os.path.join(QUARANTINE_DIR, f"{os.path.basename(file_path)}.rejected_{int(time.time())}")
            shutil.move(file_path, dest)
            reason = f"Group {file_group_id} not allowed on {watch_path}"
            log_rejection(os.path.basename(file_path), watch_path, reason)
            log_quarantine(file_path, dest, reason)
            logging.warning(f"🚫 REJECTED: {file_path} -> {reason}")
            return

        # ---- DEEP SCAN ----
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
            log_rejection(filename, watch_path, "Malicious verdict from deep scan")
            log_quarantine(file_path, dest, "Malicious content detected")
            logging.warning(f"☠️ MALICIOUS: {file_path} -> Quarantined")
        else:
            logging.info(f"✅ PASSED: {file_path}")

# ---- Main ----
if __name__ == "__main__":
    if not os.path.exists(CONFIG_FILE):
        print(f"ERROR: {CONFIG_FILE} not found.")
        sys.exit(1)

    init_db()
    config = load_config()
    event_handler = SluiceGateHandler(config)
    observer = Observer()

    for entry in config['watches']:
        path = os.path.abspath(entry['path'])
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)
        observer.schedule(event_handler, path, recursive=True)

    print(f"🛡️ Sa Akhran® Sluice‑bench running.")
    print(f"📁 Watching {len(config['watches'])} drives.")
    print(f"🗑️ Quarantine: {QUARANTINE_DIR}")
    print(f"📜 Logs: {LOG_FILE}")
    print(f"💾 Database: {DB_FILE}")

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
