#!/usr/bin/env python3
# metrics_collector.py – Real-time system sensors
# All rights reserved – Seliim Ahmed

import psutil
import time
import json
import os
from datetime import datetime

SENSOR_LOG = '/var/log/sa_akhran/sensors.log'

def collect_metrics():
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_io_counters()
    net = psutil.net_io_counters()
    
    return {
        'timestamp': datetime.now().isoformat(),
        'cpu_percent': cpu,
        'memory_percent': mem.percent,
        'disk_read_mb': disk.read_bytes / (1024 * 1024),
        'disk_write_mb': disk.write_bytes / (1024 * 1024),
        'network_recv_mb': net.bytes_recv / (1024 * 1024),
        'network_sent_mb': net.bytes_sent / (1024 * 1024)
    }

def log_metrics():
    os.makedirs(os.path.dirname(SENSOR_LOG), exist_ok=True)
    while True:
        data = collect_metrics()
        with open(SENSOR_LOG, 'a') as f:
            f.write(json.dumps(data) + '\n')
        time.sleep(2)

if __name__ == '__main__':
    log_metrics()
