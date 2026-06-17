#!/usr/bin/env python3
# sa_akhran_core.py
# All rights reserved – Seliim Ahmed (amit.khanna.1082@gmail.com)

import re
import os

# 36 Groups (exact same as your HTML)
GROUPS = {
    0: {'name': 'General System Inquiry', 'domain': 'unknown', 'trait': 'Unclassified'},
    1: {'name': 'Boot Loader', 'domain': 'kernel', 'trait': 'Root-Trust Only'},
    2: {'name': 'Kernel Core', 'domain': 'kernel', 'trait': 'Root-Trust Only'},
    3: {'name': 'Device Drivers', 'domain': 'kernel', 'trait': 'Root-Trust Only'},
    4: {'name': 'System Registry', 'domain': 'kernel', 'trait': 'Root-Trust Only'},
    5: {'name': 'BIOS/UEFI', 'domain': 'kernel', 'trait': 'Root-Trust Only'},
    6: {'name': 'Boot Configuration', 'domain': 'kernel', 'trait': 'Root-Trust Only'},
    7: {'name': 'Portable Executables', 'domain': 'executable', 'trait': 'Hash-Anchored'},
    8: {'name': 'Dynamic Libraries', 'domain': 'executable', 'trait': 'Hash-Anchored'},
    9: {'name': 'Scripts (JS/Python)', 'domain': 'executable', 'trait': 'Hash-Anchored'},
    10: {'name': 'Macros', 'domain': 'executable', 'trait': 'Hash-Anchored'},
    11: {'name': 'APK/IPA', 'domain': 'executable', 'trait': 'Hash-Anchored'},
    12: {'name': 'Firmware Updates', 'domain': 'executable', 'trait': 'Hash-Anchored'},
    13: {'name': 'Inbound TCP', 'domain': 'network', 'trait': 'Temporal-Flow'},
    14: {'name': 'Outbound TCP', 'domain': 'network', 'trait': 'Temporal-Flow'},
    15: {'name': 'Inbound UDP', 'domain': 'network', 'trait': 'Temporal-Flow'},
    16: {'name': 'Outbound UDP', 'domain': 'network', 'trait': 'Temporal-Flow'},
    17: {'name': 'ICMP/Ping', 'domain': 'network', 'trait': 'Temporal-Flow'},
    18: {'name': 'DNS Queries', 'domain': 'network', 'trait': 'Temporal-Flow'},
    19: {'name': 'Keyboard Input', 'domain': 'ui', 'trait': 'Context-Aware'},
    20: {'name': 'Mouse/Touch', 'domain': 'ui', 'trait': 'Context-Aware'},
    21: {'name': 'Voice Commands', 'domain': 'ui', 'trait': 'Context-Aware'},
    22: {'name': 'Camera Feed', 'domain': 'ui', 'trait': 'Context-Aware'},
    23: {'name': 'Clipboard Data', 'domain': 'ui', 'trait': 'Context-Aware'},
    24: {'name': 'Form Submissions', 'domain': 'ui', 'trait': 'Context-Aware'},
    25: {'name': 'Internal Flash', 'domain': 'storage', 'trait': 'Spatial-Mapping'},
    26: {'name': 'External SD Card', 'domain': 'storage', 'trait': 'Spatial-Mapping'},
    27: {'name': 'USB Drives', 'domain': 'storage', 'trait': 'Spatial-Mapping'},
    28: {'name': 'Cloud Volumes', 'domain': 'storage', 'trait': 'Spatial-Mapping'},
    29: {'name': 'Temp Cache', 'domain': 'storage', 'trait': 'Spatial-Mapping'},
    30: {'name': 'Swap/Pagefile', 'domain': 'storage', 'trait': 'Spatial-Mapping'},
    31: {'name': 'Unusual CPU Spikes', 'domain': 'anomaly', 'trait': 'Bayesian-Predictive'},
    32: {'name': 'Memory Leaks', 'domain': 'anomaly', 'trait': 'Bayesian-Predictive'},
    33: {'name': 'I/O Bottlenecks', 'domain': 'anomaly', 'trait': 'Bayesian-Predictive'},
    34: {'name': 'Permission Escalation', 'domain': 'anomaly', 'trait': 'Bayesian-Predictive'},
    35: {'name': 'Encrypted Ransomware', 'domain': 'anomaly', 'trait': 'Bayesian-Predictive'},
    36: {'name': 'Unknown Outbound Calls', 'domain': 'anomaly', 'trait': 'Bayesian-Predictive'}
}

# ---- Noise Filter ----
def is_relevant_query(text):
    keywords = ['file','process','network','packet','kernel','memory','storage','disk','usb',
                'boot','execute','script','malware','virus','spam','permission','encrypt',
                'connection','socket','port','registry','cache','heap','stack','cpu','gpu','ram']
    return any(k in text.lower() for k in keywords)

# ---- Classifier ----
def classify_query(text):
    lower = text.lower()
    matched = []
    for gid, g in GROUPS.items():
        if (g['domain'] in lower or g['name'].lower() in lower or 
            any(w in lower for w in g['trait'].lower().replace('-',' ').split())):
            matched.append({'id': gid, **g})
    if not matched:
        matched.append({'id': 0, **GROUPS[0]})
    return matched

# ---- Voice of Brahma (Ternary) ----
def voice_of_brahma(text, group):
    lower = text.lower()
    mal_words = ['virus','malware','trojan','ransom','spam','phish','exploit','inject',
                 'buffer overflow','backdoor','keylog','adware','rootkit']
    safe_words = ['trusted','signature','verified','official','update','security','patch','backup']
    mal = sum(1 for w in mal_words if w in lower)
    safe = sum(1 for w in safe_words if w in lower)
    if group['trait'] in ['Root-Trust Only', 'Hash-Anchored']: safe += 2
    if group['trait'] == 'Bayesian-Predictive': mal += 1
    if mal > safe: return -1
    if safe > mal: return 1
    return 0

# ---- Main Processor ----
def process_query(text):
    if not is_relevant_query(text):
        return {'status': 'NOISE_REJECTED', 'verdict': 'Irrelevant', 'groups': []}
    groups = classify_query(text)
    states = [voice_of_brahma(text, g) for g in groups]
    overall = sum(states)
    verdict = 'SAFE' if overall > 0 else ('MALICIOUS' if overall < 0 else 'NEUTRAL')
    return {'status': 'PROCESSED', 'verdict': verdict, 'groups': groups, 'states': states}
