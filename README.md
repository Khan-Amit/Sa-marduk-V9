# Sa‑marduk‑V9 – Informational Sanity Protocol

**Copyright © 2026 Seliim Ahmed.** All rights reserved.  
Contact: amit.khanna.1082@gmail.com

---

## Philosophy

Sa‑marduk‑V9 is a **quantum error‑correction firewall** for file systems, built upon the unified framework presented in the paper *"The Informational Substrate of Reality: Spacetime Expansion, Fractal Viscosity, and Quantum Error Correction as a Universal Sanity Protocol"* by Seliim Ahmed.

The software enforces **segregation of data by purpose** using a 36‑group classification system, a ternary logic engine (Voice of Brahma), and an Enigma translator that outputs HTML verdicts. It operates as a **Sluice‑bench** – a gatekeeper that instantly rejects data that does not belong to the intended drive's allowed groups, thereby saving energy, preventing boot‑level infections, and stopping ransomware before it executes.

---

## Key Features

- **36‑Group Classification** – Covers kernel, executables, network, storage, UI, and anomalies.
- **Voice of Brahma** – Ternary logic (`-1` malicious, `0` neutral, `+1` safe) based on keyword/trait scoring.
- **Drive Segregation** – Each mount point is assigned a whitelist of allowed groups. Any file that doesn't match is rejected instantly.
- **Energy‑Spike Detection** – Monitors CPU/disk usage; sudden anomalies trigger Group 31 alerts.
- **Live Dashboard** – Visual monitoring of rejections, quarantine size, and active rules.
- **Portable Offline Analyzer** – `analyze.html` runs in any browser without a server.
- **Linux Daemon** – `guard_daemon.py` watches file system writes in real time, using `fanotify` (optional) for pre‑write blocking.

---

## Deployment

### Browser (Client)
- Open `index.html` in any modern browser.
- Use the **Analyze Engine** to test queries.
- Download the **Portable ZIP** for offline use.

### Server (Linux)
1. Clone this repo.
2. Install dependencies: `pip install -r backend/requirements.txt`
3. Copy `backend/config.example.json` to `backend/config.json` and edit your drive mappings.
4. Run `python3 backend/guard_daemon.py` (as root for fanotify).
5. Optionally install as a systemd service.

---

## Paper

The full theoretical paper is included in `docs/Informational_Substrate_of_Reality.pdf`.

---

## License

This software is proprietary. Unauthorized reproduction, distribution, or modification is strictly prohibited without prior written consent from the author.
