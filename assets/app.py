from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import random
import time

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)

VALID_IMEIS = {
    '865926067381640': {'name': 'Seliim Ahmed', 'phone': '+66615729906'}
}

sessions = {}

@app.route('/api/health')
def health():
    return jsonify({'status': 'online'})

@app.route('/api/bind', methods=['POST'])
def bind():
    data = request.get_json()
    name = data.get('name', '').strip()
    imei = data.get('imei', '').strip()
    if imei in VALID_IMEIS and VALID_IMEIS[imei]['name'].lower() == name.lower():
        sessions[imei] = {'name': name, 'time': time.time()}
        return jsonify({'status': 'success', 'message': 'Bind successful. Welcome ' + name})
    return jsonify({'status': 'failed', 'message': 'Invalid IMEI or Name'}), 401

@app.route('/api/energy_rate')
def energy():
    return jsonify({'rate': round(random.uniform(15, 85), 2)})

@app.route('/api/speed_rate')
def speed():
    return jsonify({'mbps': round(random.uniform(20, 600), 2)})

@app.route('/api/quarantine_list')
def quarantine():
    threats = [{'file': 'malware.exe', 'risk': 4}, {'file': 'spam.dll', 'risk': 2}]
    return jsonify(random.sample(threats, k=random.randint(0, 2)))

@app.route('/api/high_queries')
def high():
    qs = ['Kernel panic', 'IMEI mismatch', 'Energy spike']
    return jsonify({'queries': random.sample(qs, k=random.randint(1, 3))})

@app.route('/api/dashboard')
def dash():
    return jsonify({'drives': '/dev/sda1', 'sessions': len(sessions)})

@app.route('/')
def index():
    return send_from_directory('../frontend', 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('../frontend', path)

if __name__ == '__main__':
    print("Server running on http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
