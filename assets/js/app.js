// FILE: assets/js/app.js
// Shared utilities for all pages – no static data, all external.

// Base endpoint – adjust to your backend host/port.
const API_BASE = '/api';

// Generic GET helper
function apiGet(endpoint) {
    return fetch(API_BASE + endpoint)
        .then(res => {
            if (!res.ok) throw new Error('HTTP ' + res.status);
            return res.json();
        });
}

// Generic POST helper
function apiPost(endpoint, body) {
    return fetch(API_BASE + endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    }).then(res => {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
    });
}

// Expose globally
window.apiGet = apiGet;
window.apiPost = apiPost;
