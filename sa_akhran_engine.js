// ============================================================
// Sa Akhran® Core Engine – Virus & Spam Guard
// All rights reserved – Seliim Ahmed (amit.khanna.1082@gmail.com)
//
// The 36 Group Classification System
// Voice of Brahma (Ternary Translation)
// Enigma Translator (HTML Output)
// ============================================================

// --------------------- 1. THE 36 GROUPS ---------------------
// Each group has a unique trait and domain.

const GROUPS = {
    // Kernel & Boot Sectors (1-6)
    1: { name: 'Boot Loader', domain: 'kernel', trait: 'Root-Trust Only' },
    2: { name: 'Kernel Core', domain: 'kernel', trait: 'Root-Trust Only' },
    3: { name: 'Device Drivers', domain: 'kernel', trait: 'Root-Trust Only' },
    4: { name: 'System Registry', domain: 'kernel', trait: 'Root-Trust Only' },
    5: { name: 'BIOS/UEFI', domain: 'kernel', trait: 'Root-Trust Only' },
    6: { name: 'Boot Configuration', domain: 'kernel', trait: 'Root-Trust Only' },

    // Executable Signatures (7-12)
    7: { name: 'Portable Executables', domain: 'executable', trait: 'Hash-Anchored' },
    8: { name: 'Dynamic Libraries', domain: 'executable', trait: 'Hash-Anchored' },
    9: { name: 'Scripts (JS/Python)', domain: 'executable', trait: 'Hash-Anchored' },
    10: { name: 'Macros', domain: 'executable', trait: 'Hash-Anchored' },
    11: { name: 'APK/IPA', domain: 'executable', trait: 'Hash-Anchored' },
    12: { name: 'Firmware Updates', domain: 'executable', trait: 'Hash-Anchored' },

    // Network Packets (13-18)
    13: { name: 'Inbound TCP', domain: 'network', trait: 'Temporal-Flow' },
    14: { name: 'Outbound TCP', domain: 'network', trait: 'Temporal-Flow' },
    15: { name: 'Inbound UDP', domain: 'network', trait: 'Temporal-Flow' },
    16: { name: 'Outbound UDP', domain: 'network', trait: 'Temporal-Flow' },
    17: { name: 'ICMP/Ping', domain: 'network', trait: 'Temporal-Flow' },
    18: { name: 'DNS Queries', domain: 'network', trait: 'Temporal-Flow' },

    // Human Input / UI (19-24)
    19: { name: 'Keyboard Input', domain: 'ui', trait: 'Context-Aware' },
    20: { name: 'Mouse/Touch', domain: 'ui', trait: 'Context-Aware' },
    21: { name: 'Voice Commands', domain: 'ui', trait: 'Context-Aware' },
    22: { name: 'Camera Feed', domain: 'ui', trait: 'Context-Aware' },
    23: { name: 'Clipboard Data', domain: 'ui', trait: 'Context-Aware' },
    24: { name: 'Form Submissions', domain: 'ui', trait: 'Context-Aware' },

    // Storage Sectors (25-30)
    25: { name: 'Internal Flash', domain: 'storage', trait: 'Spatial-Mapping' },
    26: { name: 'External SD Card', domain: 'storage', trait: 'Spatial-Mapping' },
    27: { name: 'USB Drives', domain: 'storage', trait: 'Spatial-Mapping' },
    28: { name: 'Cloud Volumes', domain: 'storage', trait: 'Spatial-Mapping' },
    29: { name: 'Temp Cache', domain: 'storage', trait: 'Spatial-Mapping' },
    30: { name: 'Swap/Pagefile', domain: 'storage', trait: 'Spatial-Mapping' },

    // Heuristic Anomalies (31-36)
    31: { name: 'Unusual CPU Spikes', domain: 'anomaly', trait: 'Bayesian-Predictive' },
    32: { name: 'Memory Leaks', domain: 'anomaly', trait: 'Bayesian-Predictive' },
    33: { name: 'I/O Bottlenecks', domain: 'anomaly', trait: 'Bayesian-Predictive' },
    34: { name: 'Permission Escalation', domain: 'anomaly', trait: 'Bayesian-Predictive' },
    35: { name: 'Encrypted Ransomware', domain: 'anomaly', trait: 'Bayesian-Predictive' },
    36: { name: 'Unknown Outbound Calls', domain: 'anomaly', trait: 'Bayesian-Predictive' }
};

// --------------------- 2. NOISE FILTER ---------------------
// The "Tailor/Lawyer" rule: if it's not about systems, reject it.
function isRelevantQuery(input) {
    const keywords = ['file', 'process', 'network', 'packet', 'kernel', 'memory', 
                      'storage', 'disk', 'usb', 'boot', 'execute', 'script', 'malware',
                      'virus', 'spam', 'permission', 'encrypt', 'connection', 'socket',
                      'port', 'registry', 'cache', 'heap', 'stack', 'cpu', 'gpu', 'ram'];
    const lower = input.toLowerCase();
    return keywords.some(kw => lower.includes(kw));
}

// --------------------- 3. GROUP CLASSIFIER ---------------------
// Maps a query to one or more groups.
function classifyQuery(input) {
    const lower = input.toLowerCase();
    let matchedGroups = [];

    for (let id in GROUPS) {
        const group = GROUPS[id];
        // Simple keyword mapping (in real system, this is an ML/rule engine)
        if (lower.includes(group.domain) || lower.includes(group.name.toLowerCase()) || 
            lower.includes(group.trait.toLowerCase().split(' ')[0].toLowerCase())) {
            matchedGroups.push({ id: parseInt(id), ...group });
        }
    }

    // If nothing matches, default to storage (group 25)
    if (matchedGroups.length === 0) {
        matchedGroups.push({ id: 25, ...GROUPS[25] });
    }

    return matchedGroups;
}

// --------------------- 4. VOICE OF BRAHMA (Ternary Translator) ---------------------
// Converts input and group traits into a Ternary state: -1, 0, +1
// +1 = Safe/Trusted, 0 = Neutral/Unknown, -1 = Malicious/Unsafe

function voiceOfBrahma(query, group) {
    // Heuristic scoring based on threat indicators
    let score = 0;
    const lower = query.toLowerCase();

    // Malicious indicators (score -1)
    const malwareWords = ['virus', 'malware', 'trojan', 'ransom', 'spam', 'phish', 
                          'exploit', 'inject', 'buffer overflow', 'backdoor', 'keylog'];
    const safeWords = ['trusted', 'signature', 'verified', 'official', 'update', 
                       'security', 'patch', 'backup'];

    // Count hits
    let malScore = malwareWords.filter(w => lower.includes(w)).length;
    let safeScore = safeWords.filter(w => lower.includes(w)).length;

    // Group trait weights
    if (group.trait === 'Root-Trust Only' || group.trait === 'Hash-Anchored') {
        safeScore += 2; // More trusting of kernel/executable domains
    }
    if (group.trait === 'Bayesian-Predictive') {
        malScore += 1; // Anomaly groups are suspicious by nature
    }

    // Ternary decision
    if (malScore > safeScore) return -1; // Malicious
    if (safeScore > malScore) return 1;  // Safe
    return 0; // Uncertain/Neutral
}

// --------------------- 5. ENIGMA TRANSLATOR ---------------------
// Translates the Ternary result + group + query into HTML output.
// Only emits HTML if query was relevant (no noise).

function enigmaTranslator(query, groups, ternaries) {
    if (!isRelevantQuery(query)) {
        return { output: 'VOID: Query discarded (Irrelevant to system).', html: '' };
    }

    // Build the verdict
    let overallStatus = 0;
    let details = '';

    groups.forEach((group, index) => {
        const state = ternaries[index];
        overallStatus += state; // Sum up

        const statusText = state === 1 ? '✅ SAFE' : (state === -1 ? '❌ MALICIOUS' : '⚪ NEUTRAL');
        details += `<tr>
            <td>${group.id}</td>
            <td>${group.name}</td>
            <td>${group.trait}</td>
            <td><strong style="color:${state===1?'#3fb950':state===-1?'#f85149':'#d29922'}">${statusText}</strong></td>
        </tr>`;
    });

    const finalVerdict = overallStatus > 0 ? '✅ OVERALL: SAFE (No threat detected)' :
                          overallStatus < 0 ? '🚨 OVERALL: MALICIOUS (Action required)' :
                          '⚠️ OVERALL: NEUTRAL (Requires human review)';

    // Build HTML
    const html = `
    <div style="font-family:monospace; background:#0d1117; color:#c9d1d9; padding:20px; border-radius:8px;">
        <h2 style="color:#58a6ff;">Sa Akhran® Analysis Report</h2>
        <p><strong>Query:</strong> "${query}"</p>
        <hr style="border-color:#30363d;">
        <h3>36-Group Classification Result</h3>
        <table style="width:100%; border-collapse:collapse;">
            <thead><tr style="border-bottom:2px solid #30363d;">
                <th>Group</th><th>Name</th><th>Trait</th><th>Ternary Verdict</th>
            </tr></thead>
            <tbody>
                ${details}
            </tbody>
        </table>
        <hr style="border-color:#30363d;">
        <h1 style="color:${overallStatus>0?'#3fb950':overallStatus<0?'#f85149':'#d29922'};">${finalVerdict}</h1>
        <p style="color:#8b949e; font-size:12px;">All rights reserved · Seliim Ahmed · amit.khanna.1082@gmail.com</p>
    </div>
    `;

    return { output: finalVerdict, html };
}

// --------------------- 6. MAIN PROCESSOR (The whole pipeline) ---------------------
function processQuery(inputQuery) {
    // Step 1: Noise Filter
    if (!isRelevantQuery(inputQuery)) {
        return { 
            status: 'NOISE_REJECTED', 
            message: 'Discarded: The system does not entertain grocery/recipe queries.',
            html: '<p style="color:#f85149;">VOID: Irrelevant query.</p>'
        };
    }

    // Step 2: Classify into 36 groups
    const matchedGroups = classifyQuery(inputQuery);

    // Step 3: Voice of Brahma (Ternary for each group)
    const ternaries = matchedGroups.map(g => voiceOfBrahma(inputQuery, g));

    // Step 4: Enigma Translator -> HTML
    const result = enigmaTranslator(inputQuery, matchedGroups, ternaries);

    return {
        status: 'PROCESSED',
        query: inputQuery,
        groups: matchedGroups,
        ternaryStates: ternaries,
        verdict: result.output,
        html: result.html
    };
}

// ============================================================
// EXPOSE FOR TESTING (Browser/Node)
// ============================================================
if (typeof window !== 'undefined') {
    window.processQuery = processQuery;
    window.GROUPS = GROUPS;
} else {
    module.exports = { processQuery, GROUPS };
}

// ============================================================
// DEMO / TEST (Run this)
// ============================================================
console.log('=== Sa Akhran® Engine Loaded ===');

// Test 1: Relevant query
const test1 = processQuery('Check the memory usage of process 4432');
console.log('Test 1 Verdict:', test1.verdict);
console.log('Test 1 HTML:', test1.html);

// Test 2: Irrelevant query (Noise)
const test2 = processQuery('How to cook biryani?');
console.log('Test 2:', test2.message);

// Test 3: Malicious query
const test3 = processQuery('Suspicious ransomware file detected on USB drive');
console.log('Test 3 Verdict:', test3.verdict);
