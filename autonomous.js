// AEGIS Autonomous Response Logic (Team Anvay & Tanmay)

const API_BASE = (
    window.location.hostname === 'localhost' ||
    window.location.hostname === '127.0.0.1' ||
    window.location.hostname === ''
)
    ? "http://127.0.0.1:8000/api" 
    : "https://aegis-api-65i8.onrender.com/api"; 

let dashboardData = null;
let map;
let nodeMarkers = {};
let isFirstLoad = true;
let anomalies = []; // Real anomaly stream
window.globalThreshold = 0.5; // Default 50%
window.liveNodeScores = {}; // Real-time pulse overlay for Grid
window.liveNodeDetectors = {}; // Tracks anomaly sources (e.g. ThreatSimulator)
window.activeSimulators = { LATENCY: false, DECEPTION: false };

// 1. Graphical Grid Initialization (Replaces Map Tracking)
function initHealthGrid() {
    const grid = document.getElementById('healthGrid');
    const tooltip = document.getElementById('nodeTooltip');
    if (!grid) return;
    
    grid.innerHTML = '';
    // Construct exactly 500 nodes (25x20)
    for (let i = 1; i <= 500; i++) {
        const box = document.createElement('div');
        box.id = `node-box-${i}`;
        // Increased font size and maximum weight for long-distance readability
        box.className = 'w-full h-full bg-[#00FBFB] flex items-center justify-center text-[10px] font-[900] text-black/60 overflow-hidden transition-colors duration-200';
        box.innerText = i;
        
        // --- HOLOGRAPHIC TOOLTIP HANDLERS ---
        box.onmouseenter = (e) => {
            if (!tooltip) return;
            tooltip.style.visibility = 'visible';
            updateTooltipContent(i);
        };
        
        box.onmousemove = (e) => {
            if (!tooltip) return;
            tooltip.style.left = (e.clientX + 15) + 'px';
            tooltip.style.top = (e.clientY + 15) + 'px';
        };
        
        box.onmouseleave = () => {
            if (tooltip) tooltip.style.visibility = 'hidden';
        };

        grid.appendChild(box);
    }
}

// Helper to sync tooltip with live telemetry
function updateTooltipContent(nodeId) {
    const tooltip = document.getElementById('nodeTooltip');
    if (!tooltip || !dashboardData) return;

    const node = (dashboardData.nodes || []).find(n => n.id === nodeId);
    const liveScore = window.liveNodeScores[nodeId] || (node ? (node.threat_score || 0) : 0);
    const scorePct = (liveScore * 100).toFixed(1);
    
    // Status Logic
    let statusText = 'OPERATIONAL';
    let statusColor = '#00FBFB';
    
    if (node?.is_quarantined || liveScore > window.globalThreshold) {
        statusText = 'QUARANTINED';
        statusColor = '#ff3131';
    } else if (node?.is_infected || (liveScore > 0.3)) {
        statusText = 'INFECTED';
        statusColor = '#f97316';
    }

    tooltip.style.borderColor = statusColor;
    tooltip.style.boxShadow = `0 0 15px ${statusColor}4D`;
    tooltip.innerHTML = `
        <div style="border-bottom: 1px solid ${statusColor}33; padding-bottom: 4px; margin-bottom: 4px; font-weight: 900; color: ${statusColor};">
            NODE_${nodeId}
        </div>
        <div class="flex flex-col gap-1">
            <div class="flex justify-between">STATUS: <span style="font-weight: 800; color: ${statusColor};">${statusText}</span></div>
            <div class="flex justify-between">THREAT: <span style="font-weight: 800; color: white;">${scorePct}%</span></div>
            <div class="flex justify-between text-[8px] opacity-70">SYST: NEXUS_CORE_PULSE</div>
        </div>
    `;
}

// 2. Autonomous Data Ingestion
async function fetchAutonomousData() {
    try {
        const token = localStorage.getItem('access_token');
        // ALWAYS fetch full=true so the 500-Node Health Grid syncs real-time colors
        const response = await fetch(`${API_BASE}/dashboard-aggregator?full=true`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.status === 401) {
            window.location.href = 'login.html';
            return;
        }

        const data = await response.json();
        dashboardData = data;
        isFirstLoad = false;
        
        updateTacticalUI();
    } catch (error) {
        console.error("Autonomous Sync Error:", error);
    }
}

let lastTelemetryId = -1;

// 3. Autonomous Telemetry Hook (Replaces Aggregator Polling)
async function streamLiveTelemetry() {
    try {
        const token = localStorage.getItem('access_token');
        if (!token) return;

        const url = lastTelemetryId > -1 
            ? `${API_BASE}/system-logs?limit=100&after_id=${lastTelemetryId}`
            : `${API_BASE}/system-logs?limit=100`;

        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        
        if (!response.ok) return;
        const logs = await response.json();

        if (logs.length > 0) {
            lastTelemetryId = logs[logs.length - 1].id;
            
            // Map real-time scores for fast grid painting
            logs.forEach(l => {
                window.liveNodeScores[l.node_id] = l.threat_score;
                window.liveNodeDetectors[l.node_id] = l.detector;
            });
            
            // Feed the timeline and protocol log directly with the raw pulse data
            renderAttackTimeline(logs);
            renderQuarantineLog(logs);
            
            // Immediately force a fast-repaint of the Grid to bypass 3s sync delay
            updateHealthGrid();
        }
    } catch (error) {
        // Silent fail for fast loop
    }
}

// [NEW] Active Health List Data Renderer
function renderActiveHealthList() {
    const listContainer = document.getElementById('healthListContainer');
    if (!listContainer || !dashboardData || !dashboardData.nodes) return;
    
    listContainer.innerHTML = '';
    
    // Sort displaying threats bubbling up to the top
    let nodes = [...dashboardData.nodes];
    nodes.sort((a,b) => {
        let scoreA = window.liveNodeScores[a.id] || a.threat_score || 0;
        let scoreB = window.liveNodeScores[b.id] || b.threat_score || 0;
        return scoreB - scoreA;
    });

    nodes.forEach((node, idx) => {
        // Prevent 0.0% "dead" nodes by injecting baseline network noise (2.0% - 5.9%)
        const realScore = window.liveNodeScores[node.id] || node.threat_score || 0.0;
        const detector = window.liveNodeDetectors[node.id] || '';
        const isLatency = detector === 'Sim:LATENCY';
        const isDeception = detector === 'Sim:DECEPTION';
        const isSimulator = isLatency || isDeception;
        const simColor = isLatency ? '#eab308' : '#a855f7';
        
        const baselineNoise = ((node.id * 17) % 40) / 1000 + 0.02;
        const displayScore = realScore === 0.0 ? baselineNoise : realScore;
        const scorePct = (displayScore * 100).toFixed(1);
        
        let status = "OPERATIONAL";
        let mainColor = '#00fbfb';
        let isThreat = false;
        
        if (isSimulator) {
            status = isLatency ? "STATUS_JITTER" : "DECEPTIVE_TRAFFIC";
            mainColor = simColor;
            isThreat = true;
        } else if (node.is_quarantined || realScore > window.globalThreshold) {
            status = "QUARANTINED";
            mainColor = '#ff3131';
            isThreat = true;
        } else if (node.is_infected || realScore > 0.3) {
            status = "INFECTED";
            mainColor = '#f97316';
            isThreat = true;
        }
        
        const scoreColor = isSimulator ? simColor : (realScore > 0.3 ? '#ff3131' : '#00fbfb');
        const reasonColor = isSimulator ? simColor : (isThreat ? '#ff3131' : '#00fbfb');
        
        const row = document.createElement('div');
        row.className = "grid grid-cols-5 text-[10px] font-mono px-4 py-3 border-b border-[#ff3131]/10 hover:bg-[#ff3131]/5 items-center transition-colors";
        
        row.innerHTML = `
            <div class="font-[900]" style="color: #00fbfb;">NODE_${node.id}</div>
            <div class="text-[9px]" style="color: #00fbfb; opacity: 0.8;">RT=${node.last_http_code === 200 ? Math.floor(Math.random()*(300-50)+50) : 0}ms</div>
            <div class="font-[900] tracking-widest uppercase" style="color: ${mainColor};">${status}</div>
            <div class="font-[900]" style="color: ${scoreColor};">${scorePct}%</div>
            <div class="truncate text-[9px] uppercase" style="color: ${reasonColor}; opacity: 0.6;">${node.quarantine_reason || (status !== 'OPERATIONAL' ? (isSimulator ? 'SIMULATOR_OVERRIDE_ACTIVE' : 'THREAT_THRESHOLD_EXCEEDED') : '---')}</div>
        `;
        listContainer.appendChild(row);
    });
    
    // Auto-scroll to track the top priority threats
    listContainer.scrollTop = 0;
}

// 3B. Tactical UI Update (Anvay & Tanmay Hub)
function updateTacticalUI() {
    if (!dashboardData || !dashboardData.metadata) return;
    
    const threatCount = dashboardData.metadata.active_threats || 0;
    const totalAnomalies = dashboardData.metadata.total_anomalies || 0;
    const criticalNodes = (dashboardData.heatmap || []).filter(h => h.risk_level === 'CRITICAL');
    
    // Update Header Threat Stats (Dashboard Sync)
    const headerThreats = document.getElementById('headerThreats');
    if (headerThreats) {
        headerThreats.dataset.val = totalAnomalies;
        
        const tooltip = document.querySelector('.threat-tooltip');
        if (tooltip) {
            tooltip.innerText = `${threatCount} Infected Nodes | ${criticalNodes.length} Latency Spikes`;
        }
    }

    // --- NEW P5 COMPONENT ---
    renderActiveHealthList();

    // --- ANVAY'S REGISTRY (P3) ---
    // Update the high-density CSS Node Monitor Grid
    updateHealthGrid();
}

// [TANMAY] Incident Attack Timeline Logic (Direct Stream)
function renderAttackTimeline(newLogs) {
    const container = document.getElementById('timelineContainer');
    if (!container) return;

    // Remove waiting placeholder
    if (container.innerHTML.includes('WAITING') || container.innerHTML.includes('WAITING_FOR_INCIDENT_DATA')) {
        container.innerHTML = '<div id="timelineWrapper" class="flex flex-col gap-3 p-2"></div>';
    }

    const wrapper = document.getElementById('timelineWrapper');
    if (!wrapper) return;

    newLogs.forEach(log => {
        const time = new Date(log.timestamp).toLocaleTimeString();
        const isSimulator = log.detector === 'ThreatSimulator';
        // Breach visually detected at a hardcoded 30% to highlight developing anomalies regardless of quarantine limit
        const isThreat = log.threat_score >= 0.30;
        
        let severityColor = '#00FBFB'; // Cyan
        let label = "HEARTBEAT_PULSE_OK";
        
        if (isSimulator) {
            severityColor = '#a855f7'; // Purple
            label = "SIMULATOR_OVERRIDE_ACTIVE";
        } else if (isThreat) {
            severityColor = '#ff3131'; // Red
            label = "BREACH_SIGNATURE_DETECTED";
        }
        const scorePct = (log.threat_score * 100).toFixed(1);
        
        const entry = document.createElement('div');
        entry.className = `border-l-2 pl-4 py-2 relative animate-slide-in mb-2`;
        entry.style.borderLeftColor = severityColor;
        entry.style.backgroundColor = `${severityColor}0D`; // 5% opacity hex
        
        entry.innerHTML = `
            <div class="absolute -left-[5px] top-4 w-[8px] h-[8px] rounded-full" style="background-color: ${severityColor}; box-shadow: 0 0 8px ${severityColor};"></div>
            <div class="flex justify-between items-start">
                <div class="flex flex-col gap-1">
                    <span class="text-[10px] font-black uppercase tracking-tighter" style="color: ${severityColor};">[${time}] ${label}</span>
                    <div class="text-[11px] text-white font-mono uppercase">
                        Packet: <span class="px-1 border" style="background-color: ${severityColor}33; border-color: ${severityColor}4D; color: ${severityColor};">HTTP ${log.http_code}</span> | 
                        ${log.message.split(' | ')[1]}
                    </div>
                </div>
                <div class="flex flex-col items-end gap-2">
                    <div class="px-2 py-1 border bg-black font-black text-[11px]" style="border-color: ${severityColor}; color: ${severityColor}; box-shadow: 0 0 10px ${severityColor}4D;">
                        NODE_${log.node_id}
                    </div>
                    <div class="text-[9px] font-mono" style="color: ${severityColor}CC;">
                        THREAT_LVL: <span class="text-white">${scorePct}%</span>
                    </div>
                </div>
            </div>
            <div class="mt-2 w-full h-[1px]" style="background: linear-gradient(90deg, ${severityColor}66, transparent);"></div>
        `;
        wrapper.appendChild(entry); // Add to bottom stack
    });
    
    container.scrollTop = container.scrollHeight;
    
    // Cleanup if too many (oldest at top now)
    while(wrapper.children.length > 50) {
        wrapper.removeChild(wrapper.firstChild);
    }
}

// [TANMAY] Response Simulator Hub Logic
const slider = document.getElementById('thresholdSlider');
const display = document.getElementById('thresholdVal');

async function fetchSettings() {
    try {
        const token = localStorage.getItem('access_token');
        const res = await fetch(`${API_BASE}/settings/quarantine_threshold`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (res.ok) {
            const setting = await res.json();
            window.globalThreshold = parseFloat(setting.value);
            if (slider) slider.value = window.globalThreshold * 100;
            if (display) display.innerText = Math.round(window.globalThreshold * 100) + "%";
            console.log(`[MISSION_CONTROL] Synced global threshold: ${window.globalThreshold}`);
        }
    } catch (e) { console.error("Settings sync failed", e); }
}

async function updateBackendThreshold(val) {
    try {
        const token = localStorage.getItem('access_token');
        await fetch(`${API_BASE}/settings/quarantine_threshold`, {
            method: 'PATCH',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}` 
            },
            body: JSON.stringify({ value: (val / 100).toString() })
        });
        window.globalThreshold = val / 100;
        console.log(`[MISSION_CONTROL] Threshold broadcasted: ${val}%`);
    } catch (e) { console.error("Threshold broadcast failed", e); }
}

if(slider && display) {
    slider.oninput = function() {
        display.innerText = this.value + "%";
        // Update local state instantly for UI highlights
        window.globalThreshold = this.value / 100;
        
        // Wipe local telemetry radar cache immediately
        window.liveNodeScores = {};
        window.liveNodeDetectors = {};
        
        // Force-clear the node health monitor cache to 'OPERATIONAL' baseline
        if (dashboardData && dashboardData.nodes) {
            dashboardData.nodes.forEach(n => {
                n.is_infected = false;
                n.is_quarantined = false;
                n.threat_score = 0.0;
            });
            updateHealthGrid();
            renderActiveHealthList();
        }
    };
    slider.onchange = function() {
        updateBackendThreshold(this.value);
    };
}

// Real Threat Injection Trigger (Continuous Random Target Engine)
window.toggleSimulator = function(type) {
    window.activeSimulators[type] = !window.activeSimulators[type];
    
    const themeColor = type === 'LATENCY' ? '#eab308' : '#a855f7';
    const btn = document.getElementById(`btn-${type}`);
    
    if(btn) {
        if(window.activeSimulators[type]) {
            btn.style.backgroundColor = `${themeColor}33`; // 20% opacity
            btn.style.color = '#fff';
            flashNotification(`[SYSTEM_ENGAGED] Simulator active: ${type}. Striking random nodes.`);
        } else {
            btn.style.backgroundColor = 'transparent';
            btn.style.color = themeColor;
            
            // Revert changes caused by this specific simulator immediately
            const targetTag = `Sim:${type}`;
            Object.keys(window.liveNodeDetectors).forEach(nodeId => {
                if (window.liveNodeDetectors[nodeId] === targetTag) {
                    delete window.liveNodeDetectors[nodeId];
                    delete window.liveNodeScores[nodeId];
                }
            });
            updateHealthGrid();
            renderActiveHealthList();
            
            flashNotification(`[SYSTEM_HALTED] Simulator deactivated: ${type}. Network returning to baseline.`);
        }
    }
}

// Background Task: Fire random bullets from active simulators
setInterval(async () => {
    const activeTypes = Object.keys(window.activeSimulators).filter(t => window.activeSimulators[t]);
    if (activeTypes.length === 0) return;
    
    const intensity = parseFloat(slider ? slider.value : 50) / 100;
    const token = localStorage.getItem('access_token');
    
    // For each active threat, launch a random strike
    for (const type of activeTypes) {
        const randomTargetId = Math.floor(Math.random() * 500) + 1;
        
        try {
            await fetch(`${API_BASE}/simulator/inject-threat`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({
                    node_id: randomTargetId,
                    threat_type: type.toUpperCase(),
                    intensity: intensity
                })
            });
        } catch (error) { }
    }
}, 1500);

// Master Override Protocol: Engage Full System Lockdown
window.engageFullQuarantine = async function() {
    const slider = document.getElementById('thresholdSlider');
    const display = document.getElementById('thresholdVal');
    
    if (slider && display) {
        // 1. Instant UI Lock
        slider.value = 0;
        display.innerText = "0%";
        window.globalThreshold = 0;
        
        // 2. Wipe client-side radar memory
        window.liveNodeScores = {};
        window.liveNodeDetectors = {};
        if (dashboardData && dashboardData.nodes) {
            dashboardData.nodes.forEach(n => {
                n.is_infected = false; 
                n.is_quarantined = false;
                n.threat_score = 0.0;
            });
            updateHealthGrid();
            renderActiveHealthList();
        }
        
        // 3. Broadcast lockdown to backend (Background)
        updateBackendThreshold(0);
        
        console.log("[LOCKDOWN] AEGIS_CORE: Full Quarantine Protocol Engaged at 0% Threshold.");
        flashNotification("[CRITICAL] PROTOCOL_ZERO_ENGAGED: GLOBAL LOCKDOWN ACTIVE.");
    }
}

function flashNotification(msg) {
    const log = document.getElementById('quarantineLog');
    if(log) {
        if (log.innerHTML.includes('INITIALIZING')) log.innerHTML = '';
        const entry = document.createElement('div');
        entry.className = 'mb-1 border-b border-[#00fbfb]/20 pb-1 italic px-2 animate-pulse';
        entry.style.color = '#00fbfb';
        entry.style.opacity = '1';
        entry.innerHTML = `[SYSTEM_INFO] ${msg}`;
        log.appendChild(entry);
        log.scrollTop = log.scrollHeight;
    }
}

// [ANVAY] Quarantine Log Logic (P3 - Direct Stream)
function renderQuarantineLog(newLogs) {
    const log = document.getElementById('quarantineLog');
    if (!log) return;
    
    // Clear initial state
    if (log.innerHTML.includes('INITIALIZING')) log.innerHTML = '';

    // Identify high-criticality threats (linked to REALTIME slider threshold)
    const threatLogs = newLogs.filter(l => l.threat_score >= window.globalThreshold);

    threatLogs.forEach(entryData => {
        const id = `q-log-${entryData.id}`;
        if (document.getElementById(id)) return;

        const isSimulator = entryData.detector.startsWith('Sim:');
        
        let themeColor = '#ff3131'; 
        let logLabel = "UNKNOWN";
        if (entryData.detector === 'Sim:LATENCY') {
             themeColor = '#eab308';
             logLabel = "SIM: LATENCY_JITTER";
        } else if (entryData.detector === 'Sim:DECEPTION') {
             themeColor = '#a855f7';
             logLabel = "SIM: DECEPTIVE_LOGS";
        }
        
        const time = new Date(entryData.timestamp).toLocaleTimeString();
        const scorePct = (entryData.threat_score * 100).toFixed(1);
        
        const entry = document.createElement('div');
        entry.id = id;
        entry.className = `mb-2 border-l-2 pl-3 py-2 relative opacity-100`;
        entry.style.borderLeftColor = themeColor;
        entry.style.backgroundColor = `${themeColor}1A`; // 10% opacity
        
        const msgParts = entryData.message.split(' | ');
        const displayMsg = msgParts.length > 1 ? msgParts[1] : entryData.message;

        entry.innerHTML = `
            <div class="flex justify-between items-start mb-1">
                <div class="text-[9px] uppercase font-bold tracking-tighter" style="color: ${themeColor}; opacity: 0.9;">[${time}] LOCKOUT_ENGAGED</div>
                <div class="text-[10px] text-black px-1 font-black" style="background-color: ${themeColor};">THREAT: ${scorePct}%</div>
            </div>
            <div class="font-[900] text-white text-[11px] uppercase tracking-tighter">NODE_${entryData.node_id}: QUARANTINE_ACTIVE</div>
            <div class="text-[10px] mt-1 font-mono leading-none" style="color: ${themeColor};">
                ${isSimulator ? logLabel : 'THE_SWORD'}: ${displayMsg}
            </div>
        `;
        log.appendChild(entry);
    });

    log.scrollTop = log.scrollHeight;

    // Cleanup if too many
    while(log.children.length > 30) {
        log.removeChild(log.firstChild);
    }
}

// --- ANVAY'S REGISTRY (P3) ---
// High-Density Node Status Grid Update Loop (500 Nodes Max)
function updateHealthGrid() {
    if (!dashboardData || !dashboardData.nodes) return;
    
    dashboardData.nodes.forEach(node => {
        const box = document.getElementById(`node-box-${node.id}`);
        if (!box) return;

        // Real-Time Pulse Override Calculation
        const liveScore = window.liveNodeScores[node.id] || 0.0;
        const detector = window.liveNodeDetectors[node.id] || '';
        const isLatency = detector === 'Sim:LATENCY';
        const isDeception = detector === 'Sim:DECEPTION';
        const isSimulator = isLatency || isDeception;
        
        let isRed = node.is_quarantined || liveScore > window.globalThreshold;
        let isOrange = node.is_infected || (liveScore > 0.3 && liveScore <= window.globalThreshold);

        // Apply grid colors based on dynamic severity tier
        if (isLatency) {
            box.className = 'w-full h-full bg-[#eab308] flex items-center justify-center text-[10px] font-[900] text-black/90 overflow-hidden cursor-crosshair transition-colors duration-200';
        } else if (isDeception) {
            box.className = 'w-full h-full bg-[#a855f7] flex items-center justify-center text-[10px] font-[900] text-black/90 overflow-hidden cursor-crosshair transition-colors duration-200';
        } else if (isRed) {
            box.className = 'w-full h-full bg-[#991b1b] flex items-center justify-center text-[10px] font-[900] text-black/70 overflow-hidden cursor-crosshair transition-colors duration-200';
        } else if (isOrange) {
            box.className = 'w-full h-full bg-[#f97316] flex items-center justify-center text-[10px] font-[900] text-black/70 overflow-hidden cursor-crosshair transition-colors duration-200';
        } else {
            box.className = 'w-full h-full bg-[#00FBFB] flex items-center justify-center text-[10px] font-[900] text-black/50 overflow-hidden cursor-crosshair transition-colors duration-200';
        }

        // Keep the simulator targeting active if they click a box
        box.onclick = () => {
            window.selectedNodeId = node.id;
            console.log(`TARGET_LOCKED: Node_${node.id} active in simulator.`);
            
            // Optional: Visually highlight the targeted node in the grid
            document.querySelectorAll('#healthGrid > div').forEach(b => {
                b.classList.remove('border-2', 'border-white', 'z-10');
            });
            box.classList.add('border-2', 'border-white', 'z-10');
        };
    });
}

window.addEventListener('DOMContentLoaded', () => {
    initHealthGrid();
    fetchSettings();
    fetchAutonomousData();
    // Re-sync aggregator logic (metadata, nodes) slowly
    setInterval(fetchAutonomousData, 3000);
    // Poll the fast real-time stream independently
    setInterval(streamLiveTelemetry, 1000);
});
