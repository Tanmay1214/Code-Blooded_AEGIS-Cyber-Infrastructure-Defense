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

// 1. Graphical Grid Initialization (Replaces Map Tracking)
function initHealthGrid() {
    const grid = document.getElementById('healthGrid');
    if (!grid) return;
    
    grid.innerHTML = '';
    // Construct exactly 500 nodes (25x20)
    for (let i = 1; i <= 500; i++) {
        const box = document.createElement('div');
        box.id = `node-box-${i}`;
        // Default initialized to OPERATIONAL (Cyan)
        box.className = 'w-full h-full bg-[#00FBFB] flex items-center justify-center text-[9px] font-black text-black/40 overflow-hidden';
        box.innerText = i;
        grid.appendChild(box);
    }
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

// 3B. Tactical UI Update (Anvay & Tanmay Hub)
function updateTacticalUI() {
    if (!dashboardData) return;
    
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
        
        // Force-clear the node health monitor cache to 'OPERATIONAL' baseline
        if (dashboardData && dashboardData.nodes) {
            dashboardData.nodes.forEach(n => {
                n.is_infected = false;
                n.is_quarantined = false;
            });
            updateHealthGrid();
        }
    };
    slider.onchange = function() {
        updateBackendThreshold(this.value);
    };
}

// Real Threat Injection via Team API
window.injectMockStress = async function(type) {
    // Determine target node (selected or random)
    const targetNodeId = window.selectedNodeId || (dashboardData.nodes ? dashboardData.nodes[0].id : 1);
    const intensity = parseFloat(slider ? slider.value : 50) / 100;

    console.log(`[TANMAY_MISSION] INJECTING_${type} INTO NODE_${targetNodeId} (Intensity: ${slider ? slider.value : 50}%)`);

    try {
        const token = localStorage.getItem('access_token');
        const response = await fetch(`${API_BASE}/simulator/inject-threat`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                node_id: targetNodeId,
                threat_type: type.toUpperCase(),
                intensity: intensity
            })
        });

        if (response.ok) {
            const result = await response.json();
            flashNotification(`[SUCCESS] ${type} INJECTED: Signal verified by AEGIS Core.`);
        } else {
            flashNotification(`[ERROR] Injection Intercepted by Backend Security.`);
        }
    } catch (error) {
        console.error("Injection Error:", error);
        flashNotification(`[CRITICAL] Backend Link Severed.`);
    }
}

function flashNotification(msg) {
    const log = document.getElementById('quarantineLog');
    if(log) {
        const entry = document.createElement('div');
        entry.className = 'mb-1 text-cyan-400 border-b border-cyan-400/10 pb-1 animate-pulse italic';
        entry.innerHTML = `[MISSION_CONTROL] ${msg}`;
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

        const isSimulator = entryData.detector === 'ThreatSimulator';
        const themeColor = isSimulator ? '#a855f7' : '#ff3131';
        const time = new Date(entryData.timestamp).toLocaleTimeString();
        const scorePct = (entryData.threat_score * 100).toFixed(1);
        
        const entry = document.createElement('div');
        entry.id = id;
        entry.className = `mb-2 border-l-2 pl-3 py-2 animate-slide-in relative`;
        entry.style.borderLeftColor = themeColor;
        entry.style.backgroundColor = `${themeColor}0D`; // 5% opacity hex
        
        entry.innerHTML = `
            <div class="flex justify-between items-start mb-1">
                <div class="text-[9px] uppercase opacity-70 tracking-tighter" style="color: ${themeColor};">[${time}] AUTONOMOUS_LOCKOUT_ENGAGED</div>
                <div class="text-[10px] text-black px-1 font-black" style="background-color: ${themeColor};">THREAT: ${scorePct}%</div>
            </div>
            <div class="font-black text-white text-[11px]">NODE_${entryData.node_id}: QUARANTINE_ACTIVE</div>
            <div class="text-[10px] mt-1 font-mono" style="color: ${themeColor}E6;">
                ${isSimulator ? 'SIMULATOR' : 'THE_SWORD'}: Threat intercepted. ${entryData.message.split(' | ')[1]}
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
        let isRed = node.is_quarantined || liveScore > window.globalThreshold;
        let isOrange = node.is_infected || (liveScore > 0.3 && liveScore <= window.globalThreshold);

        // Apply grid colors based on dynamic severity tier
        if (isRed) {
            box.className = 'w-full h-full bg-[#991b1b] flex items-center justify-center text-[9px] font-black text-black/50 overflow-hidden cursor-crosshair';
        } else if (isOrange) {
            box.className = 'w-full h-full bg-[#f97316] flex items-center justify-center text-[9px] font-black text-black/50 overflow-hidden cursor-crosshair';
        } else {
            box.className = 'w-full h-full bg-[#00FBFB] flex items-center justify-center text-[9px] font-black text-black/40 overflow-hidden cursor-crosshair';
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
