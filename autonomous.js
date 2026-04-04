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

// 1. Tactical Map Initialization
function initTacticalMap() {
    const jaipurBounds = L.latLngBounds([26.70, 75.60], [27.10, 75.95]);
    
    map = L.map('map', {
        zoomControl: true,
        maxBounds: jaipurBounds,
        maxBoundsViscosity: 1.0,
        minZoom: 11
    }).setView([26.9124, 75.7873], 12);

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; CARTO',
        subdomains: 'abcd',
        maxZoom: 20
    }).addTo(map);

    setTimeout(() => { if(map) map.invalidateSize(); }, 500);
}

// 2. Autonomous Data Ingestion
async function fetchAutonomousData() {
    try {
        const token = localStorage.getItem('access_token');
        const response = await fetch(`${API_BASE}/dashboard-aggregator${isFirstLoad ? '?full=true' : ''}`, {
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

// 3. Tactical UI Update (Anvay & Tanmay Hub)
function updateTacticalUI() {
    if (!dashboardData) return;

    // --- ANVAY'S REGISTRY (P3) ---
    drawTacticalNodes();
    renderQuarantineLog();
    
    // --- TANMAY'S REGISTRY (P4) ---
    renderAttackTimeline();
}

// [TANMAY] Incident Attack Timeline Logic
function renderAttackTimeline() {
    const container = document.getElementById('timelineContainer');
    if (!container || !dashboardData.anomalies) return;

    // Clear placeholder
    if (container.innerHTML.includes('WAITING')) container.innerHTML = '';

    const timelineData = dashboardData.anomalies.slice(0, 10); // Last 10 anomalies
    
    let timelineHTML = '<div class="flex flex-col gap-3 p-2">';
    timelineData.forEach((event, index) => {
        const time = new Date().toLocaleTimeString();
        const severityColor = event.anomaly_score > 0.8 ? '#ff3131' : '#ff9d00';
        
        timelineHTML += `
            <div class="border-l-2 border-[${severityColor}] pl-4 py-1 relative animate-slide-in">
                <div class="absolute -left-[5px] top-2 w-[8px] h-[8px] rounded-full bg-[${severityColor}]"></div>
                <div class="flex justify-between items-center">
                    <span class="text-[10px] text-[${severityColor}] font-black">[${time}] BREACH_DETECTED</span>
                    <span class="text-[9px] text-white/50">NODE_${event.node_id}</span>
                </div>
                <div class="text-[11px] text-white font-mono mt-1 uppercase">
                    Anomaly_Score: <span class="bg-[${severityColor}]/20 px-1">${event.anomaly_score.toFixed(4)}</span> | 
                    Vector: IsolationForest
                </div>
            </div>
        `;
    });
    timelineHTML += '</div>';
    container.innerHTML = timelineHTML;
}

// [TANMAY] Response Simulator Hub Logic
const slider = document.getElementById('thresholdSlider');
const display = document.getElementById('thresholdVal');

if(slider && display) {
    slider.oninput = function() {
        display.innerText = this.value + "%";
        // This value will eventually be sent to /api/simulator/threshold
        console.log(`[TANMAY_MISSION] MISSION_THRESHOLD updated to: ${this.value}%`);
    }
}

// Simulated Threat Injection (For Tanmay to test UI reactivity)
window.injectMockStress = function(type) {
    const timestamp = new Date().toLocaleTimeString();
    
    // 1. Ensure dashboardData is initialized (Crucial for fresh Docker start)
    if (!dashboardData) {
        dashboardData = { anomalies: [], nodes: [], metadata: {}, schema_engine: {} };
        console.warn("[TANMAY_MISSION] Initializing local dashboardData for Mock Ingestion...");
    }
    if (!dashboardData.anomalies) dashboardData.anomalies = [];

    // 2. Log to Quarantine Feed
    const log = document.getElementById('quarantineLog');
    if(log) {
        const entry = document.createElement('div');
        entry.className = 'mb-1 text-[#ff3131] border-b border-[#ff3131]/10 pb-1 animate-pulse';
        entry.innerHTML = `[${timestamp}] ! STRESS_INJECTION: ${type} signature detected. Sector_Alpha_02 isolated.`;
        log.prepend(entry);
    }

    // 3. Inject into Timeline Data Array (P4 Support)
    const mockAnomaly = {
        node_id: Math.floor(Math.random() * 500) + 1,
        anomaly_score: 0.95 + (Math.random() * 0.05), // High severity
        log_id: Date.now()
    };
    dashboardData.anomalies.unshift(mockAnomaly);
    
    // 4. Force immediate UI updates
    renderAttackTimeline(); 
    renderQuarantineLog();
    
    console.log(`[TANMAY_MISSION] Mock ${type} pulse successfully injected into Attack Timeline.`);
}

// [ANVAY] Quarantine Log Logic (P3)
function renderQuarantineLog() {
    const log = document.getElementById('quarantineLog');
    if (!log || !dashboardData.anomalies) return;

    // Filter high-severity as "Quarantined"
    const quarantined = dashboardData.anomalies.filter(a => a.anomaly_score > 0.9);
    
    if (quarantined.length > 0 && log.innerHTML.includes('INITIALIZING')) {
        log.innerHTML = '';
    }

    quarantined.slice(0, 15).forEach(q => {
        const id = `q-log-${q.log_id}`;
        if (document.getElementById(id)) return;

        const entry = document.createElement('div');
        entry.id = id;
        entry.className = 'mb-2 border-l-2 border-[#ff3131] pl-3 py-1 bg-[#ff3131]/5';
        entry.innerHTML = `
            <div class="text-[9px] text-[#ff3131] uppercase opacity-70">${new Date().toISOString()}</div>
            <div class="font-black text-white">NODE_${q.node_id}: QUARANTINE_ENGAGED</div>
            <div class="text-[10px] text-[#ff3131]">CRITICAL_THRESHOLD: ${q.anomaly_score.toFixed(4)} BREACHED</div>
        `;
        log.prepend(entry);
    });
}

// --- ANVAY'S REGISTRY (P3) ---
function drawTacticalNodes() {
    if (!dashboardData || !dashboardData.nodes || !map) return;

    dashboardData.nodes.forEach(node => {
        const lng = 75.60 + (node.pos.x / 100) * 0.35; 
        const lat = 26.78 + (node.pos.y / 100) * 0.25;
        
        if (nodeMarkers[node.id]) {
            const marker = nodeMarkers[node.id];
            marker.setLatLng([lat, lng]);
            const el = marker.getElement()?.querySelector('.node-pulsar');
            if (el) {
                if (node.is_infected) el.className = 'node-pulsar infected-red';
                else el.className = 'node-pulsar operational-red';
            }
        } else {
            const redIcon = L.divIcon({
                className: 'custom-div-icon',
                html: `<div class="node-pulsar ${node.is_infected ? 'infected-red' : 'operational-red'}"></div>`,
                iconSize: [6, 6],
                iconAnchor: [3, 3]
            });

            const marker = L.marker([lat, lng], { icon: redIcon }).addTo(map);
            marker.bindPopup(`
                <div style="background: #000; color: #ff3131; border: 1px solid #ff3131; padding: 5px; font-family: monospace; font-size: 10px;">
                    <strong>NODE_${node.id}</strong><br/>
                    THREAT_SCORE: <span style="font-weight: 800;">${Math.floor(Math.random() * 100)}%</span><br/>
                    STATUS: ${node.is_infected ? 'CRITICAL_ISOLATION' : 'MONITORING'}
                </div>
            `, { closeButton: false, offset: [0, -5] });

            nodeMarkers[node.id] = marker;
        }
    });
}
window.addEventListener('DOMContentLoaded', () => {
    initTacticalMap();
    fetchAutonomousData();
    setInterval(fetchAutonomousData, 3000);
});
