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
        
        // Also fetch official anomalies for Tanmay's timeline
        await fetchAnomalies();
        
        updateTacticalUI();
    } catch (error) {
        console.error("Autonomous Sync Error:", error);
    }
}

async function fetchAnomalies() {
    try {
        const token = localStorage.getItem('access_token');
        const response = await fetch(`${API_BASE}/anomalies?limit=25`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await response.json();
        anomalies = data.anomalies || [];
    } catch (error) {
        console.error("Anomaly Sync Error:", error);
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
    if (!container) return;

    if (anomalies.length === 0) {
        if (!container.innerHTML.includes('WAITING')) {
            container.innerHTML = '<div class="text-[#ff3131] opacity-50 p-4 text-center animate-pulse">[ WAITING_FOR_BREACH_SIGNALS ]</div>';
        }
        return;
    }

    const timelineData = anomalies.slice(0, 10); // Last 10 anomalies
    
    let timelineHTML = '<div class="flex flex-col gap-3 p-2">';
    timelineData.forEach((event) => {
        const time = new Date(event.detected_at).toLocaleTimeString();
        const severityColor = event.anomaly_score > 0.8 ? '#ff3131' : '#ff9d00';
        
        timelineHTML += `
            <div class="border-l-2 border-[${severityColor}] pl-4 py-1 relative animate-slide-in">
                <div class="absolute -left-[5px] top-2 w-[8px] h-[8px] rounded-full bg-[${severityColor}]"></div>
                <div class="flex justify-between items-center">
                    <span class="text-[10px] text-[${severityColor}] font-black">[${time}] BREACH_DETECTED</span>
                    <span class="text-[9px] text-white/50">NODE_${event.node_id}</span>
                </div>
                <div class="text-[11px] text-white font-mono mt-1 uppercase">
                    Score: <span class="bg-[${severityColor}]/20 px-1">${event.anomaly_score.toFixed(4)}</span> | 
                    Vector: ${event.detector}
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
        console.log(`[TANMAY_MISSION] MISSION_THRESHOLD updated to: ${this.value}%`);
    }
}

// Real Threat Injection via Team API
window.injectMockStress = async function(type) {
    // Determine target node (selected or random)
    const targetNodeId = window.selectedNodeId || (dashboardData.nodes ? dashboardData.nodes[0].id : 1);
    const intensity = parseFloat(slider ? slider.value : 90) / 100;

    console.log(`[TANMAY_MISSION] INJECTING_${type} INTO NODE_${targetNodeId} (Intensity: ${intensity})`);

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
            // Refresh anomalies immediately to show feedback
            await fetchAnomalies();
            renderAttackTimeline();
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
        log.prepend(entry);
    }
}

// [ANVAY] Quarantine Log Logic (P3)
function renderQuarantineLog() {
    const log = document.getElementById('quarantineLog');
    if (!log || !dashboardData) return;
    
    // Clear initial state
    if (log.innerHTML.includes('INITIALIZING')) log.innerHTML = '';

    // Identify quarantined nodes from the aggregate
    const quarantinedNodes = dashboardData.nodes ? dashboardData.nodes.filter(n => n.is_quarantined) : [];

    quarantinedNodes.slice(0, 10).forEach(node => {
        const id = `q-node-${node.id}`;
        if (document.getElementById(id)) return;

        const entry = document.createElement('div');
        entry.id = id;
        entry.className = 'mb-2 border-l-2 border-[#ff3131] pl-3 py-1 bg-[#ff3131]/5';
        entry.innerHTML = `
            <div class="text-[9px] text-[#ff3131] uppercase opacity-70">AUTONOMOUS_LOCKOUT_ENGAGED</div>
            <div class="font-black text-white">NODE_${node.id}: QUARANTINE_ACTIVE</div>
            <div class="text-[10px] text-[#ff3131]">THE_SWORD: Sector isolated indefinitely.</div>
        `;
        log.prepend(entry);
    });
}

// --- ANVAY'S REGISTRY (P3) ---
function drawTacticalNodes() {
    if (!dashboardData || !dashboardData.nodes || !map) return;

    dashboardData.nodes.forEach(node => {
        // Random distribution if actual coords missing (Hackathon style)
        const lng = 75.60 + ((node.id % 20) / 20) * 0.35; 
        const lat = 26.78 + ((node.id % 15) / 15) * 0.25;
        
        if (nodeMarkers[node.id]) {
            const marker = nodeMarkers[node.id];
            const el = marker.getElement()?.querySelector('.node-pulsar');
            if (el) {
                if (node.is_quarantined) el.className = 'node-pulsar infected-red';
                else el.className = 'node-pulsar operational-red';
            }
        } else {
            const redIcon = L.divIcon({
                className: 'custom-div-icon',
                html: `<div class="node-pulsar ${node.is_quarantined ? 'infected-red' : 'operational-red'}"></div>`,
                iconSize: [6, 6],
                iconAnchor: [3, 3]
            });

            const marker = L.marker([lat, lng], { icon: redIcon }).addTo(map);
            marker.on('click', () => {
                window.selectedNodeId = node.id;
                flashNotification(`TARGET_LOCKED: Node_${node.id} active in simulator.`);
            });
            
            marker.bindPopup(`
                <div style="background: #000; color: #ff3131; border: 1px solid #ff3131; padding: 5px; font-family: monospace; font-size: 10px;">
                    <strong>NODE_${node.id}</strong><br/>
                    STATUS: ${node.is_quarantined ? 'ISOLATED' : 'MONITORING'}<br/>
                    <small>Click to Target Simulator</small>
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
