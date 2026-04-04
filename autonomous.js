// AEGIS Autonomous Response Logic (Team Anvay & Tanmay)

const API_BASE = (
    window.location.hostname === 'localhost' ||
    window.location.hostname === '127.0.0.1'
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

    // Draw Red-Alert Nodes (Anvay)
    drawTacticalNodes();
    
    // Update Quarantine Log (Anvay) - Placeholder
    // Update Attack Timeline (Tanmay) - Placeholder
}

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
                // In Autonomous mode, all infected nodes pulse RED
                if (node.is_infected) el.classList.add('infected-red');
                else el.classList.remove('infected-red');
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

// 4. Simulator Interaction (Tanmay)
const slider = document.getElementById('thresholdSlider');
const display = document.getElementById('thresholdVal');

if(slider && display) {
    slider.oninput = function() {
        display.innerText = this.value + "%";
        console.log(`[SIMULATOR] Updating Isolation Threshold: ${this.value}%`);
    }
}

// Initialization
window.addEventListener('DOMContentLoaded', () => {
    initTacticalMap();
    fetchAutonomousData();
    setInterval(fetchAutonomousData, 3000);
});
