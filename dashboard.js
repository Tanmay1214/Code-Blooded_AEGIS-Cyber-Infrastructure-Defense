// AEGIS Dashboard Configuration & Logic

// 1. Tailwind Configuration
if (typeof tailwind !== 'undefined') {
    tailwind.config = {
        darkMode: "class",
        theme: {
            extend: {
                colors: {
                    "secondary": "#ffb778",
                    "surface-bright": "#3a3939",
                    "primary-container": "#00fbfb",
                    "surface-dim": "#131313",
                    "error": "#ffb4ab",
                    "on-secondary-fixed-variant": "#6c3a00",
                    "on-error-container": "#ffdad6",
                    "on-primary-fixed": "#002020",
                    "on-primary-fixed-variant": "#004f4f",
                    "secondary-container": "#fd9000",
                    "secondary-fixed": "#ffdcc1",
                    "surface-variant": "#353534",
                    "on-surface-variant": "#b9cac9",
                    "on-secondary-container": "#613400",
                    "tertiary-container": "#ffdad8",
                    "surface-container-lowest": "#0e0e0e",
                    "tertiary-fixed-dim": "#ffb3b2",
                    "on-background": "#e5e2e1",
                    "on-tertiary-fixed-variant": "#92001e",
                    "surface-container": "#201f1f",
                    "outline": "#839493",
                    "tertiary-fixed": "#ffdad8",
                    "on-surface": "#e5e2e1",
                    "surface-container-highest": "#353534",
                    "on-tertiary-fixed": "#410008",
                    "on-primary-container": "#007070",
                    "surface-container-low": "#1c1b1b",
                    "on-tertiary-container": "#ca002d",
                    "surface": "#131313",
                    "on-error": "#690005",
                    "error-container": "#93000a",
                    "surface-tint": "#00dddd",
                    "primary-fixed": "#00fbfb",
                    "on-tertiary": "#680012",
                    "inverse-on-surface": "#313030",
                    "on-primary": "#003737",
                    "primary": "#ffffff",
                    "surface-container-high": "#2a2a2a",
                    "tertiary": "#ffffff",
                    "on-secondary": "#4c2700",
                    "primary-fixed-dim": "#00dddd",
                    "inverse-primary": "#006a6a",
                    "background": "#131313",
                    "secondary-fixed-dim": "#ffb778",
                    "outline-variant": "#3a4a49",
                    "on-secondary-fixed": "#2e1500",
                    "inverse-surface": "#e5e2e1"
                },
                fontFamily: {
                    "headline": ["Space Grotesk"],
                    "body": ["Space Grotesk"],
                    "label": ["Space Grotesk"]
                },
                borderRadius: { "DEFAULT": "0.25rem", "lg": "0.5rem", "xl": "0.75rem", "full": "9999px" },
            },
        },
    };
}

// 2. Core State & Fetching
const API_BASE = (
    window.location.hostname === 'localhost' ||
    window.location.hostname === '127.0.0.1' ||
    window.location.hostname === ''
)
    ? "http://127.0.0.1:8000/api" 
    : "https://aegis-api-65i8.onrender.com/api"; 
let dashboardData = null;
let visibleNodeLimit = 50;

// Telemetry Smoothing State
let lastKnownLogs = 0;
let localLogOffset = 0;
let activeSchemaVersion = 1;
let isSimulatedRotation = false;
let lastProcessedLogId = 0;

// Differential Sync Cache
let nodeMetadataCache = {};
let isFirstLoad = true;
let lastAnomalyNodeIds = new Set();

async function fetchDashboardData() {
    try {
        const url = `${API_BASE}/dashboard-aggregator${isFirstLoad ? '?full=true' : ''}`;
        const token = localStorage.getItem('access_token');
        const response = await fetch(url, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.status === 401) {
            localStorage.removeItem('access_token');
            window.location.href = 'login.html';
            return;
        }

        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }

        const data = await response.json();

        if (isFirstLoad) {
            dashboardData = data;
            data.nodes.forEach(node => {
                nodeMetadataCache[node.id] = {
                    pos: node.pos,
                    decoded_serial: node.decoded_serial,
                    encoded_ua: node.encoded_ua
                };
            });
            isFirstLoad = false;
            activeSchemaVersion = data.schema_engine.current_version;
        }

        // 1. Check for Version Shift FIRST
        if (data.schema_engine.current_version !== activeSchemaVersion) {
            triggerSchemaRotation(data.schema_engine.current_version);
        }

        // 2. Diff Sync Nodes (Only update status for existing nodes)
        if (data.nodes && data.nodes.length > 0) {
            const newAnomalyIds = new Set();
            data.nodes.forEach(incomingNode => {
                if (incomingNode.is_infected) newAnomalyIds.add(incomingNode.id);
                let existing = dashboardData.nodes.find(n => n.id === incomingNode.id);
                if (existing) {
                    existing.is_infected = incomingNode.is_infected;
                    existing.last_http_code = incomingNode.last_http_code;
                    existing.reported_json = incomingNode.reported_json;
                }
            });
            lastAnomalyNodeIds = newAnomalyIds;
        }

        // 3. Update Global Meta
        dashboardData.metadata = data.metadata;
        dashboardData.schema_engine = data.schema_engine;
        dashboardData.heatmap = data.heatmap;
        dashboardData.terminal_logs = data.terminal_logs;

        if (dashboardData.metadata.total_logs_processed > lastKnownLogs) {
            lastKnownLogs = dashboardData.metadata.total_logs_processed;
            localLogOffset = 0;
        }

        updateUI();
    } catch (error) {
        console.error("Dashboard Sync Error:", error);
    }
}

// ─────────────────────────────────────────────────────────────
// 3. Map & Node Visualizer (Leaflet Geographic Sync)
// ─────────────────────────────────────────────────────────────
let map;
let nodeMarkers = {};

function initMap() {
    const jaipurBounds = L.latLngBounds([26.70, 75.60], [27.10, 75.95]);
    
    map = L.map('map', {
        zoomControl: true,
        dragging: true,
        scrollWheelZoom: true,
        doubleClickZoom: true,
        boxZoom: true,
        touchZoom: true,
        keyboard: true,
        maxBounds: jaipurBounds,
        maxBoundsViscosity: 1.0,
        minZoom: 11,
        attributionControl: true
    }).setView([26.9124, 75.7873], 12);

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 20
    }).addTo(map);

    setTimeout(() => { if(map) map.invalidateSize(); }, 500);

    map.on('mousemove', function(e) {
        const mouseLat = document.getElementById('mouseLat');
        const mouseLon = document.getElementById('mouseLon');
        const mouseSector = document.getElementById('mouseSector');
        
        if(mouseLat) mouseLat.innerText = e.latlng.lat.toFixed(4);
        if(mouseLon) mouseLon.innerText = e.latlng.lng.toFixed(4);
        
        if(mouseSector) {
            const secX = Math.floor((e.latlng.lng - 75.6) / 0.05);
            const secY = Math.floor((e.latlng.lat - 26.7) / 0.05);
            const sectorChar = String.fromCharCode(65 + (Math.abs(secX + secY) % 26));
            mouseSector.innerText = `SECTOR_${sectorChar}_GRID_${Math.abs(secX)}${Math.abs(secY)}`;
        }
    });
}

// 4. Node Drawing Logic
function drawNodes() {
    if (!dashboardData || !dashboardData.nodes || !map) return;

    const nodes = dashboardData.nodes;
    const nodeCountEl = document.getElementById('nodeCount');
    if (nodeCountEl) nodeCountEl.innerText = `ACTIVE_NODES: ${nodes.length}`;
    
    // Update auxiliary node counter if it exists (panel 1 subheader)
    const auxNodeCount = document.querySelector('.text-primary-container.px-2');
    if (auxNodeCount) auxNodeCount.innerText = `ACTIVE_NODES: ${nodes.length}`;

    nodes.forEach(node => {
        const lng = 75.60 + (node.pos.x / 100) * 0.35; 
        const lat = 26.78 + (node.pos.y / 100) * 0.25;
        
        if (nodeMarkers[node.id]) {
            const marker = nodeMarkers[node.id];
            marker.setLatLng([lat, lng]);
            const el = marker.getElement()?.querySelector('.node-pulsar');
            if (el) {
                if (node.is_infected) el.classList.add('infected');
                else el.classList.remove('infected');
            }
        } else {
            const pulsarIcon = L.divIcon({
                className: 'custom-div-icon',
                html: `<div class="node-pulsar ${node.is_infected ? 'infected' : ''}"></div>`,
                iconSize: [4, 4],
                iconAnchor: [2, 2]
            });

            const marker = L.marker([lat, lng], { icon: pulsarIcon }).addTo(map);
            
            marker.bindPopup(`
                <strong>NODE_${node.id}</strong><br/>
                STATUS: ${node.is_infected ? '<span style="color: #FF0000; font-weight: 800; text-shadow: 0 0 5px #FF0000;">INFECTED</span>' : '<span style="color: #00FBFB; font-weight: 800; text-shadow: 0 0 5px #00FBFB;">OPERATIONAL</span>'}<br/>
                SERIAL: ${node.decoded_serial}<br/>
                INGEST_CODE: ${node.last_http_code}
            `, { closeButton: false, offset: [0, -5] });

            marker.on('mouseover', function(e) { this.openPopup(); });
            marker.on('mouseout', function(e) { this.closePopup(); });

            nodeMarkers[node.id] = marker;
        }
    });

    if (is3DMode) update3DNodes();

    const currentIds = new Set(nodes.map(n => n.id));
    Object.keys(nodeMarkers).forEach(id => {
        if (!currentIds.has(parseInt(id))) {
            map.removeLayer(nodeMarkers[id]);
            delete nodeMarkers[id];
        }
    });
}

// UI Update Aggregator
function updateUI() {
    if (!dashboardData) return;
    drawNodes();

    const threatCount = dashboardData.metadata.active_threats;
    const totalAnomalies = dashboardData.metadata.total_anomalies;
    const criticalNodes = (dashboardData.heatmap || []).filter(h => h.risk_level === 'CRITICAL');

    const headerThreats = document.getElementById('headerThreats');
    if(headerThreats) {
        const oldVal = parseInt(headerThreats.getAttribute('data-val') || "0");
        if (totalAnomalies > oldVal) {
            headerThreats.classList.add('anomaly-scan');
            setTimeout(() => headerThreats.classList.remove('anomaly-scan'), 600);
        }
        headerThreats.setAttribute('data-val', totalAnomalies);
        headerThreats.innerHTML = `AEGIS_CORE v4.2 [ <span class="${threatCount > 0 ? 'text-error' : 'text-primary-container'} font-black">THREATS: ${threatCount} | HITS: ${totalAnomalies}</span> ]`;
    }

    const tooltip = document.querySelector('.threat-tooltip');
    if (tooltip) tooltip.innerText = `${threatCount} Infected Nodes | ${criticalNodes.length} Latency Spikes`;

    const heatmapStatus = document.getElementById('heatmapStatus');
    if (heatmapStatus && dashboardData.metadata.latest_log_timestamp) {
        const date = new Date(dashboardData.metadata.latest_log_timestamp);
        const timeStr = date.toLocaleTimeString('en-US', { hour12: false });
        const ms = date.getMilliseconds().toString().padStart(3, '0');
        heatmapStatus.innerText = `LAST_INGESTION: ${timeStr}.${ms}`;
    }

    const activeSchema = document.getElementById('activeSchema');
    const schemaVersionBadge = document.getElementById('schemaVersionBadge');
    const nodeCount = document.getElementById('nodeCount');

    if(activeSchema) activeSchema.innerText = `${activeSchemaVersion === 1 ? "load_val" : "L_V1"}_ACTIVE | SYNC_LOCKED`;
    if(schemaVersionBadge) schemaVersionBadge.innerText = `V${activeSchemaVersion}`;
    if(nodeCount) nodeCount.innerText = `ACTIVE_NODES: ${dashboardData.nodes.length}`;

    const alertEl = document.getElementById('systemAlert');
    if (alertEl) {
        if (dashboardData.metadata.active_threats > 0) {
            alertEl.innerHTML = `SYSTEM_ALERT: ${dashboardData.metadata.active_threats} Anomalies detected. <br/><span class="font-normal opacity-100 uppercase text-secondary">Security protocols engaged. Review forensic map for Breach indicators.</span>`;
            alertEl.parentElement.classList.add('pulse-red');
        } else {
            alertEl.innerHTML = `SYSTEM_STATUS: ${dashboardData.metadata.status}. <br/><span class="font-normal opacity-80 uppercase text-primary-container">All systems nominal across 500 nodes.</span>`;
            alertEl.parentElement.classList.remove('pulse-red');
        }
    }

    const tbody = document.getElementById('assetTableBody');
    if(tbody) {
        tbody.innerHTML = '';
        dashboardData.nodes.slice(0, visibleNodeLimit).forEach(node => {
            const row = document.createElement('tr');
            row.className = `${node.is_infected ? 'bg-error/10 text-error' : 'hover:bg-primary-container/5'} transition-colors cursor-default group relative`;
            row.innerHTML = `
                <td class="p-3 font-bold">${node.id}</td>
                <td class="p-3 text-outline hover-target relative">
                    ${node.encoded_ua}
                    <div class="decoding-tooltip"><span class="decoding-text"></span></div>
                </td>
                <td class="p-3 text-white">${node.decoded_serial}</td>
                <td class="p-3 text-right">
                    <span class="px-2 py-0.5 border ${node.is_infected ? 'border-[#FF0000] text-[#FF0000]' : 'border-primary-container text-primary-container'} text-[10px] uppercase font-bold">
                        ${node.is_infected ? 'Infected' : 'Operational'}
                    </span>
                </td>
            `;
            tbody.appendChild(row);
        });
    }

    const loadMoreBtn = document.getElementById('loadMoreBtn');
    if (loadMoreBtn && visibleNodeLimit >= dashboardData.nodes.length) loadMoreBtn.classList.add('hidden');

    const chartBars = document.getElementById('chartBars');
    if (chartBars) {
        chartBars.innerHTML = '';
        (dashboardData.heatmap || []).forEach((entry, idx) => {
            const lat = entry.avg_response_time_ms || 0;
            const risk = entry.risk_level || 'LOW';
            const h = Math.min(100, (lat / 250) * 100);
            const bar = document.createElement('div');
            const stagger = (idx * 20) % 200;
            bar.className = `flex-grow max-w-[16px] h-full transition-all duration-500 relative group flex items-center justify-center ${risk === 'HIGH' || risk === 'CRITICAL' ? 'bg-secondary border-t-2 border-[#fff] shadow-[0_0_20px_rgba(253,144,0,0.6)]' : 'bg-primary-container/60 border-t border-primary-container'}`;
            bar.style.height = h + '%';
            bar.style.transitionDelay = `${stagger}ms`;
            bar.innerHTML = `<span class="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 [writing-mode:vertical-lr] rotate-180 text-[10px] font-black ${risk === 'HIGH' || risk === 'CRITICAL' ? 'text-black' : 'text-white'} uppercase tracking-widest pointer-events-none select-none">ID_${entry.node_uuid}</span>`;

            bar.onmouseenter = (e) => {
                const tooltip = document.getElementById('heatmapTooltip');
                if(tooltip) {
                    tooltip.innerHTML = `NODE: ${entry.node_uuid}<br/>RT: ${lat}ms<br/>RISK: ${risk}`;
                    tooltip.style.visibility = 'visible';
                    tooltip.style.left = (e.clientX + 15) + 'px';
                    tooltip.style.top = (e.clientY + 15) + 'px';
                    tooltip.style.border = risk === 'HIGH' || risk === 'CRITICAL' ? '1px solid #fd9000' : '1px solid #00FBFB';
                    tooltip.style.boxShadow = risk === 'HIGH' || risk === 'CRITICAL' ? '0 0 10px rgba(253,144,0,0.3)' : '0 0 10px rgba(0,251,251,0.3)';
                }
            };
            bar.onmousemove = (e) => {
                const tooltip = document.getElementById('heatmapTooltip');
                if(tooltip) { tooltip.style.left = (e.clientX + 15) + 'px'; tooltip.style.top = (e.clientY + 15) + 'px'; }
            };
            bar.onmouseleave = () => { const tooltip = document.getElementById('heatmapTooltip'); if(tooltip) tooltip.style.visibility = 'hidden'; };
            chartBars.appendChild(bar);
        });
    }

    const consoleOutput = document.getElementById('consoleOutput');
    if(consoleOutput) {
        (dashboardData.terminal_logs || []).slice().reverse().forEach(log => {
            if (log.id > lastProcessedLogId) {
                const div = document.createElement('div');
                div.className = (log.status || '') !== 'HEALTHY' ? "text-secondary mb-1 animate-pulse font-bold" : "text-white mb-1";
                div.innerText = log.message;
                const oldCursor = consoleOutput.querySelector('.cursor-active');
                if (oldCursor) oldCursor.remove();
                consoleOutput.appendChild(div);
                lastProcessedLogId = log.id;
            }
        });
        if (!consoleOutput.querySelector('.cursor-active')) {
            const cursor = document.createElement('div');
            cursor.className = "text-white mb-1 animate-pulse cursor-active";
            cursor.innerText = "_█";
            consoleOutput.appendChild(cursor);
        }
        consoleOutput.scrollTop = consoleOutput.scrollHeight;
    }
}

// ─────────────────────────────────────────────────────────────
// 5. 3D Holographic Forensic Visualization (Three.js)
// ─────────────────────────────────────────────────────────────
let scene, camera, renderer, controls, raycaster;
let is3DMode = false;
let threeNodes = {};
const mouse3D = new THREE.Vector2();
let hoveredNodeId = null;

function init3D() {
    const container = document.getElementById('map3d');
    if(!container) return;
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x050505);
    camera = new THREE.PerspectiveCamera(60, container.clientWidth / container.clientHeight, 0.1, 1000);
    camera.position.set(0, 5, 10);
    renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(container.clientWidth, container.clientHeight);
    container.appendChild(renderer.domElement);
    scene.add(new THREE.GridHelper(30, 30, 0x00fbfb, 0x002020));
    generate3DCityscape();
    controls = new THREE.OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    window.addEventListener('resize', () => { if(container && camera && renderer) { camera.aspect = container.clientWidth / container.clientHeight; camera.updateProjectionMatrix(); renderer.setSize(container.clientWidth, container.clientHeight); } });
    container.addEventListener('mousemove', (event) => {
        const rect = container.getBoundingClientRect();
        mouse3D.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
        mouse3D.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
        const tooltip = document.getElementById('map3dTooltip');
        if(tooltip) { tooltip.style.left = (event.clientX - rect.left + 15) + 'px'; tooltip.style.top = (event.clientY - rect.top + 15) + 'px'; }
    });
    raycaster = new THREE.Raycaster();
    animate3D();
}

function generate3DCityscape() {
    const group = new THREE.Group();
    for (let i = 0; i < 60; i++) {
        const h = Math.random() * 4 + 1;
        const w = Math.random() * 1.5 + 0.5;
        const geom = new THREE.BoxGeometry(w, h, w);
        const mesh = new THREE.Mesh(geom, new THREE.MeshBasicMaterial({ color: 0x001515, transparent: true, opacity: 0.6 }));
        const line = new THREE.LineSegments(new THREE.EdgesGeometry(geom), new THREE.LineBasicMaterial({ color: 0x004f4f }));
        const x = (Math.random() - 0.5) * 30, z = (Math.random() - 0.5) * 30;
        mesh.position.set(x, h/2, z); line.position.set(x, h/2, z);
        group.add(mesh); group.add(line);
    }
    scene.add(group);
}

function animate3D() {
    requestAnimationFrame(animate3D); if (controls) controls.update();
    if (is3DMode && raycaster && scene && camera) {
        raycaster.setFromCamera(mouse3D, camera);
        const intersect = raycaster.intersectObjects(scene.children, true).find(i => i.object.userData && i.object.userData.nodeId);
        if (intersect) {
            const nid = intersect.object.userData.nodeId;
            if (hoveredNodeId !== nid) { hoveredNodeId = nid; const node = dashboardData.nodes.find(n => n.id === nid); if (node) show3DTooltip(node); }
        } else if (hoveredNodeId !== null) { hoveredNodeId = null; hide3DTooltip(); }
    }
    if (renderer && scene && camera) renderer.render(scene, camera);
}

function show3DTooltip(node) {
    const tooltip = document.getElementById('map3dTooltip');
    if(tooltip) {
        tooltip.innerHTML = `<div class="text-[10px] font-black mb-1 border-b border-[#00fbfb]/30 pb-1">NODE_${node.id}_UPLINK</div><div class="flex justify-between gap-4"><span>STATUS:</span><span class="${node.is_infected ? 'text-red-500' : 'text-[#00fbfb]'}">${node.is_infected ? 'INFECTED' : 'OPERATIONAL'}</span></div><div class="flex justify-between gap-4"><span>SERIAL:</span><span>${node.decoded_serial}</span></div><div class="flex justify-between gap-4"><span>INGEST:</span><span>${node.last_http_code}</span></div>`;
        tooltip.style.visibility = 'visible';
    }
}

function hide3DTooltip() { const tooltip = document.getElementById('map3dTooltip'); if(tooltip) tooltip.style.visibility = 'hidden'; }

function toggleMode() {
    is3DMode = !is3DMode;
    const btn = document.getElementById('toggle3d');
    const map2d = document.getElementById('map');
    const map3d = document.getElementById('map3d');
    if (is3DMode) {
        if(btn) { btn.innerText = "3D_HOLO"; btn.classList.add('bg-[#00FBFB]', 'text-[#050505]'); }
        if(map2d) map2d.classList.add('opacity-0');
        if(map3d) map3d.classList.remove('hidden');
        if (!renderer) init3D();
        update3DNodes();
    } else {
        if(btn) { btn.innerText = "2D_MAP"; btn.classList.remove('bg-[#00FBFB]', 'text-[#050505]'); }
        if(map2d) map2d.classList.remove('opacity-0');
        if(map3d) map3d.classList.add('hidden');
    }
}

function update3DNodes() {
    if (!is3DMode || !dashboardData || !dashboardData.nodes || !scene) return;
    dashboardData.nodes.forEach(node => {
        const x = (node.pos.x - 50) / 3.3, z = (node.pos.y - 50) / 3.3, h = node.is_infected ? 3 : 0.8;
        if (threeNodes[node.id]) {
            threeNodes[node.id].position.set(x, h, z);
            threeNodes[node.id].material.color.setHex(node.is_infected ? 0xff003c : 0x00fbfb);
        } else {
            const mesh = new THREE.Mesh(new THREE.OctahedronGeometry(0.2), new THREE.MeshBasicMaterial({ color: node.is_infected ? 0xff003c : 0x00fbfb }));
            mesh.position.set(x, h, z); mesh.userData.nodeId = node.id;
            scene.add(mesh); threeNodes[node.id] = mesh;
        }
    });
    const currentIds = new Set(dashboardData.nodes.map(n => n.id));
    Object.keys(threeNodes).forEach(id => { if (!currentIds.has(parseInt(id))) { scene.remove(threeNodes[id]); delete threeNodes[id]; } });
}

// ─────────────────────────────────────────────────────────────
// 6. Packet Counter & Extra Logic
// ─────────────────────────────────────────────────────────────
function updatePacketCounter() {
    if (!dashboardData) return;
    const display = document.getElementById('packetCount'), bar = document.getElementById('packetBar');
    if(!display || !bar) return;
    
    // Base 'remaining' packets from backend (e.g. 4300)
    let baseRem = Math.abs(parseInt(dashboardData.schema_engine.rotation_timer.replace('_PKTS', '')));
    
    // Real-time packets remaining (taking manual nudge into account)
    let rem = Math.max(0, baseRem - localLogOffset);
    if (rem === 0 && baseRem > 0) rem = 5000; // Reset handling

    // Progress bar shows progress in current window (counting up to 5000)
    let progress = (5000 - rem) % 5000;
    
    display.innerText = rem.toString().padStart(4, '0');
    bar.style.width = `${Math.min(100, (progress / 5000) * 100)}%`;
    
    if (rem < 500) { 
        bar.classList.remove('bg-primary-container'); 
        bar.style.backgroundColor = '#fd9000'; 
        bar.style.boxShadow = '0 0 10px #fd9000'; 
    } else { 
        bar.classList.add('bg-primary-container'); 
        bar.style.backgroundColor = ''; 
        bar.style.boxShadow = ''; 
    }
}

function triggerSchemaRotation(newVersion) {
    activeSchemaVersion = newVersion;
    
    lastAnomalyNodeIds = new Set();
    
    // VISUAL GLITCH
    document.body.classList.add('glitch-active'); 
    setTimeout(() => document.body.classList.remove('glitch-active'), 1000);
    
    const console = document.getElementById('consoleOutput');
    if(console) {
        const div = document.createElement('div');
        div.className = "text-secondary font-bold mb-1 border-y border-secondary/30 py-1";
        div.innerText = `[ANALYSIS] Threshold Reached. Re-syncing Forensic Layer: ${activeSchemaVersion === 1 ? "load_val (V1)" : "L_V1 (V2)"}.`;
        console.appendChild(div); console.scrollTop = console.scrollHeight;
    }
}

function acceleratePackets() {
    localLogOffset += 500;
    const console = document.getElementById('consoleOutput');
    if(console){
        const div = document.createElement('div'); div.className = "text-secondary italic mb-1 animate-pulse";
        div.innerText = ">> [SYSTEM] OVERCLOCK_SIGNAL: +500_PACKETS_INGESTED (FORCING_SCHEMA_ROTATION)";
        console.appendChild(div); console.scrollTop = console.scrollHeight;
    }
    updatePacketCounter();
}

function dismissAlert() { const alert = document.getElementById('alertContainer'); if(alert) alert.style.display = 'none'; }
function loadMoreNodes() { const btn = document.getElementById('loadMoreBtn'); if(btn) btn.classList.add('hidden'); visibleNodeLimit += 50; updateUI(); }

// 7. PDF Exports
async function downloadRegistryPDF() {
    if(!dashboardData) return;
    const { jsPDF } = window.jspdf; const doc = new jsPDF();
    doc.setFontSize(18); doc.setTextColor(0, 150, 150); doc.text("AEGIS_CYBER_FORENSIC_REGISTRY", 14, 20);
    doc.autoTable({ head: [['Node_ID', 'Encoded_User_Agent', 'Decoded_Serial', 'Status']], body: dashboardData.nodes.map(n => [n.id, n.encoded_ua, n.decoded_serial, n.is_infected ? "INFECTED" : "OPERATIONAL"]), startY: 40, theme: 'grid' });
    doc.save(`AEGIS_Forensic_Export_${Date.now()}.pdf`);
}

async function downloadHeatmapPDF() {
    if (!dashboardData || !dashboardData.heatmap) return;
    const { jsPDF } = window.jspdf; const doc = new jsPDF();
    doc.setFontSize(18); doc.setTextColor(253, 144, 0); doc.text("AEGIS_SLEEPER_HEATMAP_FORENSICS", 14, 20);
    doc.autoTable({ head: [['Node_ID', 'Serial', 'Avg_RT', 'Max_RT', 'P95_RT', 'Logs', 'Risk']], body: dashboardData.heatmap.map(e => [e.node_uuid, e.serial_number, e.avg_response_time_ms+"ms", e.max_response_time_ms+"ms", e.p95_response_time_ms+"ms", e.log_count, e.risk_level]), startY: 40, theme: 'grid' });
    doc.save(`AEGIS_HEATMAP_EXPORT_${Date.now()}.pdf`);
}

// 8. Event Listeners
window.addEventListener('DOMContentLoaded', () => {
    initMap();
    const reg = document.getElementById('registryContainer');
    if(reg) reg.addEventListener('scroll', () => {
        const { scrollTop, scrollHeight, clientHeight } = reg;
        const btn = document.getElementById('loadMoreBtn');
        if (btn && scrollHeight - Math.ceil(scrollTop) <= clientHeight + 5 && visibleNodeLimit < dashboardData?.nodes?.length) btn.classList.remove('hidden');
    });
});

window.addEventListener('mousemove', (e) => {
    const gx = document.getElementById('gXPos'), gy = document.getElementById('gYPos'), gz = document.getElementById('gZPos');
    if(gx) gx.innerText = (e.clientX / window.innerWidth).toFixed(4);
    if(gy) gy.innerText = (e.clientY / window.innerHeight).toFixed(4);
    if(gz) gz.innerText = (Math.sin(Date.now() / 1000) * 0.001).toFixed(4);
});

setInterval(fetchDashboardData, 3000);
setInterval(updatePacketCounter, 1000);
fetchDashboardData();

// Expose to window
window.toggleMode = toggleMode; window.dismissAlert = dismissAlert; window.loadMoreNodes = loadMoreNodes;
window.downloadRegistryPDF = downloadRegistryPDF; window.downloadHeatmapPDF = downloadHeatmapPDF; window.acceleratePackets = acceleratePackets;
