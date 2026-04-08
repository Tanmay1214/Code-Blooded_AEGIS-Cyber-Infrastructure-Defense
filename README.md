# AEGIS Cyber Infrastructure Defense 🛡️🛰️

> **Project AEGIS** — Identify the "Shadow Controller" infiltrating Nexus City's infrastructure
> by cutting through deceptive telemetry data to expose real attack patterns.
>
> Built by **Code Blooded** — Tanmay, Anvay, Devesh, Aarin @ LNMIIT Jaipur

---

## 🌟 Hackathon Highlights & Features

1. **Overclocked Autonomous Telemetry Pulse** 🌀  
   An in-process background worker runs silently alongside the FastAPI server, pulling forensic data from local manifests and pushing telemetry into the cloud database at **100 packets/sec**—simulating high-velocity traffic 24/7.
2. **Machine Learning "Brain"** 🧠  
   Integrated `IsolationForest` (unsupervised) and `XGBoost` (supervised) models scan all incoming logs in real-time, assigning anomaly scores and generating an Alert Ticker for malicious activity.
3. **Tactical Autonomous Response Interface (Round 2)** 🛡️  
   A new, high-density 5-panel command center designed for active defense. Featuring a 500-node real-time grid, incident timelines, and automated lockout terminals.
4. **Biphasic Threat Simulator** 🎭  
   Advanced stress-testing suite with randomized node strikes. Supports **Latency Jitter (Yellow)** and **Deceptive Traffic (Purple)** phenotypes to validate defense responsiveness.
5. **Protocol Zero: Master Quarantine Override** 🚫  
   A one-touch emergency protocol that zeroes the threat threshold, instantly isolating every infected node in the city via the automated "Sword" mechanism.
6. **Intelligent Schema Rotation & Master Sync** 🔄  
   The ingestion engine handles high-velocity `V1`/`V2` schema shifts, perfectly synchronized using **Master Sequence ID** windowing to ensure 100% accuracy in threat counts.
7. **Stratified Telemetry Protocol** 📡
   Optimized bandwidth usage by transmitting heavy node metadata once per handshake, then shifting to a lightweight "Heartbeat" protocol for 100 log/sec dashboard reactivity.
8. **Master Forensic PDF Reporting** 📄
   Integrated `jspdf` and `jspdf-autotable` to allow one-click forensic report generation for the **Asset Registry** and **Threat Heatmap**.
9. **JWT Operator Authentication** 🔐
   All sensitive endpoints are secured behind JWT Bearer token authentication. Operators must authenticate via the login terminal before gaining access.

---

## 🏗️ Architecture
```
Data Sources  →  Ingestion Layer      →  Processing Layer  →  Detection Brain        →  Storage      →  API Layer
(CSVs/Stream)    (FastAPI + Pipeline)     (Pandas/Polars)      (Rules + IsoForest)      (PG + Redis)    (FastAPI)
```

### Detection Stack
```
Raw Telemetry
     │
     ▼
┌─────────────────────────────────────────┐
│           INGESTION PIPELINE            │
│  LogAdapter → Preprocessor → Router    │
│  RegistryAdapter (Base64 decode)        │
│  SchemaAdapter (v1/v2 rotation)         │
└─────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────┐
│         RULE-BASED DETECTION ENGINE     │
│                                         │
│  Rule 1 → DDoS Detector                 │
│           (429 spikes per node > 5x)    │
│                                         │
│  Rule 2 → Latency Anomaly Detector      │
│           (response_time_ms > 200ms)    │
│                                         │
│  Rule 3 → Status Mismatch Detector      │
│           (OPERATIONAL lie detection)   │
│                                         │
│  Rule 4 → Infected Node Detector        │
│           (registry cross-reference)    │
└─────────────────────────────────────────┘
     │
     ▼
┌─────────────────────────────────────────┐
│         ML DETECTION LAYER              │
│  IsolationForest on:                    │
│  response_time_ms + http_code + load    │
└─────────────────────────────────────────┘
     │
     ▼
  ThreatAlert  (severity + evidence + details)
```

---

## 📸 Visual Interface

### 🔐 0. AEGIS Secure Login Terminal
Operators must authenticate before accessing any forensic data. Features a CRT scanline overlay and neon cyan framing.
- **Username:** `admin`
- **Password:** `aegis123`

### 🌀 1. Initial Boot Sequence (Landing)
Immersive terminal-style boot-up with typewriter effects as the AEGIS Core initializes.
![AEGIS Landing Screen](aegis_backend/assets/screenshots/landing.png)

### 🛰️ 2. High-Velocity Forensic Dashboard
Access to the real-time telemetry suite, featuring node maps, anomaly heatmaps, and a 100 log/sec ingestion stream.
![AEGIS Forensic Dashboard](aegis_backend/assets/screenshots/dashboard.png)

### 🛡️ 3. Autonomous Response Center (Round 2)
The "War Room" interface for active threat mitigation.
- **Active Health Monitor**: Prioritized list of high-risk nodes.
- **Infrastructure Grid**: 500-node visual heatmap for global health tracking.
- **Attack Timeline**: Real-time visual patterns of breach attempts.
- **Quarantine Logs**: Audit trail of every automated node lockout.
- **Control Hub**: Master threshold sliders and Biphasic Threat Simulator toggles.
![AEGIS Autonomous Dashboard](aegis_backend/assets/screenshots/autonomous.png)

---

## 🛠️ Tech Stack

- **Backend:** Python, FastAPI, SQLAlchemy (Async), Uvicorn, Scikit-Learn, XGBoost, python-jose (JWT).
- **Frontend:** Vanilla HTML5, CSS3, JavaScript (Fetch API).
- **Database:** PostgreSQL (Render Managed Provider / Local Docker).
- **Cache:** Redis (Upstash / Local Docker).

---

## 🚀 Quick Start (Docker-First) 🐳

The AEGIS system is designed for a **"One-Command"** setup using Docker, providing an optimized local environment with PostgreSQL and Redis.

### 1. Engage the Mission Stack
```bash
cd aegis_backend
docker-compose up --build -d
```

### 2. Initialize the Local Sector
Populate the database with the initial node fabric and telemetry data:
```bash
docker exec -it aegis_api sh
# Inside container:
python scripts/seed_db.py
python scripts/train_model.py
exit
```

### 2.5. Operator Login
Once the dashboard is live, navigate to `login.html` first.
- **Username:** `admin`
- **Password:** `aegis123`

### 3. Launch the Dashboard
Launch the frontend from the **Root Project Folder**:
```bash
# On your host machine (root folder)
python -m http.server 8080
```
Open current dash at: `https://aegis-api-65i8.onrender.com/` or locally at `http://localhost:8080/login.html`

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | System health — DB, Redis, ML model status |
| POST | `/api/login` | JWT authentication — returns bearer token |
| GET | `/api/nodes` | All 500 nodes with decoded serial numbers |
| GET | `/api/dashboard-aggregator` | **Master Pulse**: Unified state for the Cyberpunk UI |
| GET | `/api/city-map` | All nodes colored by TRUE HTTP status |
| GET | `/api/heatmap` | Response-time heatmap — identifies sleeper malware |
| POST | `/api/ingest` | Ingest a new log entry + run live ML inference |
| POST | `/api/simulator/inject-threat` | **Biphasic Simulator**: Inject Latency/Deceptive threats |
| POST | `/api/settings/update` | Update global quarantine thresholds |

---

## 🛡️ Key Design Decisions

### 1. Biphasic Simulation Phenotypes (Round 2)
The simulator now differentiates between two critical attack vectors:
- **Latency Jitter (Yellow)**: Targets random nodes with HTTP 429/DDoS spikes.
- **Deceptive Traffic (Purple)**: Targets random nodes with HTTP 206/Infiltration signals.
- Both use a continuous background interval to barrage the grid, validating real-time response times.

### 2. Protocol Zero Lockdown
We implemented a "No-Trust" emergency toggle. By broadcasting a 0% threshold to the backend, the automated "Sword" protocol instantly isolates every single node with even a trace score, securing the city in milliseconds.

### 3. Stratified Telemetry Protocol
- **Handshake (`full=true`)**: Retrieves heavy metadata (node positions, serials).
- **Heartbeat (`full=false`)**: Retrieves only the mission-critical delta (anomaly counts, log IDs).

### 4. Status Truth — HTTP over JSON
The AEGIS pipeline **never trusts the JSON label**. It uses HTTP response codes as ground truth:
- **200**: HEALTHY
- **206**: PARTIAL — Hijack signal
- **429**: THROTTLED — DDoS indicator

---

## 📊 Dataset Intelligence

| Dataset | Rows | Anomaly Signal |
|---------|------|----------------|
| `system_logs.csv` | 10,000 | Silent column rotation at log_id 5000 |
| `node_registry.csv` | 500 nodes | 70 known infected (Base64 encoded serials) |

---

## 🌐 Live Demo
Frontend: [aegis-cyber-infrastructure-defense.vercel.app](https://aegis-cyber-infrastructure-defense.vercel.app)

> [!WARNING]
> **Infrastructure Notice:** The live backend is hosted on Render's Free Tier. Resources are limited; you may experience cold-start latency.

---
**Mission Complete. Nexus City is Secured.** 🏆
