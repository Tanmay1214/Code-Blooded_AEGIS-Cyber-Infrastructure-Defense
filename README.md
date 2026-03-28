# AEGIS Cyber Infrastructure Defense 🛡️🛰️

**Team:** Code-Blooded  
**Mission:** To protect Nexus City using a high-performance, autonomous, cloud-native forensic intelligence platform.

AEGIS (Autonomous Experimental Grid Intelligence System) is a complete full-stack cybersecurity dashboard engineered for real-time anomaly detection, node health monitoring, and automated forensic ingestion. Built for the hackathon, AEGIS simulates a **100 packets/sec** telemetry data stream, analyzes it using machine learning models, and visualizes network health through an immersive, cyberpunk-themed web dashboard.

---

## 🌟 Hackathon Highlights & Features

1. **Overclocked Autonomous Telemetry Pulse** 🌀  
   An in-process background worker runs silently alongside the FastAPI server, pulling forensic data from local manifests and pushing telemetry into the cloud database at **100 packets/sec**—simulating high-velocity traffic 24/7 without requiring external paid workers.
2. **Machine Learning "Brain"** 🧠  
   Integrated `IsolationForest` (unsupervised) and `XGBoost` (supervised) models scan all incoming logs in real-time, assigning anomaly scores and generating an Alert Ticker for malicious activity.
3. **Immersive Cyberpunk Dashboard** 🌃  
   A pure Vanilla HTML/JS/CSS frontend featuring a CRT scanline overlay, dynamic network heatmaps, smooth staggered layout animations, and typing terminal effects.
4. **Intelligent Schema Rotation & Master Sync** 🔄  
   The ingestion engine handles high-velocity `V1`/`V2` schema shifts, perfectly synchronized using **Master Sequence ID** windowing to ensure 100% accuracy in threat counts and glitch triggers.
5. **Cloud-Native Resilience** ⚡  
   Engineered for managed PostgreSQL with `asyncpg`, featuring a custom 5-attempt retry loop and automatic sequence calibration to ensure flawless startups on cloud infrastructure.

---

## 🧠 Deep Dive: The Backend Intelligence (`aegis_backend`)

The `aegis_backend` is the asynchronous "Brain" of the entire application. Built primarily with Python 3.10+ and FastAPI, it is engineered to process massive telemetry logs (**100 logs/sec**), hunt for cybersecurity anomalies using Machine Learning, and serve data to the frontend in real-time.

### 1. The Autonomous Pulse Generator (`app/services/pulse.py`)
Instead of relying on external cron jobs, paid scripts, or manual triggers, this backend features a self-sustaining in-process background worker. Every **0.5 seconds**, it streams a batch of 50 telemetry logs into PostgreSQL (**100 logs/sec**). This guarantees a true **Zero-Cost 24/7 Live Feed**.

### 2. The Machine Learning Engine (`app/ml/detector.py`)
During data insertion, the stream is continuously evaluated by the Anomaly Detection Engine:
- **XGBoost Classifier**: Scans the payload for known threat patterns (Supervised).
- **Isolation Forest**: Hunts for bizarre behavior and outliers (Unsupervised).
Logs with highly abnormal `response_time_ms` or `load_val` metrics are flagged as "ANOMALY" and intercepted into a dedicated threat table.

### 3. Forensic Ingestion & Schema Rotation (`app/services/ingestion.py`)
Real-world cybersecurity data structures evolve dynamically. To simulate this, the ingest engine monitors the data stream for **Schema Evolution**. It automatically determines if an incoming packet requires the "V1" or "V2" schema structure and formats it properly before database insertion.

### 4. Asynchronous Resilience (`app/core/database.py`)
Powered by `SQLAlchemy` combined with the `asyncpg` driver, the API is entirely non-blocking. To harden the system for cloud deployments, the database initialization features a robust 5-attempt retry-backoff handshake to survive transient cloud DNS latency.

---

## 🛠️ Tech Stack

- **Backend:** Python, FastAPI, SQLAlchemy (Async), Uvicorn, Scikit-Learn, XGBoost.
- **Frontend:** Vanilla HTML5, CSS3, JavaScript (Fetch API).
- **Database:** PostgreSQL (Render Managed Provider / Local Docker).
- **Cache / Message Broker:** Redis (Upstash / Local Docker).

---

## 🚀 Local Deployment (Docker-First) 🐳

For maximum accuracy, performance, and efficiency, the AEGIS system is designed to run in a fully containerized environment using **Docker**. This ensures a literal "One-Command" setup with local PostgreSQL and Redis instances, providing zero-latency data ingestion.

### Prerequisites
- **Docker Desktop** installed and running.

---

### Step 1: Engage the Mission Stack 🌀
From the root of the project, navigate to the backend and launch the entire defense architecture:

```bash
cd aegis_backend
docker-compose up --build -d
```
*This will spin up the FastAPI Brain, a private PostgreSQL instance, and a dedicated Redis cache.*

---

### Step 2: Initialize the Local Sector 🧹
The containers are now live, but the local database is empty. You must populate it with the initial node fabric and telemetry data.

```bash
# Enter the API container to run the initialization scripts
docker exec -it aegis_api sh

# Inside the container, run the baseline commands:
python reset_db.py
python scripts/seed_db.py
python scripts/calibrate_sequences.py
exit
```

---

### Step 3: Launch the Cyberpunk Dashboard 🏙️
With the backend active at `http://localhost:8000`, launch the frontend from the **Root Project Folder**:

```bash
# On your host machine (root folder)
python -m http.server 8080
```
Open your browser at: `http://localhost:8080/dashboard.html`

---

## 🌐 Live Deployment & Disclaimer

The AEGIS Defense System frontend is actively hosted at:
**[https://aegis-cyber-infrastructure-defense.vercel.app/](https://aegis-cyber-infrastructure-defense.vercel.app/)**

> [!WARNING]
> **Infrastructure Notice:** The backend intelligence, database, and telemetry pulse are currently hosted on **Render's Free Tier** services. As a result, computing resources are limited. You may experience noticeable latency, occasional data-sync inaccuracies, or temporary service hibernation if the server powers down due to inactivity.

---
**Mission Complete. Nexus City is Secured.** 🏆
