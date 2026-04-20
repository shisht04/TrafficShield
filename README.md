#  TrafficShield — Network Traffic Analyzer & Security Dashboard

A cybersecurity project that performs **Deep Packet Inspection (DPI)** on network traffic captures (`.pcap` files) and visualizes the results through an interactive web dashboard.

---

##  What It Does

Modern networks carry traffic from hundreds of applications simultaneously. TrafficShield answers:

> *"What is actually flowing through a network, and is any of it a threat?"*

The system reads a `.pcap` file, inspects each packet deep into its payload, identifies which application generated it (YouTube, Facebook, DNS, etc.), and presents everything visually — blocked packets, top domains, protocol breakdown, and more.

---

##  Architecture

```
.pcap file
    │
    ▼
C++ DPI Engine  (cpp_engine/)
    │  Parses packets, extracts TLS SNI,
    │  classifies apps, applies block rules
    │
    ▼ stdout report
Python Parser  (analyzer/parse_output.py)
    │  Converts DPI output → structured JSON
    │
    ▼ report.json
Flask Backend  (backend/app.py)
    │  Serves data via REST API
    │
    ▼ GET /api/report
Web Dashboard  (dashboard/index.html)
       Interactive charts & tables in browser
```

---

##  Features

-  **Deep Packet Inspection** — inspects beyond headers into packet payloads
-  **TLS SNI Extraction** — identifies HTTPS destinations even through encryption
-  **Traffic Classification** — detects YouTube, Facebook, Google, DNS, and more
-  **Packet Blocking** — drops traffic by app, domain, or source IP
-  **Web Dashboard** — interactive charts for traffic breakdown, blocked packets, top domains
-  **PCAP Output** — filtered traffic saved as a new `.pcap` for further analysis

---

##  Repo Structure

```
TrafficShield/
├── cpp_engine/             # C++ DPI engine (core packet inspector)
├── analyzer/
│   └── parse_output.py     # Parses DPI output → JSON
├── backend/
│   └── app.py              # Flask server — serves /api/report
├── dashboard/
│   └── index.html          # Web dashboard (charts + tables)
├── requirements.txt
└── README.md
```

---

##  Getting Started

### Prerequisites
- Python 3.8+
- pip
- g++ with C++17 support (to build the engine)

### Step 1 — Install Python dependencies

```bash
pip install -r requirements.txt
```

### Step 2 — Build the C++ engine (optional)

```bash
cd cpp_engine
g++ -std=c++17 -O2 -I include -o dpi_engine \
    src/main_working.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

### Step 3 — Run the dashboard

```bash
python backend/app.py
```

Open your browser at `http://localhost:5000`

---

##  Dashboard Panels

| Panel | Description |
|---|---|
| Traffic Breakdown | Pie chart — % of packets per app |
| Blocked vs Forwarded | Bar chart — packets passed vs dropped |
| Top Domains | Table of detected SNI hostnames |
| Protocol Split | TCP vs UDP doughnut chart |
| Per-App Count | Horizontal bar chart |
| Alert Log | List of blocked connections with reason |

---

##  How DPI Works

### SNI Extraction
Even HTTPS traffic leaks the destination domain. The **TLS Client Hello** — sent before encryption starts — contains the domain in plaintext:

```
TLS Client Hello
└── Extensions
    └── SNI: "www.youtube.com"   ← visible without decryption
```

### Flow-Based Blocking
Once a connection is identified (e.g. YouTube), all subsequent packets of that flow are dropped automatically.

---

##  Tech Stack

| Layer | Technology |
|---|---|
| Packet Inspection | C++17 |
| Data Parsing | Python 3 |
| Backend API | Flask |
| Dashboard | HTML, CSS, JavaScript, Chart.js |
| Network Format | libpcap `.pcap` files |

---

##  License

This project is for educational purposes, made by Shisht Tiwari.
Do Star it if you find it useful<33
