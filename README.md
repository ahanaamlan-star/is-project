<div align="center">

# 🛡️ NetSentry XAI

### Explainable AI for Network Forensics & Threat Investigation

**From raw packets to an evidence-backed, explainable investigation — entirely in your browser.**

![Version](https://img.shields.io/badge/version-2.0.0-0284c7?style=for-the-badge)
![React](https://img.shields.io/badge/React-18-61dafb?style=for-the-badge&logo=react&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178c6?style=for-the-badge&logo=typescript&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-5-646cff?style=for-the-badge&logo=vite&logoColor=white)
![Netlify](https://img.shields.io/badge/Deploy-Netlify-00c7b7?style=for-the-badge&logo=netlify&logoColor=white)
![Privacy](https://img.shields.io/badge/data-100%25%20local-059669?style=for-the-badge)

[✨ Features](#-features) •
[🚀 Quick Start](#-quick-start) •
[🏗️ Architecture](#️-architecture) •
[🔍 Detection](#-detection-engine) •
[🧠 Explainability](#-explainability-by-design) •
[☁️ Deploy](#️-deploy-to-netlify)

</div>

---

## 📖 What is NetSentry XAI?

NetSentry XAI turns **PCAP / PCAPNG packet captures** into an understandable investigation: *what happened, which hosts and flows were involved, why each event was flagged, how unusual it was, and what evidence supports it.*

Unlike black-box classifiers, every finding is **traceable back to packets, flows and timestamps**, and every score comes with a plain explanation, alternative explanations and known limitations.

> [!IMPORTANT]
> **No backend. No uploads. No telemetry.** The whole analysis engine runs in a Web Worker inside your browser. Captures stay on your machine, stored only in your browser's IndexedDB.

<table>
<tr>
<td width="33%" valign="top">

### 📦 Evidence first
Every alert links to packet indices, flow IDs, timestamps, observed values and the thresholds that fired.

</td>
<td width="33%" valign="top">

### 🔎 Explainable by default
Observed facts, detection rationale and interpretation are always kept separate, so a narrative is never mistaken for evidence.

</td>
<td width="33%" valign="top">

### 🧑‍💼 Human-led
Read-only analysis. Analysts review, annotate, escalate or dismiss findings, and every action is audited.

</td>
</tr>
</table>

---

## ✨ Features

| | Feature | What you get |
|:-:|---|---|
| 📥 | **PCAP & PCAPNG upload** | Drag-and-drop, multiple files, magic-byte validation, size limits, SHA-256 chain of custody |
| 🧬 | **Protocol dissection** | Ethernet/VLAN/SLL, IPv4/IPv6, TCP/UDP/ICMP, DNS, HTTP, SSH, QUIC, TLS with **SNI, ALPN, JA3/JA3S** |
| 🔀 | **Flow reconstruction** | Bidirectional 5-tuple flows, idle-timeout splitting, Zeek-style connection states |
| 🎯 | **14 transparent rules** | Scans, sweeps, beaconing, DNS tunnelling, floods, exfiltration, ARP spoofing, lateral movement and more |
| 📊 | **Statistical baseline** | Robust median/MAD z-scores for unusual host egress |
| 🌲 | **Isolation Forest** | Seeded, reproducible anomaly scoring with per-feature attribution |
| 🧠 | **Structured explanations** | Facts → rationale → interpretation → alternatives → next checks → limitations |
| 🧩 | **Incident correlation** | Findings grouped by shared hosts and time; analysts can split or merge groupings |
| ⚖️ | **Transparent risk priority** | Weighted, configurable score, with every component shown |
| 🕸️ | **Host network graph** | Interactive force-directed graph with severity rings, drag, zoom and pan |
| 🕒 | **Incident timeline** | Swim-lane timeline with incident windows and zoom |
| 💬 | **Evidence assistant** | Ask *"What did 10.10.0.23 do?"* and get answers with clickable citations (no external AI) |
| 🆚 | **PCAP Diff** | Compare two captures: new hosts, domains, SNI, JA3, ports and protocol shifts |
| 🧪 | **Evaluation lab** | Live precision / recall / F1 for rules-only vs anomaly-only vs hybrid |
| 🗺️ | **MITRE ATT&CK** | Technique mapping, presented as a hypothesis rather than attribution |
| 📄 | **Reports** | PDF, HTML, JSON, CSV and **STIX 2.1** with provenance, configuration and audit trail |

---

## 🚀 Quick Start

```bash
# 1. Install dependencies (Node 18+, Node 20 recommended)
npm install

# 2. Start the dev server → http://localhost:5173
npm run dev

# 3. Production build → dist/
npm run build && npm run preview
```

Then open the site and click **"Run the live demo"**, or go to **PCAP Ingestion** and drop in your own capture.

### 🧭 First-run journey

```mermaid
flowchart LR
    A([🌐 Open site]) --> B{Have a PCAP?}
    B -- Yes --> C[📥 PCAP Ingestion<br/>drag & drop file]
    B -- No --> D[✨ Run the live demo]
    C --> E[🔐 Validate + SHA-256]
    D --> E
    E --> F[⚙️ Analyse in Web Worker]
    F --> G[📊 Overview]
    G --> H[🚨 Findings]
    H --> I[🧩 Incidents]
    I --> J[📄 Export report]

    style A fill:#0c4a6e,stroke:#38bdf8,color:#fff
    style D fill:#7c2d12,stroke:#fb923c,color:#fff
    style F fill:#312e81,stroke:#818cf8,color:#fff
    style J fill:#064e3b,stroke:#34d399,color:#fff
```

---

## 🏗️ Architecture

NetSentry XAI is a **static single-page app**. The Python/FastAPI pipeline from the original blueprint has been ported to TypeScript and runs in a background Web Worker, so the UI stays responsive and no server is needed.

```mermaid
flowchart TB
    subgraph Browser["🖥️ Analyst's Browser"]
        direction TB
        subgraph UI["🎨 React UI (main thread)"]
            P[Pages<br/>Dashboard · Findings · Graph · Timeline · Reports]
            C[Components<br/>Modals · Command palette · Charts]
        end
        S[(🗃️ Zustand store)]
        DB[(💾 IndexedDB<br/>cases · captures · runs · audit)]
        subgraph W["⚙️ Web Worker (analysis engine)"]
            direction LR
            V[Validate<br/>& hash] --> PA[Dissect<br/>pcap.ts]
            PA --> FL[Flows & hosts<br/>flows.ts]
            FL --> DT[Detectors<br/>detectors.ts]
            DT --> IF[Isolation Forest<br/>iforest.ts]
            IF --> CO[Correlate & score<br/>correlate.ts]
        end
    end
    NET[☁️ Netlify CDN<br/>static files only]

    NET -- "HTML / JS / CSS" --> UI
    UI <--> S
    S <--> DB
    S -- "capture bytes" --> W
    W -- "results + progress" --> S

    style Browser fill:#0b101c,stroke:#334155,color:#e2e8f0
    style W fill:#1e1b4b,stroke:#818cf8,color:#e0e7ff
    style UI fill:#082f49,stroke:#38bdf8,color:#e0f2fe
    style NET fill:#134e4a,stroke:#2dd4bf,color:#ccfbf1
```

> [!NOTE]
> The only network traffic is downloading the site itself from Netlify (plus optional Google Fonts). Capture data never crosses the network.

### 🔄 Analysis pipeline, step by step

```mermaid
sequenceDiagram
    autonumber
    actor A as 👤 Analyst
    participant UI as 🎨 React UI
    participant ST as 🗃️ Store / IndexedDB
    participant WK as ⚙️ Web Worker

    A->>UI: Drop capture.pcapng
    UI->>UI: Check extension & size limit
    UI->>WK: hash(buffer)
    WK-->>UI: SHA-256 + format (magic bytes)
    alt Not a PCAP/PCAPNG
        UI-->>A: ❌ Rejected — file not stored
    else Valid capture
        UI->>ST: Save capture bytes + metadata
        UI->>WK: analyze(buffer, config)
        loop Progress updates
            WK-->>UI: stage + % (parse → flows → detect → correlate)
        end
        WK-->>UI: Packets · flows · hosts · findings · incidents
        UI->>ST: Persist run + audit event
        UI-->>A: 📊 Overview & findings
    end
```

---

## 🔬 How a capture becomes findings

```mermaid
flowchart LR
    subgraph L1["1️⃣ Ingest"]
        A1[PCAP / PCAPNG] --> A2[Magic bytes<br/>a1b2c3d4 · 0a0d0d0a]
        A2 --> A3[SHA-256<br/>provenance]
    end
    subgraph L2["2️⃣ Dissect"]
        B1[L2: Ethernet · VLAN · SLL]
        B2[L3: IPv4 · IPv6 · ARP]
        B3[L4: TCP · UDP · ICMP]
        B4[L7: DNS · TLS · HTTP · SSH]
        B1 --> B2 --> B3 --> B4
    end
    subgraph L3["3️⃣ Reconstruct"]
        C1[Bidirectional flows]
        C2[Host profiles]
        C3[Passive DNS / SNI names]
    end
    subgraph L4["4️⃣ Detect"]
        D1[🎯 14 Rules]
        D2[📊 Statistical baseline]
        D3[🌲 Isolation Forest]
    end
    subgraph L5["5️⃣ Explain"]
        E1[Structured explanation]
        E2[Incident correlation]
        E3[Risk priority]
    end
    A3 --> B1
    B4 --> C1 --> C2
    B4 --> C3
    C2 --> D1 & D2 & D3
    D1 & D2 & D3 --> E1 --> E2 --> E3
```

### 🔀 Flow reconstruction & connection states

Packets are grouped into **bidirectional flows** using a canonical 5-tuple (`proto : endpointA <-> endpointB`). A new flow starts after the idle timeout (default 120 s) or when a fresh SYN reuses a closed port pair. TCP flows get a Zeek-style state:

```mermaid
stateDiagram-v2
    direction LR
    [*] --> SYN_sent: SYN from initiator
    SYN_sent --> S0: no reply
    SYN_sent --> REJ: RST from responder
    SYN_sent --> HALF: SYN-ACK, no final ACK
    HALF --> S1: initiator ACK
    SYN_sent --> S1: SYN-ACK + ACK
    S1 --> SF: FIN (clean close)
    S1 --> RST: RST after establishment
    S0 --> [*]
    REJ --> [*]
    SF --> [*]
    RST --> [*]

    note right of S0
        S0 · REJ · HALF count as
        failed connections
    end note
```

---

## 🔍 Detection Engine

Detection is **layered**: transparent rules first, then statistical baselines, then an unsupervised model. Each layer's signal is kept separate, and each layer can be switched off in **Detection Settings**.

```mermaid
flowchart TB
    F[(Flows · Hosts · Packets)] --> R & S & M

    subgraph R["🎯 Rule layer — exact, explainable"]
        R1[Port scan / sweep]
        R2[DNS anomaly / tunnelling]
        R3[Beaconing]
        R4[Burst / SYN flood]
        R5[Outbound transfer]
        R6[ARP spoofing]
        R7[Lateral movement]
        R8[+ 7 more]
    end
    subgraph S["📊 Statistical layer"]
        S1[Robust z-score<br/>median / MAD of host egress]
    end
    subgraph M["🌲 Model layer"]
        M1[Isolation Forest<br/>100 trees · seed 42]
        M2[Path-based feature attribution]
        M1 --> M2
    end

    R & S & M --> X{{🧩 Correlation<br/>shared entities + time window}}
    X --> P[⚖️ Risk priority 0–100]
    P --> Q[🚨 Prioritised findings & incidents]

    style R fill:#052e16,stroke:#34d399,color:#d1fae5
    style S fill:#1e1b4b,stroke:#818cf8,color:#e0e7ff
    style M fill:#4a044e,stroke:#e879f9,color:#fae8ff
    style Q fill:#4c0519,stroke:#fb7185,color:#ffe4e6
```

### 📋 Detector catalogue

| Detector | Layer | Looks for | ATT&CK (hypothesis) |
|---|:-:|---|:-:|
| `rule_port_scan` | 🎯 | Many ports on one host (sliding window) or one port on many hosts | T1046 |
| `rule_failed_connections` | 🎯 | Many S0 / REJ / half-open attempts from one source | T1046, T1110 |
| `rule_icmp_sweep` | 🎯 | Echo requests to many hosts | T1018 |
| `rule_dns_anomaly` | 🎯 | NXDOMAIN ratio, long / high-entropy labels, unique-subdomain bursts | T1071.004, T1568.002, T1048 |
| `rule_beacon_periodicity` | 🎯 | Low-jitter repeated connections (bulk transfers excluded from timing) | T1071.001, T1041 |
| `rule_traffic_burst` | 🎯 | Packets-per-second bursts; SYN-dominated → possible flood | T1498, T1499 |
| `rule_outbound_transfer` | 🎯 | Large internal → external egress per destination | T1048, T1041 |
| `rule_tcp_flag_anomaly` | 🎯 | SYN+FIN, Xmas, NULL flag packets | T1046 |
| `rule_protocol_port_mismatch` | 🎯 | TLS / HTTP / SSH / DNS on unexpected ports | T1571, T1572 |
| `rule_cleartext_credentials` | 🎯 | HTTP Basic, FTP / POP3 / IMAP / SMTP auth, Telnet (values never stored) | T1040 |
| `rule_arp_spoofing` | 🎯 | One IP claimed by several MACs; unsolicited ARP storms | T1557.002 |
| `rule_lateral_movement` | 🎯 | Internal fan-out on SMB / RDP / SSH / WinRM / RPC | T1021 |
| `rule_fan_in` | 🎯 | Many sources converging on one destination | T1498 |
| `rule_suspicious_port` | 🎯 | Answered sessions to backdoor / IRC / Tor ports | T1571 |
| `stat_host_volume_outlier` | 📊 | Host egress far above the capture's median host | — |
| `ml_isolation_forest_flow` | 🌲 | Flows the Isolation Forest isolates unusually fast | — |

> [!WARNING]
> Every detector documents its **blind spots** (for example, legitimate vulnerability scanners resemble port scans, and NTP is periodic by design). These caveats appear in the UI, in every finding and in every report.

---

## 🧠 Explainability by Design

Each finding separates **what the capture shows**, **why it fired** and **what it might mean**:

```mermaid
flowchart TB
    F["🚨 <b>Finding</b><br/>Possible vertical port scan: 10.10.0.23 → 10.10.0.5"]
    F --> O["👁️ <b>Observed facts</b><br/>32 distinct ports in 1.9 s · 27 RST replies"]
    F --> R["🎯 <b>Rule evidence</b><br/>distinct ports (32) ≥ threshold (12) in 15 s window"]
    F --> M["🌲 <b>Model signal</b><br/>relative score, not a probability"]
    O & R & M --> I["💡 <b>Interpretation</b> (hypothesis)<br/>consistent with service discovery"]
    I --> AL["🔀 <b>Alternatives</b><br/>authorised scan · inventory · monitoring"]
    I --> N["✅ <b>Next checks</b><br/>confirm source role · review open ports"]
    I --> LI["⚠️ <b>Limitations</b><br/>single vantage point · capture may be incomplete"]

    style F fill:#4c0519,stroke:#fb7185,color:#fff
    style O fill:#052e16,stroke:#34d399,color:#fff
    style R fill:#422006,stroke:#fbbf24,color:#fff
    style M fill:#4a044e,stroke:#e879f9,color:#fff
    style I fill:#082f49,stroke:#38bdf8,color:#fff
```

### ⚖️ Risk priority formula

```
Priority = 100 × (w₁·Severity + w₂·Anomaly + w₃·Evidence + w₄·Corroboration + w₅·Context) / Σw
```

| Component | Meaning | Default weight |
|---|---|:-:|
| **Severity** | Potential impact if the hypothesis is true | 0.35 |
| **Anomaly** | How unusual the related flows are (model / statistical) | 0.15 |
| **Evidence** | How many packets and flows support the claim, and how complete they are | 0.20 |
| **Corroboration** | Independent detectors in the same incident | 0.20 |
| **Context** | Critical asset → internal host → external host | 0.10 |

> Priority is a **ranking aid, not a calibrated probability**. Weights are editable, and every component is shown next to the score.

### 🧩 Incident correlation

```mermaid
flowchart LR
    F1[NSX-0001<br/>ICMP sweep] -- shared host<br/>10.10.0.23 --> F2[NSX-0002<br/>Port scan]
    F2 -- shared host --> F3[NSX-0003<br/>Lateral SMB]
    F3 -- shared host --> F4[NSX-0004<br/>Beaconing]
    F4 -- shared C2 IP --> F5[NSX-0005<br/>14 MB exfiltration]
    F1 & F2 & F3 & F4 & F5 --> INC{{🧩 INC-001<br/>Multi-stage activity<br/>Discovery → Lateral Movement →<br/>C2 → Exfiltration}}

    style INC fill:#312e81,stroke:#818cf8,color:#fff
```

Findings are grouped with **union-find** when they share an entity within the correlation window (default 30 min). Each incident shows **why** it was grouped, and analysts can **split or merge** incidents, with every change logged.

### 🔁 Finding lifecycle (analyst triage)

```mermaid
stateDiagram-v2
    [*] --> New: raised by detector
    New --> UnderReview: analyst opens
    New --> BenignFP: dismiss
    UnderReview --> Suspicious: confirm
    UnderReview --> BenignFP: dismiss
    Suspicious --> Escalated: escalate
    Suspicious --> BenignFP: rule out
    Escalated --> [*]: exported in report
    BenignFP --> [*]: kept for audit,<br/>hidden from reports by default
```

> Dispositions **carry forward** when you re-run the analysis with new settings.

---

## 🗺️ The Workspace

```mermaid
mindmap
  root((NetSentry XAI))
    Investigation
      Case Dashboard
      PCAP Ingestion
      Analysis Overview
      Findings Explorer
      Incidents
    Evidence
      Packets & Flows
        display filters
        hex dump
      Host Network Graph
      Incident Timeline
      Evidence Assistant
      PCAP Diff
    Case & Lab
      Notes & Audit Trail
      Reports
        PDF / HTML
        JSON / CSV
        STIX 2.1
      Evaluation Lab
      Detection Settings
      System Diagnostics
```

**Power-user extras:** `Ctrl/⌘ + K` command palette · saved filters · bulk triage · display filters such as `ip:10.0.0.5 port:443 proto:tls state:S0` · case bundle export/import.

---

## 🧪 Demo Captures & Evaluation

All demo traffic in `public/samples/` is **synthetic** and labelled as such.

| Capture | Type | What's inside |
|---|:-:|---|
| `enterprise_multistage_intrusion.pcap` | 🔴 | 15-minute office capture: drive-by download, TLS beaconing, ICMP sweep, port scan, SMB lateral movement, DNS tunnelling, 14 MB exfiltration, ARP spoofing, Xmas probes, cleartext FTP & Telnet |
| `office_baseline_benign.pcapng` | 🟢 | Benign office traffic in PCAPNG format with IPv6, used as a baseline for PCAP Diff |
| `port_scan_recon.pcap` | 🔴 | Vertical SYN scan across 25 ports |
| `dns_tunneling_anomaly.pcap` | 🔴 | High-entropy DNS labels with NXDOMAIN replies |
| `c2_beaconing.pcap` | 🔴 | Six heartbeats exactly 2 s apart |
| `syn_flood_burst.pcap` | 🔴 | 260 SYNs to one host in one second |
| `benign_web_browsing.pcap` | 🟢 | One DNS lookup and an HTTP fetch |

Regenerate the synthetic captures with `npm run samples`.

```mermaid
flowchart LR
    S[(7 labelled<br/>captures)] --> R1[Rules only]
    S --> R2[Anomaly only]
    S --> R3[Hybrid]
    R1 & R2 & R3 --> MET[📈 Precision · Recall · F1<br/>false-alarm rate · latency]
    MET --> EXP[💾 Export JSON]
```

The **Evaluation Lab** runs these scenarios live in your browser. On the bundled synthetic set, rules-only and hybrid modes fire every expected detector with no unexpected rule alerts, and anomaly-only mode is noticeably noisier. These are synthetic results: run your own labelled captures before drawing real-world conclusions.

---

## ☁️ Deploy to Netlify

```mermaid
flowchart LR
    subgraph A["Option A — Git (recommended)"]
        A1[Push to GitHub] --> A2[Netlify: Import project] --> A3[Auto build<br/>npm run build]
    end
    subgraph B["Option B — Drag & drop"]
        B1[Open app.netlify.com/drop] --> B2[Drop the dist/ folder]
    end
    subgraph C["Option C — CLI"]
        C1[npm run build] --> C2[netlify deploy --prod --dir=dist]
    end
    A3 & B2 & C2 --> LIVE([🌍 Live site])
    style LIVE fill:#134e4a,stroke:#2dd4bf,color:#fff
```

Everything is pre-configured in **`netlify.toml`**:

| Setting | Value |
|---|---|
| Build command | `npm run build` |
| Publish directory | `dist` |
| Node version | 20 |
| SPA routing | `/* → /index.html (200)` |
| Security headers | CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, `Permissions-Policy` |

```bash
# CLI deploy
npm install
npm run build
npx netlify-cli deploy --prod --dir=dist
```

---

## 📁 Project Structure

```
netsentry-xai/
├── 📄 netlify.toml              # Build, SPA redirect, security headers
├── 📄 package.json
├── 📂 public/
│   ├── favicon.svg
│   ├── _redirects
│   └── 📂 samples/              # Synthetic demo captures
├── 📂 scripts/
│   └── generate-samples.mjs     # Synthetic PCAP/PCAPNG generator
└── 📂 src/
    ├── 📂 engine/               # ⚙️ Analysis engine (runs in Web Worker)
    │   ├── pcap.ts              #    PCAP/PCAPNG reader + protocol dissectors
    │   ├── flows.ts             #    Flow reconstruction, host profiles, passive DNS
    │   ├── detectors.ts         #    14 rules + statistical + Isolation Forest wrapper
    │   ├── iforest.ts           #    Seeded Isolation Forest + attribution
    │   ├── correlate.ts         #    Incident correlation + risk scoring
    │   ├── pipeline.ts          #    End-to-end orchestration + summary
    │   ├── worker.ts            #    Web Worker entry (hash + analyse)
    │   ├── config.ts            #    Default thresholds & weights
    │   └── types.ts             #    Shared data contracts
    ├── 📂 store/                # 🗃️ Zustand state + IndexedDB persistence
    ├── 📂 lib/                  # 🧰 Reports, assistant, diff, formatting, samples
    ├── 📂 components/           # 🎨 Shell, modals, command palette, UI kit
    └── 📂 pages/                # 📄 Landing + 15 workspace pages
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| UI | React 18 · TypeScript 5 · Vite 5 · Tailwind CSS 3 |
| State & storage | Zustand · IndexedDB (fallback to memory) |
| Charts & graph | Recharts · d3-force |
| Icons | Lucide |
| Analysis | Custom TypeScript dissectors · Isolation Forest · WebCrypto SHA-256 |
| Concurrency | Web Worker (ES module) |
| Hosting | Netlify (static) |

---

## 🔒 Security & Privacy

```mermaid
flowchart LR
    U[📁 Your capture] --> B[🖥️ Your browser]
    B --> W[⚙️ Web Worker<br/>bounds-checked parsing]
    W --> I[(💾 IndexedDB<br/>this browser only)]
    I -. one-click delete .-> X[🗑️ Purged]
    B -. ✖ never sent .-> S[☁️ Any server]
    style S fill:#4c0519,stroke:#fb7185,color:#fff,stroke-dasharray: 5 5
    style I fill:#052e16,stroke:#34d399,color:#fff
```

- ✅ **Local-first:** no backend, no telemetry, no third-party enrichment
- ✅ **Untrusted-input handling:** bounds-checked parsing, size and packet limits; malformed packets are recorded, not dropped
- ✅ **Chain of custody:** SHA-256 on every capture; config hash and engine versions on every run
- ✅ **Credentials never stored:** cleartext logins are flagged with their values redacted
- ✅ **Read-only:** never blocks traffic or changes infrastructure
- ✅ **Retention control:** delete per capture or per case, or purge everything from *System Diagnostics*
- ✅ **Strict CSP** and security headers via `netlify.toml`

---

## 📌 Honest-Uncertainty Principles

> [!CAUTION]
> - Scores are **relative indicators**, not probabilities of compromise.
> - **Evidence confidence** is reported separately from **severity**.
> - ATT&CK mappings are **hypotheses**, never attribution.
> - **Absence of a finding does not prove absence of activity**: captures can be incomplete or encrypted.
> - Analyse only traffic you are **authorised** to inspect.

---

<div align="center">

**NetSentry XAI** — *the strength is not the number of AI features, it is the link between every AI-assisted claim and concrete network evidence.*

⭐ If this project helped you, consider starring the repository.

</div>
