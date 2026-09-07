# OneWaySentinel AI

### AI-Powered Passive Cyber Threat Detection for Unidirectional IP Traffic

> **Transforming passive, one-way network observations into actionable and explainable cyber threat intelligence — without establishing a communication path back to the production network.**

---

## 🛡️ Overview

**OneWaySentinel AI** is an AI-assisted passive network threat detection and intelligence platform designed for high-security and critical-infrastructure environments where network traffic can flow **only into a dedicated monitoring environment**.

The system is designed around a strict **unidirectional monitoring architecture**. Traffic is passively collected from a one-way network tap, data diode, mirrored gateway link, or equivalent monitoring interface and analysed inside an isolated monitoring enclave.

The monitoring system does **not** initiate probes, complete active handshakes, reconnect to observed hosts, or transmit mitigation commands into the production network.

The platform analyses passive traffic characteristics, extracts behavioural features, identifies anomalous patterns, classifies potential threats, assigns threat scores, and presents evidence-based alerts through a security visualization dashboard.

---

## 🎯 Problem Statement

Conventional network security monitoring can become challenging in environments where the monitoring infrastructure itself must remain isolated from production systems.

Critical environments such as:

- Power and energy infrastructure
- Industrial control environments
- Government networks
- Defence infrastructure
- High-security enterprise networks
- Sensitive operational networks

may require monitoring systems that can observe network behaviour without creating an additional communication path into the protected environment.

This creates a key challenge:

> **How can cyber threats be detected and analysed when the security system is allowed to observe traffic but cannot actively communicate with the production network?**

OneWaySentinel AI addresses this challenge through **passive traffic intelligence and unidirectional analysis**.

---

## 💡 Proposed Solution

The proposed architecture follows the pipeline:

```text
                    PRODUCTION NETWORK
                           │
                           │
                    ONE-WAY TRAFFIC
                           │
                           ▼
                  ┌───────────────────┐
                  │  DATA DIODE /     │
                  │  PASSIVE TAP      │
                  └─────────┬─────────┘
                            │
                            ▼
                ┌────────────────────────┐
                │ PASSIVE MONITORING     │
                │ ENCLAVE                │
                └───────────┬────────────┘
                            │
                            ▼
                ┌────────────────────────┐
                │ FEATURE EXTRACTION      │
                │                        │
                │ Flow / Packet /        │
                │ Temporal / Statistical │
                │ Features               │
                └───────────┬────────────┘
                            │
                            ▼
                ┌────────────────────────┐
                │ AI / ML DETECTION       │
                │ ENGINE                  │
                └───────────┬────────────┘
                            │
                            ▼
                ┌────────────────────────┐
                │ THREAT CLASSIFICATION  │
                │ & SCORING              │
                └───────────┬────────────┘
                            │
                            ▼
                ┌────────────────────────┐
                │ EVIDENCE-BASED ALERTS  │
                └───────────┬────────────┘
                            │
                            ▼
                ┌────────────────────────┐
                │ SECURITY VISUALIZATION │
                │ DASHBOARD              │
                └────────────────────────┘

Threat Detection Capabilities

The initial system focuses on two major threat categories.

1. Volumetric & Protocol-Based DDoS Detection

The detection pipeline is designed to identify behavioural characteristics associated with:

SYN Flood
UDP Flood
UDP Reflection / Amplification
Spoofed-Source Flood
Abnormal volumetric traffic bursts

Potential detection features include:

Packets per second (PPS)
Bytes per second (BPS)
Protocol distribution
Unique source count
Source-IP entropy
Destination concentration
SYN/ACK behavioural ratios where observable
Packet-size characteristics
Flow-level rate statistics

Example:

Normal Traffic
      │
      ▼
Baseline Behaviour
      │
      ▼
Significant Traffic Deviation
      │
      ▼
Feature Analysis
      │
      ▼
DDoS Classification
      │
      ▼
Severity + Confidence + Evidence
2. Botnet C2 Beacon Detection

OneWaySentinel AI also analyses temporal traffic behaviour to identify potential command-and-control beaconing.

The detection approach considers:

Periodic communication patterns
Inter-arrival time (IAT)
Repeated destination connections
Connection frequency
Temporal consistency
Destination concentration
Packet-size consistency
Behavioural deviations from baseline traffic

A simplified beaconing pattern can be represented as:

Client
  │
  ├──────► Destination
  │          ↑
  ├──────►   │
  │          │ Regular interval
  ├──────►   │
  │          │
  └──────►   │

Repeated communication at suspiciously consistent temporal intervals can be used as an indicator for further investigation.

🧠 AI / ML Architecture

The planned detection architecture combines supervised and unsupervised techniques.

Supervised Detection

Potential models:

Random Forest
XGBoost

These models can be trained on labelled network-security datasets to classify known traffic patterns.

Example classification categories:

NORMAL
SYN_FLOOD
UDP_FLOOD
UDP_AMPLIFICATION
SPOOFED_SOURCE_FLOOD
Unsupervised Anomaly Detection

Isolation Forest is planned for identifying anomalous traffic behaviour that may not correspond to previously labelled attack classes.

This provides an additional detection layer for previously unseen or insufficiently represented behaviours.

Statistical & Temporal Analysis

Machine-learning predictions can be complemented by statistical verification, including:

Source-IP entropy
Traffic-rate deviation
Inter-arrival statistics
Periodicity analysis
Destination concentration
Behavioural baselines

The goal is to reduce dependence on a single detection technique and improve explainability.

📊 Threat Scoring

Rather than producing a simple binary alert, the system is designed to generate contextual threat intelligence.

Each detection can contain:

Threat Type
Severity
Confidence Score
Source
Destination
Protocol
Detection Method
Supporting Evidence
Timestamp
Relevant Features

Example:

THREAT: SYN FLOOD

Severity: CRITICAL
Confidence: 96%

Evidence:
• Significant increase in SYN traffic
• Abnormal packet rate
• Large number of unique sources
• Elevated source-IP entropy
• Target concentration detected

This approach allows analysts to understand why traffic was classified as suspicious.

🖥️ Security Visualization Dashboard

The prototype includes a security-oriented visualization layer designed to provide a centralized view of passive network intelligence.

Current dashboard concepts include:
Security overview
Live/simulated traffic monitoring
Threat monitoring
DDoS detection
C2 beacon detection
Passive data ingestion
Threat queue
Alert investigation
Feature telemetry
Threat severity
AI confidence
Evidence visualization
Passive architecture status

The dashboard is designed to make complex network telemetry easier to interpret during real-time monitoring and investigation.

🧩 Technology Stack
AI / Machine Learning
Python
Scikit-learn
Random Forest
XGBoost
Isolation Forest
Network Analysis
Scapy
PyShark
PCAP processing
NetFlow
IPFIX
Flow-level feature extraction
Backend
FastAPI
REST API
WebSocket
Python-based detection services
Frontend
React
Next.js
TypeScript
Interactive visualization components
Data Storage
Prototype
SQLite
Scalable Deployment
PostgreSQL
🔬 Data & Research

The system is intended to be evaluated using a combination of labelled security datasets, public network traces, PCAP files and controlled synthetic traffic.

Potential datasets include:

CIC-DDoS
CICIDS
UNSW-NB15
CTU-13 Botnet Dataset
Public PCAP datasets
Public network-flow datasets
Controlled synthetic traffic

Research areas include:

Passive network traffic analysis
ML-based intrusion detection
DDoS detection using flow statistics
Source-IP entropy analysis
Botnet C2 detection
Temporal network analysis
Periodicity-based anomaly detection
Network-flow anomaly detection
🏗️ Current Prototype Status

The current implementation represents the Initial Prototype / Proof of Concept stage.

Implemented / Demonstrated
 Passive monitoring architecture
 One-way network security concept
 Monitoring-enclave workflow
 Synthetic passive traffic generation
 Traffic visualization
 DDoS detection workflow
 SYN flood scenario
 UDP flood scenario
 UDP reflection/amplification scenario
 Spoofed-source flood scenario
 C2 beaconing detection workflow
 Periodicity-based analysis concept
 Threat classification
 Threat severity
 Confidence scoring
 Evidence-based alerts
 Security dashboard
 Passive data-ingestion interface
 PCAP / CSV / JSON / JSONL ingestion design
🚧 Development Roadmap

The project is being developed incrementally.

Phase 1 — Prototype Validation
Synthetic Traffic
        ↓
Feature Simulation
        ↓
Detection Workflow
        ↓
Threat Scoring
        ↓
Dashboard

Status: Prototype implemented

Phase 2 — Real Passive Data Processing
PCAP / Flow Records
        ↓
Packet / Flow Parsing
        ↓
Feature Extraction
        ↓
Feature Normalization
        ↓
Detection Engine

Planned integration with:

Scapy
PyShark
PCAP processing
NetFlow/IPFIX
Phase 3 — ML Detection Engine

Implement and evaluate:

Random Forest
XGBoost
Isolation Forest
Statistical verification
Temporal C2 analysis

Evaluation metrics will include:

Accuracy
Precision
Recall
F1-score
False-positive rate
Detection latency
Phase 4 — Real-Time Streaming

The future architecture will support continuous passive telemetry:

Passive Traffic
      ↓
Streaming Ingestion
      ↓
Feature Extraction
      ↓
ML Inference
      ↓
Threat Scoring
      ↓
WebSocket
      ↓
Real-Time Dashboard
Phase 5 — Validation & Deployment

Future validation will include:

Benchmark datasets
Controlled attack simulations
PCAP replay
Detection latency measurement
False-positive analysis
Model comparison
Scalability testing
Security hardening
🔐 Security & Design Principles

OneWaySentinel AI follows several security-oriented design principles.

Passive by Design

The detection layer should analyse observed traffic without actively probing network endpoints.

No Return Path

The monitoring environment should not require a communication channel back into the protected production network.

Explainable Detection

Alerts should include supporting evidence rather than relying only on a model prediction.

Modular Architecture

Traffic ingestion, feature extraction, detection, scoring and visualization are separated into modular components.

Defence in Depth

Multiple analytical approaches can complement each other:

ML Classification
        +
Anomaly Detection
        +
Statistical Analysis
        +
Temporal Analysis
        ↓
Threat Intelligence
Forensic Awareness

Observed traffic and derived features can be retained as evidence for subsequent investigation and analysis.

⚠️ Current Limitations

The current prototype is not yet a production-grade network security appliance.

Current limitations include:

Synthetic traffic is used for initial prototype demonstration.
Full-scale real-time PCAP processing is part of the next development phase.
Production ML models require training and validation using appropriate datasets.
Detection performance must be benchmarked before deployment.
Encrypted traffic limits payload-level inspection; therefore, behavioural and metadata-based analysis is emphasized.
Real-world deployment requires appropriate data-diode/tap infrastructure and operational security controls.

The project deliberately distinguishes between prototype functionality and future production capabilities.

🔮 Future Enhancements

Planned improvements include:

Real PCAP ingestion
NetFlow/IPFIX ingestion
Automated feature extraction
Trained ML models
Real-time streaming detection
Adaptive behavioural baselines
Advanced C2 detection
Multi-stage threat correlation
Model explainability
Threat-intelligence enrichment
Large-scale distributed processing
Historical forensic analysis
Containerized deployment
Production-grade PostgreSQL storage
Model performance monitoring
🧪 Example Detection Workflow
Passive Traffic
      │
      ▼
Flow Aggregation
      │
      ▼
Feature Extraction
      │
      ├───────────────┐
      │               │
      ▼               ▼
DDoS Analysis     C2 Analysis
      │               │
      ▼               ▼
ML Classification  Temporal Analysis
      │               │
      └───────┬───────┘
              ▼
       Anomaly Detection
              │
              ▼
       Threat Correlation
              │
              ▼
        Threat Scoring
              │
              ▼
      Evidence Generation
              │
              ▼
      Security Dashboard
📈 Expected Outcomes

OneWaySentinel AI aims to provide:

Passive cyber-threat detection
Early identification of abnormal traffic
DDoS classification
Botnet C2 beacon identification
Explainable threat intelligence
Evidence-based security alerts
Behavioural anomaly detection
Reduced monitoring-network exposure
A scalable foundation for critical-infrastructure security monitoring
🚀 Vision

Build a cyber-threat intelligence layer that can see the attack, understand the behaviour, explain the evidence — while remaining physically and logically separated from the network it protects.

OneWaySentinel AI is ultimately intended to demonstrate that effective network threat detection does not necessarily require active access to the network being monitored.
