import {
  NetworkPacket,
  SecurityAlert,
  TelemetryMetrics,
  TrafficTimePoint,
  ThreatType,
  SimulationScenario,
  C2BeaconCandidate,
  ThreatIntelligenceRecord,
  DDoSMetricData
} from '../types';

export const SIMULATION_SCENARIOS: SimulationScenario[] = [
  {
    id: 'baseline',
    name: 'Normal Enterprise Baseline',
    category: 'Baseline',
    description: 'Routine corporate network ingress: HTTPS microservices, DNS resolutions, and TLS telemetry. No active anomalies detected.',
    targetService: 'All Ingress Nodes',
    trafficMultiplier: 1.0,
    activeThreat: null
  },
  {
    id: 'syn-flood',
    name: 'SYN Flood Volumetric Attack',
    category: 'DDoS',
    description: 'High-frequency TCP SYN packet burst targeting public-facing Web VIP (192.168.10.45:443) without completing 3-way handshakes.',
    targetService: 'Web Application VIP (192.168.10.45:443)',
    trafficMultiplier: 4.8,
    activeThreat: 'SYN Flood'
  },
  {
    id: 'udp-amplification',
    name: 'NTP/DNS UDP Reflection & Amplification',
    category: 'DDoS',
    description: 'Reflected volumetric attack leveraging misconfigured external NTP/DNS servers with an amplification ratio > 55x targeting core DB proxy.',
    targetService: 'Core DB Gateway (192.168.20.10:5432)',
    trafficMultiplier: 6.2,
    activeThreat: 'UDP Reflection/Amplification'
  },
  {
    id: 'spoofed-source',
    name: 'Distributed Spoofed-Source Flood',
    category: 'DDoS',
    description: 'High-entropy packet burst utilizing forged bogon source IPs to exhaust enclave state tables and confuse flow reassembly.',
    targetService: 'API Gateway (192.168.10.1:8080)',
    trafficMultiplier: 5.5,
    activeThreat: 'Spoofed-Source Flood'
  },
  {
    id: 'c2-beacon',
    name: 'Stealth Botnet C2 Beaconing (Cobalt Strike)',
    category: 'C2',
    description: 'Low-and-slow periodic TLS heartbeats with low jitter (45s ± 3%) to external rogue IP, mimicking legitimate user analytics.',
    targetService: 'Internal Workstation WS-092 (10.0.4.118)',
    trafficMultiplier: 1.2,
    activeThreat: 'Botnet C2 Beaconing'
  },
  {
    id: 'traffic-anomaly',
    name: 'High-Velocity Protocol Anomaly & Port Scan',
    category: 'Anomaly',
    description: 'Sudden divergence in protocol distribution with abnormal non-standard port traffic and high packet inter-arrival burst variance.',
    targetService: 'Internal Subnet 10.0.4.0/24',
    trafficMultiplier: 2.5,
    activeThreat: 'General Traffic Anomaly'
  }
];

export const INITIAL_C2_BEACONS: C2BeaconCandidate[] = [
  {
    id: 'c2-01',
    sourceIp: '10.0.4.118',
    destinationC2: '185.220.101.42',
    c2Domain: 'cdn-cloudsync-telemetry.org',
    periodicitySeconds: 45.2,
    jitterPercentage: 3.4,
    confidenceScore: 94,
    ja3Hash: 'a0e9f5d64349fb13191bc781f81f42e1',
    knownMalwareFamily: 'Cobalt Strike (Malleable C2)',
    beaconCount: 142,
    firstSeen: '2026-09-03 04:12:08 UTC',
    lastSeen: '2026-09-03 07:58:33 UTC',
    status: 'Confirmed Beacon',
    fftPeakPower: 0.92
  },
  {
    id: 'c2-02',
    sourceIp: '10.0.8.44',
    destinationC2: '91.240.118.89',
    c2Domain: 'updates.system-diagnostic-api.net',
    periodicitySeconds: 120.0,
    jitterPercentage: 5.1,
    confidenceScore: 89,
    ja3Hash: '72c03fb41f1737e6f3e180860e517300',
    knownMalwareFamily: 'Sliver C2 Framework',
    beaconCount: 58,
    firstSeen: '2026-09-03 06:30:15 UTC',
    lastSeen: '2026-09-03 07:59:12 UTC',
    status: 'Confirmed Beacon',
    fftPeakPower: 0.86
  },
  {
    id: 'c2-03',
    sourceIp: '10.0.12.203',
    destinationC2: '194.38.20.15',
    c2Domain: 'dga-x8892-relay.cc',
    periodicitySeconds: 300.5,
    jitterPercentage: 12.8,
    confidenceScore: 78,
    ja3Hash: 'b384631043b380f8164e864164f331bb',
    knownMalwareFamily: 'IcedID / BokBot Loader',
    beaconCount: 24,
    firstSeen: '2026-09-03 07:10:00 UTC',
    lastSeen: '2026-09-03 07:56:44 UTC',
    status: 'Suspected',
    fftPeakPower: 0.74
  }
];

export const INITIAL_INTEL_RECORDS: ThreatIntelligenceRecord[] = [
  {
    id: 'ioc-101',
    iocValue: '185.220.101.42',
    iocType: 'IPv4',
    threatActor: 'APT29 / Cozy Bear Affiliate',
    threatType: 'Botnet C2 Beaconing',
    confidenceScore: 97,
    firstReported: '2026-08-14',
    mitreTactics: ['T1071.001 - Web Protocols', 'T1573 - Encrypted Channel', 'T1008 - Fallback Channels'],
    cveReferences: ['CVE-2024-3400', 'CVE-2023-46805'],
    reputationSource: 'AlienVault OTX & Mandiant Intel',
    maliciousActivitySummary: 'Known active staging server for Cobalt Strike Team Server infrastructure. Utilizes randomized URIs mimicking jquery CDN scripts.'
  },
  {
    id: 'ioc-102',
    iocValue: '45.154.255.88',
    iocType: 'IPv4',
    threatActor: 'Mirai IoT / Reaper Botnet Cluster',
    threatType: 'UDP Flood',
    confidenceScore: 92,
    firstReported: '2026-08-28',
    mitreTactics: ['T1498.001 - Direct Network Flood', 'T1499.004 - Application Exploitation'],
    cveReferences: ['CVE-2023-1389', 'CVE-2022-26186'],
    reputationSource: 'AbuseIPDB (Confidence 100%)',
    maliciousActivitySummary: 'Originating botnet reflection node. Frequently floods DNS root resolvers and private infrastructure with massive NTP monlist amplification.'
  },
  {
    id: 'ioc-103',
    iocValue: 'cdn-cloudsync-telemetry.org',
    iocType: 'Domain',
    threatActor: 'ShadowPad / Storm-0558 Affiliate',
    threatType: 'Botnet C2 Beaconing',
    confidenceScore: 95,
    firstReported: '2026-08-30',
    mitreTactics: ['T1568.002 - Domain Generation Algorithms', 'T1071 - Application Layer Protocol'],
    cveReferences: ['CVE-2023-38831'],
    reputationSource: 'CISA Automated Indicator Sharing (AIS)',
    maliciousActivitySummary: 'Fast-flux C2 domain utilizing dynamic DNS providers to bypass static perimeter blocklists. High entropy name scoring.'
  },
  {
    id: 'ioc-104',
    iocValue: 'a0e9f5d64349fb13191bc781f81f42e1',
    iocType: 'JA3_HASH',
    threatActor: 'Generic Cybercrime Syndicates',
    threatType: 'Botnet C2 Beaconing',
    confidenceScore: 89,
    firstReported: '2026-07-22',
    mitreTactics: ['T1071.001 - Web Protocols'],
    cveReferences: [],
    reputationSource: 'SSL Blacklist / abuse.ch',
    maliciousActivitySummary: 'Standard TLS Client Hello fingerprint for default uncustomized Cobalt Strike HTTPS listeners across Linux/Windows endpoints.'
  }
];

export const INITIAL_ALERTS: SecurityAlert[] = [
  {
    id: 'ALT-2026-8812',
    threatType: 'SYN Flood',
    severity: 'Critical',
    confidenceScore: 96,
    timestamp: '2026-09-03 07:59:14 UTC',
    source: '198.51.100.0/24 (Multi-Source Cluster)',
    destination: '192.168.10.45:443 (Prod Web VIP)',
    protocol: 'TCP',
    supportingEvidence: [
      'Abnormal SYN packet rate exceeding 420,000 pps',
      'Sudden traffic surge (9.4x baseline threshold)',
      'SYN/ACK completion ratio collapsed to 0.02% (half-open exhaustion)',
      'Source-IP Shannon entropy measured at 6.94 (high dispersion)'
    ],
    detectionMethod: 'Sliding-Window TCP Flag Ratio & Shannon Entropy Deviation',
    status: 'New',
    packetRate: 428500,
    bandwidthRate: '12.8 Gbps',
    mitreTechnique: 'T1498.001 - Direct Network Flood'
  },
  {
    id: 'ALT-2026-8811',
    threatType: 'Botnet C2 Beaconing',
    severity: 'High',
    confidenceScore: 94,
    timestamp: '2026-09-03 07:58:33 UTC',
    source: '10.0.4.118 (Workstation-Finance-02)',
    destination: '185.220.101.42:443 (Suspicious External IP)',
    protocol: 'TLS',
    supportingEvidence: [
      'Deterministic connection periodicity (interval: 45.2s with ±3.4% jitter)',
      'Consistent payload outbound byte size (fixed 340-byte request frames)',
      'JA3 fingerprint matches known Cobalt Strike malleable C2 profile',
      'Fast Fourier Transform (FFT) detected sharp power spectral peak at 0.022 Hz'
    ],
    detectionMethod: 'Passive FFT Periodicity Analysis & JA3 Hash Correlation',
    status: 'Investigating',
    packetRate: 14,
    bandwidthRate: '4.8 Kbps',
    mitreTechnique: 'T1071.001 - Web Protocols'
  },
  {
    id: 'ALT-2026-8810',
    threatType: 'UDP Reflection/Amplification',
    severity: 'Critical',
    confidenceScore: 95,
    timestamp: '2026-09-03 07:54:20 UTC',
    source: 'Multiple Public NTP Resolvers (Port 123)',
    destination: '192.168.20.10:5432 (Core DB Gateway)',
    protocol: 'UDP',
    supportingEvidence: [
      'Disproportionate inbound UDP frame sizes (average 1,420 bytes)',
      'Originating from port 123 with monlist response flag indicators',
      'Calculated amplification ratio factor: 55.4x compared to baseline',
      'Sudden UDP protocol surge to 78% of aggregate ingress bandwidth'
    ],
    detectionMethod: 'Packet Payload Asymmetry & Amplification Factor Heuristics',
    status: 'Verified',
    packetRate: 310000,
    bandwidthRate: '18.4 Gbps',
    mitreTechnique: 'T1498.002 - Reflection Amplification'
  },
  {
    id: 'ALT-2026-8809',
    threatType: 'Spoofed-Source Flood',
    severity: 'High',
    confidenceScore: 91,
    timestamp: '2026-09-03 07:48:02 UTC',
    source: 'Random Bogon & Unrouted Address Space (0.0.0.0/8, 100.64.0.0/10)',
    destination: '192.168.10.1:8080 (API Gateway)',
    protocol: 'UDP',
    supportingEvidence: [
      'Shannon Source-IP Entropy spiked to 7.82 (near theoretical maximum 8.0)',
      'Non-routable RFC 5735 / bogon IP addresses detected in ingress stream',
      'Zero TCP ACK correlation across all observed ephemeral ports',
      'Enclave flow table allocation rate surpassed 95,000 entries/sec'
    ],
    detectionMethod: 'Shannon Source-IP Entropy Variance & Bogon Validation',
    status: 'New',
    packetRate: 185000,
    bandwidthRate: '6.1 Gbps',
    mitreTechnique: 'T1498 - Network Denial of Service'
  },
  {
    id: 'ALT-2026-8808',
    threatType: 'UDP Flood',
    severity: 'High',
    confidenceScore: 89,
    timestamp: '2026-09-03 07:35:19 UTC',
    source: 'Distributed Botnet Subnets (AS4134, AS4837)',
    destination: '192.168.10.50:53 (Authoritative DNS)',
    protocol: 'UDP',
    supportingEvidence: [
      'Volumetric UDP stream targeting single destination port 53',
      'Truncated malformed DNS queries missing query questions',
      'Packet inter-arrival variance under 0.05ms (machine-generated burst)'
    ],
    detectionMethod: 'Volumetric Rate Anomaly & DNS Query Syntax Inspection',
    status: 'Mitigated',
    packetRate: 145000,
    bandwidthRate: '4.2 Gbps',
    mitreTechnique: 'T1498.001 - Direct Network Flood'
  },
  {
    id: 'ALT-2026-8807',
    threatType: 'General Traffic Anomaly',
    severity: 'Medium',
    confidenceScore: 82,
    timestamp: '2026-09-03 07:20:41 UTC',
    source: '10.0.2.45 (Internal Dev Server)',
    destination: '192.168.30.0/24 (Restricted SCADA Segment)',
    protocol: 'TCP',
    supportingEvidence: [
      'Sequential SYN scans traversing 1,024 TCP ports within 1.2 seconds',
      'Baseline deviation: Node previously only sent HTTPS egress traffic',
      'High destination port entropy index with minimal payload bytes'
    ],
    detectionMethod: 'Isolation Forest Behavioral Profile Divergence',
    status: 'False Positive',
    packetRate: 850,
    bandwidthRate: '48 Kbps',
    mitreTechnique: 'T1046 - Network Service Discovery'
  }
];

// Helper: Calculate Shannon Entropy on a set of IP distribution counts
export function calculateShannonEntropy(counts: number[], total: number): number {
  if (total === 0) return 0;
  let entropy = 0;
  for (const count of counts) {
    if (count > 0) {
      const p = count / total;
      entropy -= p * Math.log2(p);
    }
  }
  return Number(entropy.toFixed(2));
}

// Generate realistic mock packet for the live traffic stream
export function generateSimulatedPacket(scenario: SimulationScenario): NetworkPacket {
  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  const id = 'pkt-' + Math.random().toString(36).substring(2, 9);
  
  if (scenario.id === 'syn-flood') {
    const isAttack = Math.random() < 0.75;
    if (isAttack) {
      const srcSubnet = ['198.51.100.', '203.0.113.', '192.0.2.'][Math.floor(Math.random() * 3)];
      const srcIp = `${srcSubnet}${Math.floor(Math.random() * 254) + 1}`;
      return {
        id,
        timestamp,
        sourceIp: srcIp,
        sourcePort: Math.floor(Math.random() * 60000) + 1025,
        destIp: '192.168.10.45',
        destPort: 443,
        protocol: 'TCP',
        flags: 'SYN',
        length: 64,
        interArrivalTimeMs: Number((Math.random() * 0.1).toFixed(3)),
        shannonEntropy: 7.15,
        isAnomaly: true,
        threatTag: 'SYN Flood',
        payloadSnippet: '0x4500003c... [TCP SYN seq=319028 win=64240]'
      };
    }
  }

  if (scenario.id === 'udp-amplification') {
    const isAttack = Math.random() < 0.7;
    if (isAttack) {
      const ntpServers = ['129.6.15.28', '132.163.96.1', '216.239.35.0', '193.182.111.14'];
      return {
        id,
        timestamp,
        sourceIp: ntpServers[Math.floor(Math.random() * ntpServers.length)],
        sourcePort: 123,
        destIp: '192.168.20.10',
        destPort: 5432,
        protocol: 'NTP',
        length: 1420,
        interArrivalTimeMs: Number((Math.random() * 0.15).toFixed(3)),
        shannonEntropy: 5.4,
        isAnomaly: true,
        threatTag: 'UDP Reflection/Amplification',
        payloadSnippet: '0x1700032a... [NTP monlist payload response x55.4 amp]'
      };
    }
  }

  if (scenario.id === 'spoofed-source') {
    const isAttack = Math.random() < 0.8;
    if (isAttack) {
      const bogons = ['100.64.', '192.0.0.', '198.18.', '0.0.'];
      const srcIp = `${bogons[Math.floor(Math.random() * bogons.length)]}${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}`;
      return {
        id,
        timestamp,
        sourceIp: srcIp,
        sourcePort: Math.floor(Math.random() * 64000) + 1024,
        destIp: '192.168.10.1',
        destPort: 8080,
        protocol: 'UDP',
        length: Math.floor(Math.random() * 400) + 80,
        interArrivalTimeMs: Number((Math.random() * 0.08).toFixed(3)),
        shannonEntropy: 7.88,
        isAnomaly: true,
        threatTag: 'Spoofed-Source Flood',
        payloadSnippet: '0x7e8b91... [Forged unroutable Bogon source]'
      };
    }
  }

  if (scenario.id === 'c2-beacon') {
    const isBeacon = Math.random() < 0.25;
    if (isBeacon) {
      return {
        id,
        timestamp,
        sourceIp: '10.0.4.118',
        sourcePort: 49821,
        destIp: '185.220.101.42',
        destPort: 443,
        protocol: 'TLS',
        flags: 'ACK+PSH',
        length: 340,
        interArrivalTimeMs: 45200 + (Math.random() * 3000 - 1500),
        shannonEntropy: 4.1,
        isAnomaly: true,
        threatTag: 'Botnet C2 Beaconing',
        payloadSnippet: '0x170303... [TLS Application Data - Periodic Beacon Heartbeat]'
      };
    }
  }

  // Normal Baseline packet
  const normalSrcs = ['10.0.2.14', '10.0.3.55', '172.16.4.12', '10.0.1.9', '192.168.5.88'];
  const normalDsts = ['192.168.10.10', '192.168.10.45', '8.8.8.8', '1.1.1.1', '10.0.50.2'];
  const protocols: ('TCP' | 'UDP' | 'DNS' | 'TLS')[] = ['TCP', 'TLS', 'DNS', 'UDP'];
  const proto = protocols[Math.floor(Math.random() * protocols.length)];

  let port = 443;
  let flags = 'ACK';
  let len = 512;

  if (proto === 'DNS') {
    port = 53;
    flags = '';
    len = 78;
  } else if (proto === 'TLS') {
    port = 443;
    flags = 'ACK+PSH';
    len = Math.floor(Math.random() * 1200) + 200;
  } else if (proto === 'TCP') {
    port = [80, 443, 8080, 22, 5432][Math.floor(Math.random() * 5)];
    flags = ['SYN', 'ACK', 'FIN+ACK'][Math.floor(Math.random() * 3)];
    len = Math.floor(Math.random() * 900) + 64;
  }

  return {
    id,
    timestamp,
    sourceIp: normalSrcs[Math.floor(Math.random() * normalSrcs.length)],
    sourcePort: Math.floor(Math.random() * 40000) + 10240,
    destIp: normalDsts[Math.floor(Math.random() * normalDsts.length)],
    destPort: port,
    protocol: proto,
    flags,
    length: len,
    interArrivalTimeMs: Number((Math.random() * 8 + 1).toFixed(2)),
    shannonEntropy: Number((Math.random() * 0.8 + 3.4).toFixed(2)),
    isAnomaly: false,
    payloadSnippet: `0x${Math.floor(Math.random() * 0xffffffff).toString(16)}... [Routine Ingress Flow]`
  };
}

// Generate initial timeline dataset
export function generateInitialTimeline(): TrafficTimePoint[] {
  const points: TrafficTimePoint[] = [];
  const now = Date.now();
  for (let i = 20; i >= 0; i--) {
    const t = new Date(now - i * 3000);
    const timeStr = t.toTimeString().substring(0, 8);
    const base = 45000 + Math.floor(Math.random() * 10000);
    points.push({
      time: timeStr,
      totalPPS: base,
      tcpPPS: Math.floor(base * 0.62),
      udpPPS: Math.floor(base * 0.24),
      icmpPPS: Math.floor(base * 0.04),
      otherPPS: Math.floor(base * 0.10),
      mbps: Number(((base * 620 * 8) / 1000000).toFixed(1)),
      entropy: Number((3.65 + Math.random() * 0.4).toFixed(2))
    });
  }
  return points;
}
