export type ThreatType =
  | 'SYN Flood'
  | 'UDP Flood'
  | 'UDP Reflection/Amplification'
  | 'Spoofed-Source Flood'
  | 'Botnet C2 Beaconing'
  | 'General Traffic Anomaly'
  | 'Multi-Vector Mixed Attack';

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low';

export type AlertStatus = 'New' | 'Investigating' | 'Verified' | 'Mitigated' | 'False Positive';

export interface SecurityAlert {
  id: string;
  alertId?: string;
  threatType: ThreatType;
  severity: Severity;
  confidenceScore: number; // e.g. 96 (%)
  threatScore?: number; // 0 - 100
  timestamp: string;
  source: string;
  destination: string;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'TLS' | 'NTP';
  supportingEvidence: string[];
  detectionMethod: string;
  recommendedAction?: string;
  simulationStatus?: string; // e.g. "SIMULATED SCENARIO" | "PCAP ANALYSIS" | "FLOW ANALYSIS"
  status: AlertStatus;
  packetRate?: number; // pps
  bandwidthRate?: string; // e.g. "14.2 Gbps"
  mitreTechnique?: string;
  notes?: string;
}

export interface NetworkPacket {
  id: string;
  flowId?: string;
  timestamp: string;
  sourceIp: string;
  sourcePort: number;
  destIp: string;
  destPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'TLS' | 'NTP' | 'SSDP';
  flags?: string; // e.g. "SYN", "SYN+ACK", "ACK", "RST", "FIN+ACK"
  length: number; // bytes
  bytes?: number;
  interArrivalTimeMs: number;
  shannonEntropy: number; // 0.0 - 8.0
  isAnomaly: boolean;
  threatTag?: ThreatType;
  payloadSnippet?: string;
}

export interface TelemetryMetrics {
  monitoringStatus: 'ACTIVE_ONE_WAY' | 'DEGRADED' | 'STANDBY';
  totalPackets: number;
  totalBytes: number;
  packetsPerSecond: number;
  bytesPerSecond: number;
  activeThreatsCount: number;
  criticalAlertsCount: number;
  averageAiConfidence: number;
  sourceIPEntropy: number; // current Shannon entropy (normal ~ 3.5-4.2, spoofed flood > 6.8)
  destinationConcentration: number; // Herfindahl-Hirschman index (0-1.0)
  diodeReversePacketsTransmitted: 0; // Invariant: ALWAYS 0
  diodeOpticalRxPowerDbm: number;
  diodeTxHardwareDisabled: true; // Hardwired invariant
  pipelineLatencyMs: number;
  mlInferenceLatencyMs: number;
}

export interface TrafficTimePoint {
  time: string;
  totalPPS: number;
  tcpPPS: number;
  udpPPS: number;
  icmpPPS: number;
  otherPPS: number;
  mbps: number;
  entropy: number;
}

export interface DDoSMetricData {
  synFloodIntensity: number; // 0 - 100
  udpFloodIntensity: number; // 0 - 100
  amplificationFactor: number; // e.g., 55.4x for NTP, 12x for DNS
  spoofedEntropyScore: number; // 0 - 8.0
  synToAckRatio: number; // normal ~ 1:1, attack > 30:1
  topTargetVips: { ip: string; service: string; pps: number; percentage: number }[];
  amplificationVectors: { protocol: string; port: number; pps: number; factor: string }[];
}

export interface C2BeaconCandidate {
  id: string;
  sourceIp: string;
  destinationC2: string;
  c2Domain: string;
  periodicitySeconds: number;
  jitterPercentage: number; // e.g. 4.2%
  confidenceScore: number;
  ja3Hash: string;
  knownMalwareFamily: string; // e.g., "Cobalt Strike", "Sliver C2", "Brute Ratel"
  beaconCount: number;
  firstSeen: string;
  lastSeen: string;
  status: 'Confirmed Beacon' | 'Suspected' | 'Under Observation';
  fftPeakPower: number;
}

export interface ThreatIntelligenceRecord {
  id: string;
  iocValue: string;
  iocType: 'IPv4' | 'Domain' | 'JA3_HASH' | 'SHA256';
  threatActor: string;
  threatType: ThreatType;
  confidenceScore: number;
  firstReported: string;
  mitreTactics: string[];
  cveReferences: string[];
  reputationSource: string;
  maliciousActivitySummary: string;
}

export interface SimulationScenario {
  id: string;
  name: string;
  category: 'Baseline' | 'DDoS' | 'C2' | 'Anomaly';
  description: string;
  targetService: string;
  trafficMultiplier: number;
  activeThreat: ThreatType | null;
}
