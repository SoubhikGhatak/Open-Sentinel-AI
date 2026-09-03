/**
 * OneWaySentinel AI - Normalized Cybersecurity Detection Engine Types
 * Strict Passive Optical Monitoring Enclave Specification
 */

export type ProtocolType = 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'TLS' | 'NTP' | 'SSDP' | 'OTHER';

export interface TrafficFlow {
  id: string;
  flowId?: string;
  timestamp: string; // ISO string or UTC timestamp
  timestampMs: number;
  sourceIP: string;
  destinationIP: string;
  sourcePort: number;
  destinationPort: number;
  protocol: ProtocolType;
  packetCount: number;
  byteCount: number;
  bytes?: number;
  packetLength?: number;
  durationMs: number;
  packetSizes: number[];
  interArrivalTimes: number[];
  interArrivalTime?: number;
  tcpFlags?: string[]; // e.g. ["SYN"], ["SYN", "ACK"], ["ACK"], ["RST"]
  direction: 'INGRESS'; // Passive one-way invariant: ONLY INGRESS
  payloadSnippet?: string;
}

export interface GeneralFeatures {
  packetsPerSecond: number;
  bytesPerSecond: number;
  averagePacketSize: number;
  packetSizeStdDev: number;
  packetSizeVariance: number;
  flowDurationMs: number;
  flowDuration: number;
  connectionFrequency: number;
  packetCount: number;
  byteCount: number;
  uniqueSourceIPCount: number;
  uniqueDestinationIPCount: number;
  protocolDistribution: Record<ProtocolType, number>; // counts
  protocolPercentages: Record<ProtocolType, number>; // 0 - 100
  destinationPortDistribution: Record<number, number>;
  topDestinationPorts: { port: number; count: number; percentage: number }[];
}

export interface DDoSFeatures {
  synPacketRate: number; // syn pps
  ackPacketRate: number; // ack pps
  synToAckRatio: number; // observable SYN:ACK ratio
  udpPacketRate: number; // udp pps
  sourceIPCount: number;
  sourceIPEntropy: number; // Shannon Entropy H(X) 0.0 - 8.0
  destinationConcentrationHHI: number; // Herfindahl-Hirschman Index 0.0 - 1.0
  ppsDeviationFromBaseline: number; // ratio (e.g. 3.4x)
  bpsDeviationFromBaseline: number; // ratio
  uniqueSourceRatio: number; // uniqueSrc / totalPackets
  targetVIPConcentration: { ip: string; count: number; percentage: number }[];
  halfOpenEstimate: number;
}

export interface C2Features {
  meanInterArrivalTimeMs: number;
  stdDevInterArrivalTimeMs: number;
  coefficientOfVariation: number; // stdDev / mean
  periodicityScore: number; // 0.0 - 1.0
  jitterPercentage: number; // e.g. 3.4%
  connectionCount: number;
  destinationConcentration: number;
  payloadConsistencyScore: number;
  repeatedDestinationFrequency: number;
  repeatedConnectionFrequency: number;
  packetSizeConsistency: number; // 0.0 - 1.0 (1 = identical sizes)
  connectionIntervalConsistency: number; // 0.0 - 1.0
  destinationPersistenceSeconds: number;
  fftAnalysis: {
    hasSufficientSamples: boolean;
    sampleCount: number;
    dominantFrequencyHz?: number;
    dominantPeriodSeconds?: number;
    peakSpectralPower?: number; // 0.0 - 1.0
    statusMessage: string;
  };
}

export interface AnomalyFeatures {
  zScorePPS: number;
  zScoreBPS: number;
  zScoreEntropy: number;
  entropyDeviation: number;
  trafficRateDeviation: number;
  unusualProtocolDeviation: number;
  unusualDestinationConcentration: number;
  anomalyScore: number; // 0 - 100
  methodLabel: 'STATISTICAL ANALYSIS' | 'ML MODEL';
  methodDetails: string;
}

export interface FlowFeatures {
  timeWindowMs: number;
  general: GeneralFeatures;
  ddos: DDoSFeatures;
  c2: C2Features;
  anomaly: AnomalyFeatures;
  dataQuality: {
    level: 'HIGH' | 'MEDIUM' | 'LOW';
    score: number; // 0 - 100
    flowCount: number;
    packetCount: number;
    temporalCoverageSeconds: number;
    hasPacketLevelDetails: boolean;
    reasons: string[];
  };
}

export interface BaselineMetrics {
  baselinePacketsPerSecond: number;
  baselineBytesPerSecond: number;
  baselineEntropy: number;
  baselineDestinationHHI: number;
  baselineProtocolDistribution: Record<ProtocolType, number>;
  baselineMeanIATMs: number;
  sampleWindowSize: number;
}

export interface DDoSThreatResult {
  detected: boolean;
  threatType: 'SYN Flood' | 'UDP Flood' | 'UDP Reflection/Amplification' | 'Spoofed-Source Flood' | null;
  confidence: number; // 0 - 100
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  evidence: string[];
  featureValues: Record<string, number | string>;
  timestamp: string;
  sourceSummary: string;
  targetSummary: string;
  mitigationAdvisory: string; // Advisory ONLY - never executed by enclave
}

export interface C2BeaconCluster {
  id: string;
  sourceIp: string;
  destinationIp: string;
  destinationPort: number;
  protocol: ProtocolType;
  connectionCount: number;
  meanIntervalSeconds: number;
  stdDevIntervalSeconds: number;
  jitterPercentage: number;
  packetSizeMean: number;
  packetSizeStdDev: number;
  periodicityScore: number;
  c2SuspicionScore?: number;
  destinationConcentration?: number;
  payloadConsistencyScore?: number;
  classification:
    | 'Background Traffic'
    | 'Potential C2 Beacon'
    | 'Suspicious Periodic Communication'
    | 'Suspicious Periodic Traffic'
    | 'High-confidence Beaconing Pattern'
    | 'High-Confidence C2 Beacon';
  potentialC2FamilyCorrelation?: string; // Conservative correlation only
  evidence: string[];
  firstSeen: string;
  lastSeen: string;
  fftStatus: string;
  fftPeakPower: number;
}

export interface UnifiedThreatScore {
  score: number; // 0 - 100
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  confidence: number; // 0 - 100
  breakdown: {
    anomalyContribution: number;
    ddosContribution: number;
    temporalContribution: number;
    entropyContribution: number;
    concentrationContribution: number;
  };
  primaryThreat: string;
  allEvidence: string[];
}

export interface NormalizedAlert {
  id: string;
  alertId?: string;
  timestamp: string;
  threatType: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  confidence: number;
  threatScore: number;
  source: string;
  target: string;
  protocol: ProtocolType;
  detectionMethod: string;
  evidence: string[];
  features: Record<string, number | string>;
  recommendedAction: string;
  simulationStatus: string;
  packetRate?: number;
  bandwidthRate?: string;
  mitreTechnique?: string;
  status: 'New' | 'Investigating' | 'Verified' | 'Mitigated' | 'False Positive';
}

export interface IngestionReport {
  sourceType: 'PCAP' | 'CSV' | 'SIMULATION';
  filename?: string;
  totalFlows: number;
  totalPackets: number;
  totalBytes: number;
  durationSeconds: number;
  uniqueSources: number;
  uniqueDestinations: number;
  protocols: Record<string, number>;
  topTalkers: { ip: string; bytes: number; packets: number }[];
  topDestinations: { ip: string; bytes: number; packets: number; share: number }[];
  entropy: {
    current: number;
    baseline: number;
    deviation: number;
    interpretation: string;
  };
  concentration: {
    hhi: number;
    primaryTarget: string;
    trafficShare: number;
    interpretation: string;
  };
  detectionSummary: {
    threatScore: number;
    severity: string;
    detectedThreats: string[];
    confidence: number;
  };
  eventTimeline: {
    time: string;
    pps: number;
    mbps: number;
    threats: string[];
  }[];
}

export interface ModuleStatus {
  name: string;
  status: 'ONLINE' | 'DEGRADED' | 'ERROR';
  type: string;
  latencyMs: number;
  description: string;
  lastVerified: string;
}
