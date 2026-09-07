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
  destinationDomain?: string;
  destinationPort: number;
  protocol: ProtocolType;
  connectionCount: number;
  meanIntervalSeconds: number;
  stdDevIntervalSeconds: number;
  coefficientOfVariation: number; // CV = stdDev / mean
  jitterPercentage: number;
  connectionFrequencyHz: number; // 1 / meanIntervalSeconds
  packetSizeMean: number;
  packetSizeStdDev: number;
  packetSizeConsistency: number; // 0.0 - 1.0
  periodicityScore: number;
  iatRegularityScore: number; // 0.0 - 1.0
  c2Confidence: number; // 0 - 100
  c2SuspicionScore?: number; // legacy alias
  destinationConcentration: number; // 0.0 - 1.0
  payloadConsistencyScore?: number;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  classification:
    | 'Background Traffic'
    | 'Potential C2 Beacon'
    | 'Suspicious Periodic Communication'
    | 'Suspicious Periodic Traffic'
    | 'High-confidence Beaconing Pattern'
    | 'High-Confidence C2 Beacon'
    | 'Benign Periodic Traffic';
  potentialC2FamilyCorrelation?: string; // Conservative correlation only
  evidence: string[];
  firstSeen: string;
  lastSeen: string;
  fftStatus: string;
  fftPeakPower: number;
  scoreBreakdown: {
    periodicityContrib: number; // 0 - 25
    iatRegularityContrib: number; // 0 - 20
    destinationRepetitionContrib: number; // 0 - 20
    connectionFreqContrib: number; // 0 - 15
    packetSizeConsistencyContrib: number; // 0 - 20
  };
  timelineEvents: {
    id: string;
    timestamp: string;
    timestampMs: number;
    sourceIp: string;
    destinationIp: string;
    destinationPort: number;
    bytes: number;
    intervalSeconds: number;
  }[];
  iatDistribution?: number[];
  packetSizes?: number[];
  isBenignPeriodicService?: boolean;
  benignServiceReason?: string;
}

export type ThreatScoreRiskLevel = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';

export interface ExplainableSignalCard {
  id: string;
  name: string;
  score: number; // 0 - 100
  contribution: 'HIGH' | 'MEDIUM' | 'LOW';
  weightPercentage: number;
  calculatedPoints: number;
  telemetryContext: string;
  forensicInterpretation: string;
}

export interface RiskFactorRadarPoint {
  factor: string;
  score: number; // 0 - 100
  baseline: number; // normal baseline 0 - 100
  fullMark: number;
}

export interface CorrelatedThreatIncident {
  title: string;
  correlatedSignalsCount: number;
  correlationConfidence: number;
  signalsSummary: string[];
  threatVector: string;
}

export interface UnifiedThreatScore {
  score: number; // 0 - 100
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  riskLevel: ThreatScoreRiskLevel;
  confidence: number; // 0 - 100
  label: string; // "AI-Assisted Threat Scoring"
  subLabel: string; // "Explainable Behavioural Risk Engine"
  breakdown: {
    anomalyContribution: number;
    ddosContribution: number;
    temporalContribution: number;
    entropyContribution: number;
    concentrationContribution: number;
    confidenceContribution?: number;
    trafficIntensityContribution?: number;
    protocolContribution?: number;
    [key: string]: number | undefined;
  };
  primaryThreat: string;
  allEvidence: string[];
  evidenceChain: string[];
  operatorExplanation: string; // "WHY THIS MATTERS"
  signalCards: ExplainableSignalCard[];
  radarData: RiskFactorRadarPoint[];
  correlation: CorrelatedThreatIncident;
  scoreTimeline?: { time: string; score: number; scenarioId?: string }[];
}

export interface NormalizedAlert {
  id: string;
  alertId?: string;
  timestamp: string;
  threatType: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  confidence: number;
  confidenceScore?: number;
  threatScore: number;
  source: string;
  target: string;
  destination?: string;
  protocol: ProtocolType;
  detectionMethod: string;
  evidence: string[];
  supportingEvidence?: string[];
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
