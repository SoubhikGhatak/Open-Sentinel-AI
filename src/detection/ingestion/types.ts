/**
 * OneWaySentinel AI - Normalized Passive Ingestion & Feature Extraction Types
 * Strictly Passive Optical Monitoring Architecture
 */

import { Severity, ThreatType } from '../../types';

export type IngestionSourceFormat = 'PCAP' | 'CSV' | 'JSON' | 'JSONL' | 'SIMULATION';

/**
 * Normalized internal representation of an individual passive network observation
 * Extracted without transmitting or injecting any packets.
 */
export interface PassiveObservation {
  id: string;
  timestamp: string; // ISO-8601 formatted timestamp
  timestampMs: number; // Unix epoch milliseconds
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'DNS' | 'TLS' | 'NTP' | 'SSDP' | 'OTHER';
  packetCount: number;
  byteCount: number;
  durationMs: number;
  tcpFlags?: string[]; // e.g. ["SYN"], ["ACK"], ["FIN"], ["RST"]
  packetSizes: number[];
  interArrivalTimes: number[];
  payloadSnippet?: string;
  rawSource: IngestionSourceFormat;
}

/**
 * Structured feature record computed for each sliding time-window
 * Combines Basic, DDoS-oriented, and C2-oriented statistical metrics.
 */
export interface FeatureVector {
  id: string;
  windowIndex: number;
  windowStartMs: number;
  windowEndMs: number;
  windowDurationSec: number;
  timestamp: string; // Window middle / end formatted

  // Summary labels for quick table viewing
  sourceSummary: string;
  destinationSummary: string;
  protocol: string;

  // 1. Basic Metrics
  packetCount: number;
  byteCount: number;
  flowDurationMs: number;
  packetsPerSecond: number;
  bytesPerSecond: number;
  averagePacketSize: number;
  minPacketSize: number;
  maxPacketSize: number;
  primaryProtocol: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;

  // 2. DDoS-Oriented Metrics
  synPacketCount: number;
  ackPacketCount: number;
  synToAckRatio: number;
  uniqueSourceIpCount: number;
  sourceIpEntropy: number; // Shannon entropy H(X) 0.0 - 8.0
  destinationConcentration: number; // Herfindahl-Hirschman Index (0.0 - 1.0)
  trafficGrowthRate: number; // % change in PPS compared to preceding window

  // 3. C2-Oriented Metrics
  connectionFrequency: number; // connections per minute
  interArrivalTimeMean: number; // milliseconds
  interArrivalTimeStdDev: number; // milliseconds
  interArrivalTimeMin: number;
  interArrivalTimeMax: number;
  coefficientOfVariation: number; // CV = stdDev / mean
  periodicityScore: number; // 0.0 - 1.0 (high for low-jitter periodic pulses)
  destinationRepetitionCount: number;
  packetSizeConsistency: number; // 0.0 - 1.0 (1.0 = strictly uniform payload size)
  jitterPercentage: number; // % variance from mean interval

  // Quality & Diagnostics
  observationCount: number;
  detectedThreatIndicator?: ThreatType | 'Normal' | 'Anomaly';
}

/**
 * Clean internal detection result contract
 */
export interface DetectionResult {
  threatType: ThreatType | 'Normal Baseline' | 'Traffic Anomaly';
  severity: Severity;
  confidence: number; // 0 - 100
  timestamp: string;
  source: string;
  destination: string;
  evidence: string[];
  features: Record<string, number | string | boolean>;
  detectionMethod: string;
  recommendedAction: string; // Advisory only - enclave never sends commands
}

/**
 * Validation summary produced when processing any raw file or stream
 */
export interface IngestionValidationSummary {
  success: boolean;
  sourceType: IngestionSourceFormat;
  filename: string;
  validRecords: number;
  invalidRecords: number;
  totalRecordsProcessed: number;
  parseErrors: string[];
  timeRange?: {
    start: string;
    end: string;
    durationSeconds: number;
  };
}

/**
 * User-configurable sliding window parameters
 */
export interface SlidingWindowConfig {
  windowDurationSeconds: number; // Default: 10 seconds
  stepSeconds: number; // Default: 5 seconds
}

/**
 * Overall summary metrics computed across an entire passive dataset
 */
export interface PassiveDatasetSummary {
  totalFlows: number;
  totalPackets: number;
  totalBytes: number;
  analysisWindow: string; // e.g. "10s window / 5s step"
  protocolsObserved: Record<string, number>; // counts
  protocolPercentages: Record<string, number>; // percentages
  uniqueSourceIps: number;
  uniqueDestinationIps: number;
  averagePacketRate: number; // average PPS
  averageByteRate: number; // average BPS
  averageEntropy: number;
  peakPeriodicityScore: number;
  timeRangeStart: string;
  timeRangeEnd: string;
}
