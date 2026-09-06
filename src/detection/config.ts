/**
 * OneWaySentinel AI - Centralized Detection & Scoring Engine Configuration
 * All baseline defaults, mathematical weights, and threshold bounds.
 */

import { BaselineMetrics } from './types';

export const ENGINE_CONFIG = {
  // Baseline Normal Traffic Profile
  baseline: {
    baselinePacketsPerSecond: 600, // Nominal ingress flow rate for the simulated tap window
    baselineBytesPerSecond: 420000, // ~420 KB/s or 3.36 Mbps nominal
    baselineEntropy: 3.75, // Normal organic source IP Shannon entropy (3.5 - 4.2)
    baselineDestinationHHI: 0.28, // Normal modest VIP concentration
    baselineProtocolDistribution: {
      TCP: 65,
      UDP: 22,
      TLS: 8,
      DNS: 3,
      ICMP: 1,
      NTP: 1,
      SSDP: 0,
      OTHER: 0
    },
    baselineMeanIATMs: 3.8,
    sampleWindowSize: 5000
  } as BaselineMetrics,

  // Shannon Entropy Thresholds H(X)
  entropy: {
    lowThreshold: 2.5, // Highly concentrated source IP distribution
    normalMin: 2.8,
    normalMax: 4.8, // Organic multi-user distribution
    highThreshold: 6.2, // Potential distributed / spoofed source flood
    maximumTheoretical: 8.0 // 8-bit octet entropy bound
  },

  // Herfindahl-Hirschman Index (HHI) for Destination Concentration: sum(s_i ^ 2)
  concentration: {
    distributedThreshold: 0.35, // Low HHI -> distributed traffic across many targets
    moderateConcentration: 0.65, // Concentrated VIP traffic
    targetedFloodThreshold: 0.82 // Very high HHI -> possible targeted denial of service
  },

  // DDoS Detection Thresholds
  ddos: {
    synRateMultiplierThreshold: 4.0, // 4x above baseline SYN rate
    synToAckImbalanceRatio: 12.0, // Observable SYN:ACK ratio > 12:1
    udpRateMultiplierThreshold: 3.5, // 3.5x baseline UDP
    udpAmplificationMinFactor: 10.0, // > 10x ratio of response to request
    knownAmplificationPorts: [123, 53, 11211, 1900, 389, 161],
    spoofedEntropyMin: 6.8, // High entropy indicating randomized/spoofed IPs
    spoofedUniqueSourceRatio: 0.60 // > 60% packets from distinct single-packet sources
  },

  // C2 Beacon Detection Bounds
  c2: {
    minSamplesForFFT: 8, // Minimum temporal samples to run meaningful FFT/periodicity
    maxJitterPercentageForBeacon: 15.0, // <= 15% jitter = periodic machine heartbeat
    highConfidenceJitterMax: 6.0, // <= 6% jitter = very high confidence beacon
    minConnectionRepetitions: 4, // Observed callbacks to same destination
    maxPayloadSizeVarianceBytes: 25.0 // Uniform frame sizes
  },

  // Unified Threat Scoring Weights (Sums to 1.0)
  scoringWeights: {
    anomalyScoreWeight: 0.25,
    ddosEvidenceWeight: 0.35,
    temporalC2Weight: 0.20,
    entropyEvidenceWeight: 0.10,
    concentrationEvidenceWeight: 0.10
  },

  // Severity Classification Boundaries (0 - 100)
  severityBands: {
    lowMax: 24,
    mediumMax: 49,
    highMax: 74,
    criticalMin: 75
  },

  // One-Way Diode Physical Invariant
  physicalDiodeInvariant: {
    reversePacketsPermitted: 0,
    allowActiveScanning: false,
    allowPacketInjection: false,
    enclaveOperatingMode: 'STRICT_PASSIVE_MONITORING'
  }
} as const;
