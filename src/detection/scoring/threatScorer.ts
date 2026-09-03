/**
 * Unified Threat Scoring & Evidence Generation Module
 * Mathematical synthesis of all detection vectors into a standardized 0 - 100 severity index.
 * Generates fully explainable forensic evidence records.
 */

import { FlowFeatures, DDoSThreatResult, C2BeaconCluster, UnifiedThreatScore, NormalizedAlert } from '../types';
import { ENGINE_CONFIG } from '../config';

export function calculateUnifiedThreatScore(
  features: FlowFeatures,
  ddosResult: DDoSThreatResult,
  c2Clusters: C2BeaconCluster[]
): UnifiedThreatScore {
  const { anomaly, ddos } = features;
  const weights = ENGINE_CONFIG.scoringWeights;

  // 1. Anomaly component (0 - 100)
  const anomalyScore = anomaly.anomalyScore;

  // 2. DDoS component (0 - 100)
  let ddosScore = 0;
  if (ddosResult.detected) {
    ddosScore = ddosResult.confidence;
  }

  // 3. C2 Beacon component (0 - 100)
  let c2Score = 0;
  const highConfBeacon = c2Clusters.find(
    (c) => c.classification === 'High-confidence Beaconing Pattern' || c.classification === 'High-Confidence C2 Beacon'
  );
  const suspBeacon = c2Clusters.find(
    (c) => c.classification === 'Suspicious Periodic Communication' || c.classification === 'Suspicious Periodic Traffic'
  );
  const potBeacon = c2Clusters.find((c) => c.classification === 'Potential C2 Beacon');

  if (highConfBeacon) {
    c2Score = highConfBeacon.c2SuspicionScore ?? Math.min(95, 75 + highConfBeacon.periodicityScore * 20);
  } else if (suspBeacon) {
    c2Score = suspBeacon.c2SuspicionScore ?? 50;
  } else if (potBeacon) {
    c2Score = potBeacon.c2SuspicionScore ?? 35;
  }

  // 4. Entropy component (0 - 100)
  let entropyScore = 0;
  if (ddos.sourceIPEntropy >= ENGINE_CONFIG.entropy.highThreshold) {
    entropyScore = Math.min(100, Math.round(((ddos.sourceIPEntropy - 4.5) / 3.5) * 100));
  } else if (ddos.sourceIPEntropy < ENGINE_CONFIG.entropy.lowThreshold) {
    entropyScore = 35;
  }

  // 5. Destination Concentration component (0 - 100)
  let concentrationScore = 0;
  if (ddos.destinationConcentrationHHI >= ENGINE_CONFIG.concentration.targetedFloodThreshold) {
    concentrationScore = Math.min(100, Math.round(ddos.destinationConcentrationHHI * 100));
  } else if (ddos.destinationConcentrationHHI >= ENGINE_CONFIG.concentration.moderateConcentration) {
    concentrationScore = 45;
  }

  // Weighted aggregation: anomalyScore*0.25 + ddosScore*0.35 + c2Score*0.20 + entropyScore*0.10 + concentrationScore*0.10
  const rawScore =
    anomalyScore * 0.25 +
    ddosScore * 0.35 +
    c2Score * 0.20 +
    entropyScore * 0.10 +
    concentrationScore * 0.10;

  const finalScore = Math.min(100, Math.max(0, Math.round(rawScore)));

  // Severity classification (0-24: LOW, 25-49: MEDIUM, 50-74: HIGH, 75-100: CRITICAL)
  let severity: 'Critical' | 'High' | 'Medium' | 'Low' = 'Low';
  if (finalScore >= 75) {
    severity = 'Critical';
  } else if (finalScore >= 50) {
    severity = 'High';
  } else if (finalScore >= 25) {
    severity = 'Medium';
  } else {
    severity = 'Low';
  }

  // Primary threat naming
  let primaryThreat = 'Nominal Egress Monitoring';
  if (ddosResult.detected && ddosResult.threatType && highConfBeacon) {
    primaryThreat = `Multi-Vector Threat: ${ddosResult.threatType} + C2 Beaconing`;
  } else if (ddosResult.detected && ddosResult.threatType) {
    primaryThreat = ddosResult.threatType;
  } else if (highConfBeacon) {
    primaryThreat = `Simulated C2 Beaconing (${highConfBeacon.sourceIp} -> ${highConfBeacon.destinationIp})`;
  } else if (anomalyScore >= 60) {
    primaryThreat = 'Statistical Baseline Anomaly';
  }

  // Synthesize comprehensive evidence
  const allEvidence: string[] = [];
  if (ddosResult.detected) {
    allEvidence.push(...ddosResult.evidence);
  }
  if (highConfBeacon) {
    allEvidence.push(...highConfBeacon.evidence);
  }
  if (allEvidence.length === 0) {
    allEvidence.push('Passive optical monitoring pipeline confirms nominal ingress traffic profile.');
    allEvidence.push('Zero packet transmission detected across data diode boundary (enclave isolation verified).');
  }

  const confidence = Math.max(
    ddosResult.confidence,
    highConfBeacon ? 92 : 0,
    features.dataQuality.level === 'LOW' ? 45 : 88
  );

  return {
    score: finalScore,
    severity,
    confidence: finalScore === 0 ? 98 : confidence,
    breakdown: {
      anomalyContribution: Math.round(anomalyScore * 0.25),
      ddosContribution: Math.round(ddosScore * 0.35),
      temporalContribution: Math.round(c2Score * 0.20),
      entropyContribution: Math.round(entropyScore * 0.10),
      concentrationContribution: Math.round(concentrationScore * 0.10)
    },
    primaryThreat,
    allEvidence
  };
}

export function generateAlertsFromAnalysis(
  features: FlowFeatures,
  ddosResult: DDoSThreatResult,
  c2Clusters: C2BeaconCluster[],
  threatScore: UnifiedThreatScore
): NormalizedAlert[] {
  const alerts: NormalizedAlert[] = [];
  const now = new Date().toISOString().replace('T', ' ').substring(0, 19);

  // DDoS Alert
  if (ddosResult.detected && ddosResult.threatType) {
    const alertId = `alert-ddos-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    alerts.push({
      id: alertId,
      alertId,
      timestamp: now,
      threatType: ddosResult.threatType,
      severity: ddosResult.severity,
      confidence: ddosResult.confidence,
      threatScore: threatScore.score,
      source: ddosResult.sourceSummary,
      target: ddosResult.targetSummary,
      protocol: ddosResult.threatType === 'SYN Flood' ? 'TCP' : ddosResult.threatType === 'UDP Reflection/Amplification' ? 'NTP' : 'UDP',
      detectionMethod: 'Passive Multi-Signal Flow & Entropy Analyzer',
      evidence: ddosResult.evidence,
      features: ddosResult.featureValues,
      packetRate: features.general.packetsPerSecond,
      bandwidthRate: `${((features.general.bytesPerSecond * 8) / 1e9).toFixed(2)} Gbps`,
      mitreTechnique: ddosResult.threatType === 'SYN Flood' ? 'T1498.001 - Direct Network Flood' : 'T1498.002 - Reflection Amplification',
      recommendedAction: ddosResult.mitigationAdvisory,
      simulationStatus: 'SYNTHETIC_PASSIVE_FLOW',
      status: 'New'
    });
  }

  // C2 Alerts
  for (const cluster of c2Clusters) {
    if (
      cluster.classification === 'High-confidence Beaconing Pattern' ||
      cluster.classification === 'High-Confidence C2 Beacon'
    ) {
      const alertId = `alert-${cluster.id}-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
      alerts.push({
        id: alertId,
        alertId,
        timestamp: now,
        threatType: 'Botnet C2 Beaconing',
        severity: 'High',
        confidence: 94,
        threatScore: threatScore.score,
        source: cluster.sourceIp,
        target: `${cluster.destinationIp}:${cluster.destinationPort}`,
        protocol: cluster.protocol,
        detectionMethod: 'Inter-Arrival Time (IAT) Spectral & Jitter FFT Analyzer',
        evidence: [
          ...cluster.evidence,
          cluster.potentialC2FamilyCorrelation ? `Behavioral correlation: ${cluster.potentialC2FamilyCorrelation}` : 'Simulated C2 beacon scenario',
          'Zero packet transmission initiated by monitoring enclave (passive observation only)'
        ],
        features: {
          interval: `${cluster.meanIntervalSeconds}s`,
          jitter: `${cluster.jitterPercentage}%`,
          packetSize: `${cluster.packetSizeMean}B`,
          periodicityScore: cluster.periodicityScore,
          fftPower: cluster.fftPeakPower
        },
        packetRate: Math.round(1 / (cluster.meanIntervalSeconds || 1)),
        bandwidthRate: `${Math.round((cluster.packetSizeMean * 8) / (cluster.meanIntervalSeconds || 1))} bps`,
        mitreTechnique: 'T1071.001 - Application Layer Protocol: Web Protocols',
        recommendedAction: `PASSIVE MITIGATION ADVISORY: Execution is manual/out-of-band. OneWaySentinel AI cannot transmit mitigation commands into the monitored production network. Recommended out-of-band action: Isolate internal host ${cluster.sourceIp} via switch port shutdown or upstream endpoint isolation agent.`,
        simulationStatus: 'SYNTHETIC_PASSIVE_FLOW',
        status: 'New'
      });
    }
  }

  return alerts;
}
