/**
 * Statistically Grounded Anomaly Detection Engine
 * Multi-dimensional baseline divergence analysis using sliding window z-scores and distributional distance.
 * Explicitly labeled as "STATISTICAL ANALYSIS" to maintain strict analytical transparency.
 */

import { FlowFeatures, BaselineMetrics } from '../types';
import { ENGINE_CONFIG } from '../config';

export interface AnomalyEvaluation {
  anomalyScore: number; // 0 - 100
  isAnomalous: boolean;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  label: 'STATISTICAL ANALYSIS';
  breakdown: {
    ppsZScore: number;
    bpsZScore: number;
    entropyZScore: number;
    hhiDelta: number;
    protocolVariance: number;
  };
  evidence: string[];
}

export function evaluateAnomalies(
  features: FlowFeatures,
  baseline: BaselineMetrics = ENGINE_CONFIG.baseline
): AnomalyEvaluation {
  const { general, ddos, anomaly } = features;

  const ppsZ = anomaly.zScorePPS;
  const bpsZ = anomaly.zScoreBPS;
  const entropyZ = anomaly.zScoreEntropy;
  const hhiDelta = anomaly.unusualDestinationConcentration;

  const evidence: string[] = [];

  if (Math.abs(ppsZ) >= 2.0) {
    evidence.push(`Packet arrival rate z-score: ${ppsZ > 0 ? '+' : ''}${ppsZ}σ divergence from baseline (${general.packetsPerSecond.toLocaleString()} pps vs ${baseline.baselinePacketsPerSecond.toLocaleString()} pps baseline).`);
  }

  if (Math.abs(bpsZ) >= 2.0) {
    evidence.push(`Ingress throughput z-score: ${bpsZ > 0 ? '+' : ''}${bpsZ}σ divergence (${(general.bytesPerSecond / 1e6).toFixed(1)} MB/s vs ${(baseline.baselineBytesPerSecond / 1e6).toFixed(1)} MB/s).`);
  }

  if (Math.abs(entropyZ) >= 2.0) {
    evidence.push(`Source IP entropy divergence: ${entropyZ > 0 ? '+' : ''}${entropyZ}σ (Shannon H(X) = ${ddos.sourceIPEntropy} vs ${baseline.baselineEntropy} expected).`);
  }

  if (hhiDelta >= 0.35) {
    evidence.push(`Destination concentration delta: +${hhiDelta} HHI shift toward specific victim IP VIP.`);
  }

  if (evidence.length === 0) {
    evidence.push('All statistical moments and distribution metrics reside within nominal baseline tolerance.');
  }

  let severity: 'Critical' | 'High' | 'Medium' | 'Low' = 'Low';
  if (anomaly.anomalyScore >= ENGINE_CONFIG.severityBands.criticalMin) {
    severity = 'Critical';
  } else if (anomaly.anomalyScore >= ENGINE_CONFIG.severityBands.highMax - 25) {
    severity = 'High';
  } else if (anomaly.anomalyScore >= ENGINE_CONFIG.severityBands.mediumMax - 24) {
    severity = 'Medium';
  }

  return {
    anomalyScore: anomaly.anomalyScore,
    isAnomalous: anomaly.anomalyScore >= 45,
    severity,
    label: 'STATISTICAL ANALYSIS',
    breakdown: {
      ppsZScore: ppsZ,
      bpsZScore: bpsZ,
      entropyZScore: entropyZ,
      hhiDelta,
      protocolVariance: anomaly.unusualProtocolDeviation
    },
    evidence
  };
}
