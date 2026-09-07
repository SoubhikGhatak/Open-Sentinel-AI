/**
 * OneWaySentinel AI - Core Mathematical & Feature Calculation Utilities
 * Strictly passive feature extraction functions operating on observed ingress telemetry.
 */

import { calculateShannonEntropy } from './entropy';
import { calculateDestinationConcentration } from './concentration';
import { analyzeTemporalPeriodicity } from './spectral';

/**
 * 1. Packets Per Second (PPS)
 * Calculates observed ingress packet rate over observation window.
 */
export function calculatePacketsPerSecond(packetCount: number, durationSeconds: number): number {
  if (durationSeconds <= 0 || packetCount <= 0) return 0;
  return Math.round(packetCount / durationSeconds);
}

/**
 * 2. Bytes Per Second (BPS)
 * Calculates observed throughput in bytes per second.
 */
export function calculateBytesPerSecond(byteCount: number, durationSeconds: number): number {
  if (durationSeconds <= 0 || byteCount <= 0) return 0;
  return Math.round(byteCount / durationSeconds);
}

/**
 * 3. Flow Duration (Seconds)
 * Computes observed temporal duration between first and last packet.
 */
export function calculateFlowDuration(minTimeMs: number, maxTimeMs: number): number {
  if (maxTimeMs <= minTimeMs) return 0;
  return Number(((maxTimeMs - minTimeMs) / 1000).toFixed(3));
}

/**
 * 4. SYN Packet Rate (PPS)
 * Computes the arrival rate of TCP SYN packets.
 */
export function calculateSynRate(synCount: number, durationSeconds: number): number {
  if (durationSeconds <= 0 || synCount <= 0) return 0;
  return Math.round(synCount / durationSeconds);
}

/**
 * 5. SYN/ACK Ratio
 * Measures ratio of observable SYN requests to completed ACK handshakes.
 * Normal ~ 1:1, Volumetric SYN Flood > 20:1.
 */
export function calculateSynToAckRatio(synCount: number, ackCount: number): number {
  if (synCount <= 0) return 0;
  if (ackCount <= 0) return 50.0; // Infinite/severe buildup capped at 50:1 for normalized reporting
  return Number((synCount / ackCount).toFixed(2));
}

/**
 * 6. Unique Source IP Count
 * Calculates cardinal count of distinct source IP addresses in sample window.
 */
export function calculateUniqueSourceIpCount(sourceIps: string[]): number {
  if (!sourceIps || sourceIps.length === 0) return 0;
  return new Set(sourceIps).size;
}

/**
 * 7. Source IP Shannon Entropy
 * H(X) = -Σ p(x) * log2(p(x))
 * Nominal enterprise range: ~3.2 - 4.6. Spoofed flood > 6.5.
 */
export function calculateSourceIpEntropy(sourceIps: string[]): number {
  return calculateShannonEntropy(sourceIps);
}

/**
 * 8. Destination Concentration / Herfindahl-Hirschman Index (HHI)
 * HHI = Σ s_i^2 where s_i is the traffic share of destination VIP i (0.0 to 1.0).
 */
export function calculateDestinationConcentrationHHI(destinations: string[], weights?: number[]): number {
  return calculateDestinationConcentration(destinations, weights).hhi;
}

/**
 * 9. Inter-Arrival Times (IAT)
 * Computes consecutive arrival differences in milliseconds from timestamp sequence.
 */
export function calculateInterArrivalTimes(timestampsMs: number[]): number[] {
  if (!timestampsMs || timestampsMs.length < 2) return [];
  const sorted = [...timestampsMs].sort((a, b) => a - b);
  const diffs: number[] = [];
  for (let i = 1; i < sorted.length; i++) {
    const delta = sorted[i] - sorted[i - 1];
    if (delta >= 0) diffs.push(delta);
  }
  return diffs;
}

/**
 * 10. Mean Value / Mean Inter-Arrival Time
 */
export function calculateMean(values: number[]): number {
  if (!values || values.length === 0) return 0;
  const sum = values.reduce((acc, v) => acc + v, 0);
  return Number((sum / values.length).toFixed(3));
}

/**
 * 11. Standard Deviation (σ)
 */
export function calculateStandardDeviation(values: number[]): number {
  if (!values || values.length <= 1) return 0;
  const mean = calculateMean(values);
  const variance = values.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / values.length;
  return Number(Math.sqrt(variance).toFixed(3));
}

/**
 * 12. Coefficient of Variation (CV = σ / μ)
 */
export function calculateCoefficientOfVariation(stdDev: number, mean: number): number {
  if (mean <= 0) return 0;
  return Number((stdDev / mean).toFixed(3));
}

/**
 * 13. Jitter Percentage
 * Expressed as (σ / μ) * 100 for network beaconing analysis.
 */
export function calculateJitterPercentage(stdDev: number, mean: number): number {
  if (mean <= 0) return 0;
  return Number(((stdDev / mean) * 100).toFixed(2));
}

/**
 * 14. Periodicity Score (0.0 - 1.0)
 * Evaluates timing regularity from inter-arrival times.
 */
export function calculatePeriodicityScore(intervalsMs: number[]): number {
  if (!intervalsMs || intervalsMs.length === 0) return 0;
  const res = analyzeTemporalPeriodicity(intervalsMs);
  return res.periodicityScore;
}

/**
 * 15. Traffic Anomaly Score (0 - 100)
 * Evaluates multi-dimensional statistical divergence from baseline parameters.
 */
export function calculateTrafficAnomalyScore(params: {
  zScorePPS: number;
  zScoreBPS: number;
  zScoreEntropy: number;
  hhi: number;
}): number {
  let score = 0;
  if (params.zScorePPS > 2) score += Math.min(35, params.zScorePPS * 8);
  if (params.zScoreBPS > 2) score += Math.min(25, params.zScoreBPS * 5);
  if (Math.abs(params.zScoreEntropy) > 2) score += Math.min(20, Math.abs(params.zScoreEntropy) * 7);
  if (params.hhi > 0.75) score += 20;
  return Math.min(100, Math.max(0, Math.round(score)));
}
