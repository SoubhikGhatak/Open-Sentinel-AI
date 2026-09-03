/**
 * Dedicated C2 Beacon Detection Engine
 * Passive analysis of stealthy, low-and-slow command and control heartbeats without decrypting payloads.
 * 
 * Analyzes:
 * - Connection repetition and persistence
 * - Inter-arrival time (IAT) distribution, mean, standard deviation, and coefficient of variation
 * - Periodicity score and jitter percentage
 * - Discrete Fourier Transform (DFT/FFT) spectral peak (or reports "Insufficient temporal samples")
 * - Packet size consistency
 * - Conservative behavioral correlation with known C2 frameworks (Cobalt Strike, Sliver, etc.)
 */

import { TrafficFlow, C2BeaconCluster } from '../types';
import { ENGINE_CONFIG } from '../config';
import { analyzeTemporalPeriodicity } from '../features/spectral';

export function detectC2Beacons(flows: TrafficFlow[]): C2BeaconCluster[] {
  if (!flows || flows.length === 0) return [];

  // Group flows by conversational pairing: (source IP -> destination IP:destination Port)
  const conversationMap: Map<string, TrafficFlow[]> = new Map();

  for (const flow of flows) {
    const key = `${flow.sourceIP}->${flow.destinationIP}:${flow.destinationPort}`;
    const list = conversationMap.get(key) || [];
    list.push(flow);
    conversationMap.set(key, list);
  }

  const clusters: C2BeaconCluster[] = [];

  for (const [key, convFlows] of conversationMap.entries()) {
    // Sort chronologically
    convFlows.sort((a, b) => a.timestampMs - b.timestampMs);

    const firstFlow = convFlows[0];
    const sourceIp = firstFlow.sourceIP;
    const destIp = firstFlow.destinationIP;
    const destPort = firstFlow.destinationPort;
    const protocol = firstFlow.protocol;

    // Collect all inter-arrival intervals
    const intervalsMs: number[] = [];
    for (let i = 1; i < convFlows.length; i++) {
      const delta = convFlows[i].timestampMs - convFlows[i - 1].timestampMs;
      if (delta > 0) intervalsMs.push(delta);
    }

    // Also include any internal inter-arrival times from within the flow records
    for (const flow of convFlows) {
      if (flow.interArrivalTimes && flow.interArrivalTimes.length > 0) {
        intervalsMs.push(...flow.interArrivalTimes);
      }
    }

    // Collect packet sizes
    const sizes: number[] = [];
    for (const flow of convFlows) {
      if (flow.packetSizes && flow.packetSizes.length > 0) {
        sizes.push(...flow.packetSizes);
      } else {
        sizes.push(Math.round(flow.byteCount / (flow.packetCount || 1)));
      }
    }

    // Compute packet size statistics
    const sizeSum = sizes.reduce((a, b) => a + b, 0);
    const sizeMean = sizes.length > 0 ? Math.round(sizeSum / sizes.length) : 0;
    const sizeVar = sizes.length > 0 ? sizes.reduce((acc, s) => acc + Math.pow(s - sizeMean, 2), 0) / sizes.length : 0;
    const sizeStdDev = Math.round(Math.sqrt(sizeVar));

    // Run spectral & temporal analysis
    const spectral = analyzeTemporalPeriodicity(intervalsMs);
    const meanSec = Number((spectral.meanIntervalMs / 1000).toFixed(2));
    const stdDevSec = Number((spectral.stdDevIntervalMs / 1000).toFixed(2));
    const jitterPct = spectral.jitterPercentage;

    // Compute C2 Suspicion Scoring Model
    // c2SuspicionScore = periodicityScore * 30 + lowJitterScore * 25 + destinationRepetitionScore * 25 + payloadConsistencyScore * 20
    const periodicityScore = spectral.periodicityScore;
    const lowJitterScore = Math.max(0, 1 - Math.min(1, jitterPct / 30));
    const destinationRepetitionScore = Math.min(1, Math.max(convFlows.length, intervalsMs.length) / 5);
    const payloadConsistencyScore = sizeMean > 0 ? Math.max(0, 1 - Math.min(1, sizeStdDev / 40)) : 0;

    const c2SuspicionScore = Math.min(100, Math.round(
      periodicityScore * 30 +
      lowJitterScore * 25 +
      destinationRepetitionScore * 25 +
      payloadConsistencyScore * 20
    ));

    let classification:
      | 'High-confidence Beaconing Pattern'
      | 'Suspicious Periodic Communication'
      | 'Potential C2 Beacon'
      | 'Background Traffic' = 'Background Traffic';
    let potentialFamily: string | undefined = undefined;
    const evidence: string[] = [];

    if (intervalsMs.length < 2) {
      classification = 'Background Traffic';
      evidence.push(`Sparse interaction (${intervalsMs.length} intervals observed). Insufficient temporal evidence for beacon classification.`);
    } else if (c2SuspicionScore >= 68 && convFlows.length >= 3 && jitterPct <= 15) {
      classification = 'High-confidence Beaconing Pattern';
      evidence.push(`High suspicion score: ${c2SuspicionScore} / 100 (periodicity ${periodicityScore.toFixed(2)}, jitter ${jitterPct}%)`);
      evidence.push(`Deterministic timing: Periodic heartbeat observed with interval ~${meanSec}s (jitter: ${jitterPct}%)`);
      evidence.push(`Uniform outbound payload: mean ${sizeMean}B with near-zero variance (σ = ${sizeStdDev}B)`);
      evidence.push(`Repeated destination persistence across ${convFlows.length} connection callbacks`);

      if (spectral.hasSufficientSamples && spectral.peakSpectralPower && spectral.peakSpectralPower > 0.6) {
        evidence.push(`Spectral peak detected at frequency ${spectral.dominantFrequencyHz} Hz (${(spectral.peakSpectralPower * 100).toFixed(0)}% spectral concentration)`);
      } else {
        evidence.push(spectral.statusMessage);
      }

      // Simulated framework correlation (clearly labeled as simulation)
      if (Math.abs(meanSec - 45) < 8 && sizeMean >= 300 && sizeMean <= 450) {
        potentialFamily = 'Simulated Cobalt Strike-like beacon pattern (45s sleep profile, uniform payload)';
      } else if (Math.abs(meanSec - 120) < 15 && sizeMean >= 480 && sizeMean <= 600) {
        potentialFamily = 'Simulated Sliver-like implant beacon scenario (120s heartbeat profile)';
      } else {
        potentialFamily = 'Simulated C2 beacon scenario';
      }
    } else if (c2SuspicionScore >= 45) {
      classification = 'Suspicious Periodic Communication';
      evidence.push(`Moderate suspicion score: ${c2SuspicionScore} / 100. Periodicity: ${periodicityScore.toFixed(2)} with ${jitterPct}% jitter`);
      evidence.push(`Payload size mean ${sizeMean}B (σ = ${sizeStdDev}B)`);
      evidence.push(spectral.statusMessage);
      potentialFamily = 'Simulated C2 beacon scenario';
    } else if (c2SuspicionScore >= 30) {
      classification = 'Potential C2 Beacon';
      evidence.push(`Low-to-moderate periodicity signature detected (suspicion score: ${c2SuspicionScore}/100)`);
      evidence.push(spectral.statusMessage);
    } else {
      classification = 'Background Traffic';
      evidence.push(`Nominal organic interaction: high jitter (${jitterPct}%) and variable payload sizes (suspicion score: ${c2SuspicionScore}/100).`);
      evidence.push(spectral.statusMessage);
    }

    const firstSeen = convFlows[0]?.timestamp || new Date().toISOString();
    const lastSeen = convFlows[convFlows.length - 1]?.timestamp || new Date().toISOString();

    clusters.push({
      id: `c2-${key.replace(/[^a-zA-Z0-9]/g, '-')}`,
      sourceIp,
      destinationIp: destIp,
      destinationPort: destPort,
      protocol,
      connectionCount: convFlows.length,
      meanIntervalSeconds: meanSec,
      stdDevIntervalSeconds: stdDevSec,
      jitterPercentage: jitterPct,
      packetSizeMean: sizeMean,
      packetSizeStdDev: sizeStdDev,
      periodicityScore: spectral.periodicityScore,
      c2SuspicionScore,
      destinationConcentration: 1.0,
      payloadConsistencyScore,
      classification,
      potentialC2FamilyCorrelation: potentialFamily,
      evidence,
      firstSeen,
      lastSeen,
      fftStatus: spectral.statusMessage,
      fftPeakPower: spectral.peakSpectralPower || 0
    });
  }

  // Sort: High-confidence beaconing pattern first, then suspicious, then potential, then background
  clusters.sort((a, b) => {
    const score = (c: C2BeaconCluster) =>
      c.classification === 'High-confidence Beaconing Pattern' || c.classification === 'High-Confidence C2 Beacon' ? 4 :
      c.classification === 'Suspicious Periodic Communication' || c.classification === 'Suspicious Periodic Traffic' ? 3 :
      c.classification === 'Potential C2 Beacon' ? 2 : 1;
    return score(b) - score(a);
  });

  return clusters;
}
