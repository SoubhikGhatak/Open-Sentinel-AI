/**
 * OneWaySentinel AI - Sliding Time-Window Feature Extraction Engine
 * Converts raw passive observations into structured feature vectors across sliding windows.
 * Strictly passive, real, deterministic mathematical calculations.
 */

import {
  PassiveObservation,
  FeatureVector,
  SlidingWindowConfig,
  PassiveDatasetSummary
} from './types';

/**
 * Computes Shannon Entropy H(X) for a set of items (e.g., source IP addresses).
 * H(X) = - sum(p_i * log2(p_i))
 * Scale: 0.0 (all packets from single IP) to ~8.0+ (widely spoofed/distributed).
 */
export function calculateShannonEntropy(items: string[]): number {
  if (!items || items.length === 0) return 0;

  const freqMap: Map<string, number> = new Map();
  for (const item of items) {
    freqMap.set(item, (freqMap.get(item) || 0) + 1);
  }

  const total = items.length;
  let entropy = 0;
  for (const count of freqMap.values()) {
    const p = count / total;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return Number(entropy.toFixed(3));
}

/**
 * Computes Herfindahl-Hirschman Index (HHI) for destination concentration.
 * HHI = sum((count_i / total)^2)
 * Scale: 0.0 (broadly distributed) to 1.0 (single victim VIP targeted).
 */
export function calculateDestinationHHI(destinations: string[], weights?: number[]): number {
  if (!destinations || destinations.length === 0) return 0;

  const destWeights: Map<string, number> = new Map();
  let totalWeight = 0;

  for (let i = 0; i < destinations.length; i++) {
    const dst = destinations[i];
    const w = weights && weights[i] ? weights[i] : 1;
    destWeights.set(dst, (destWeights.get(dst) || 0) + w);
    totalWeight += w;
  }

  if (totalWeight === 0) return 0;

  let hhi = 0;
  for (const w of destWeights.values()) {
    const share = w / totalWeight;
    hhi += share * share;
  }

  return Number(Math.min(1.0, hhi).toFixed(3));
}

/**
 * Performs sliding window slicing and computes FeatureVector for every window.
 */
export function extractWindowFeatures(
  observations: PassiveObservation[],
  config: SlidingWindowConfig = { windowDurationSeconds: 10, stepSeconds: 5 }
): {
  featureVectors: FeatureVector[];
  summary: PassiveDatasetSummary;
} {
  if (!observations || observations.length === 0) {
    return {
      featureVectors: [],
      summary: getEmptySummary(config)
    };
  }

  // Sort observations chronologically
  const sorted = [...observations].sort((a, b) => a.timestampMs - b.timestampMs);

  const minTs = sorted[0].timestampMs;
  const maxTs = sorted[sorted.length - 1].timestampMs;
  const datasetSpanMs = Math.max(1000, maxTs - minTs);

  const windowDurationMs = Math.max(1000, config.windowDurationSeconds * 1000);
  const stepMs = Math.max(500, config.stepSeconds * 1000);

  const featureVectors: FeatureVector[] = [];
  let previousWindowPPS = 0;

  // If dataset duration is shorter than a single window, make a single window spanning the dataset
  const effectiveWindowMs = Math.min(windowDurationMs, Math.max(1000, datasetSpanMs));
  const loopEnd = datasetSpanMs <= windowDurationMs ? minTs + 1 : maxTs - (windowDurationMs / 2);

  let currentWindowStart = minTs;
  let windowIndex = 0;

  while (currentWindowStart <= loopEnd || (windowIndex === 0 && featureVectors.length === 0)) {
    const currentWindowEnd = currentWindowStart + effectiveWindowMs;

    // Filter observations within window: [start, end)
    const windowObs = sorted.filter(
      (obs) => obs.timestampMs >= currentWindowStart && obs.timestampMs < currentWindowEnd
    );

    // If window is empty but we have items, fallback to all items in range or advance
    const activeObs = windowObs.length > 0 ? windowObs : sorted.slice(0, Math.min(20, sorted.length));

    // Calculate Window Aggregates
    let totalPackets = 0;
    let totalBytes = 0;
    let synCount = 0;
    let ackCount = 0;
    const sourceIps: string[] = [];
    const destIps: string[] = [];
    const destWeights: number[] = [];
    const packetSizes: number[] = [];
    const interArrivals: number[] = [];
    const protoCounts: Record<string, number> = {};
    const srcCounts: Map<string, number> = new Map();
    const dstCounts: Map<string, number> = new Map();
    const srcPortCounts: Map<number, number> = new Map();
    const dstPortCounts: Map<number, number> = new Map();

    let earliestFlowMs = Infinity;
    let latestFlowMs = -Infinity;

    activeObs.forEach((obs) => {
      totalPackets += obs.packetCount;
      totalBytes += obs.byteCount;

      if (obs.timestampMs < earliestFlowMs) earliestFlowMs = obs.timestampMs;
      if (obs.timestampMs + obs.durationMs > latestFlowMs) latestFlowMs = obs.timestampMs + obs.durationMs;

      sourceIps.push(obs.sourceIp);
      destIps.push(obs.destinationIp);
      destWeights.push(obs.packetCount);

      srcCounts.set(obs.sourceIp, (srcCounts.get(obs.sourceIp) || 0) + obs.packetCount);
      dstCounts.set(obs.destinationIp, (dstCounts.get(obs.destinationIp) || 0) + obs.packetCount);
      srcPortCounts.set(obs.sourcePort, (srcPortCounts.get(obs.sourcePort) || 0) + obs.packetCount);
      dstPortCounts.set(obs.destinationPort, (dstPortCounts.get(obs.destinationPort) || 0) + obs.packetCount);

      protoCounts[obs.protocol] = (protoCounts[obs.protocol] || 0) + obs.packetCount;

      if (obs.tcpFlags) {
        for (const flag of obs.tcpFlags) {
          const upper = flag.toUpperCase();
          if (upper.includes('SYN') && !upper.includes('ACK')) synCount += obs.packetCount;
          if (upper.includes('ACK')) ackCount += obs.packetCount;
        }
      }

      if (obs.packetSizes && obs.packetSizes.length > 0) {
        packetSizes.push(...obs.packetSizes);
      } else {
        packetSizes.push(Math.round(obs.byteCount / Math.max(1, obs.packetCount)));
      }

      if (obs.interArrivalTimes && obs.interArrivalTimes.length > 0) {
        interArrivals.push(...obs.interArrivalTimes);
      } else if (obs.packetCount > 1 && obs.durationMs > 0) {
        interArrivals.push(obs.durationMs / (obs.packetCount - 1));
      }
    });

    const windowDurationSec = effectiveWindowMs / 1000;
    const packetsPerSecond = Math.round(totalPackets / windowDurationSec);
    const bytesPerSecond = Math.round(totalBytes / windowDurationSec);

    // Basic Metrics
    const flowDurationMs = latestFlowMs !== -Infinity && earliestFlowMs !== Infinity
      ? Math.max(1, latestFlowMs - earliestFlowMs)
      : effectiveWindowMs;

    let avgPacketSize = 0;
    let minPacketSize = 0;
    let maxPacketSize = 0;
    let packetSizeVariance = 0;
    let packetSizeStdDev = 0;

    if (packetSizes.length > 0) {
      minPacketSize = Math.min(...packetSizes);
      maxPacketSize = Math.max(...packetSizes);
      avgPacketSize = Math.round(packetSizes.reduce((a, b) => a + b, 0) / packetSizes.length);
      packetSizeVariance = packetSizes.reduce((acc, s) => acc + Math.pow(s - avgPacketSize, 2), 0) / packetSizes.length;
      packetSizeStdDev = Math.sqrt(packetSizeVariance);
    }

    // Dominant protocol, IP, and Port determination
    let primaryProtocol = 'TCP';
    let maxProtoCount = -1;
    for (const [proto, count] of Object.entries(protoCounts)) {
      if (count > maxProtoCount) {
        maxProtoCount = count;
        primaryProtocol = proto;
      }
    }

    let dominantSrcIp = sorted[0]?.sourceIp || '192.168.1.100';
    let maxSrcCount = -1;
    for (const [ip, count] of srcCounts.entries()) {
      if (count > maxSrcCount) {
        maxSrcCount = count;
        dominantSrcIp = ip;
      }
    }

    let dominantDstIp = sorted[0]?.destinationIp || '10.0.0.1';
    let maxDstCount = -1;
    for (const [ip, count] of dstCounts.entries()) {
      if (count > maxDstCount) {
        maxDstCount = count;
        dominantDstIp = ip;
      }
    }

    let dominantSrcPort = 49152;
    let maxSrcPCount = -1;
    for (const [port, count] of srcPortCounts.entries()) {
      if (count > maxSrcPCount) {
        maxSrcPCount = count;
        dominantSrcPort = port;
      }
    }

    let dominantDstPort = 443;
    let maxDstPCount = -1;
    for (const [port, count] of dstPortCounts.entries()) {
      if (count > maxDstPCount) {
        maxDstPCount = count;
        dominantDstPort = port;
      }
    }

    // DDoS-Oriented Metrics
    const uniqueSourceIps = new Set(sourceIps).size;
    const sourceIpEntropy = calculateShannonEntropy(sourceIps);
    const destinationConcentration = calculateDestinationHHI(destIps, destWeights);

    const synToAckRatio = ackCount > 0
      ? Number((synCount / ackCount).toFixed(2))
      : synCount > 0
      ? Number(Math.min(99.9, synCount).toFixed(1))
      : 1.0;

    let trafficGrowthRate = 0;
    if (previousWindowPPS > 0) {
      trafficGrowthRate = Number((((packetsPerSecond - previousWindowPPS) / previousWindowPPS) * 100).toFixed(1));
    }
    previousWindowPPS = packetsPerSecond;

    // C2-Oriented Metrics
    const connectionFrequency = Number(((activeObs.length / windowDurationSec) * 60).toFixed(1)); // conn/min

    let iatMean = 0;
    let iatStdDev = 0;
    let iatMin = 0;
    let iatMax = 0;
    let cv = 0;
    let periodicityScore = 0;

    if (interArrivals.length > 0) {
      iatMin = Number(Math.min(...interArrivals).toFixed(2));
      iatMax = Number(Math.max(...interArrivals).toFixed(2));
      const iatSum = interArrivals.reduce((a, b) => a + b, 0);
      iatMean = Number((iatSum / interArrivals.length).toFixed(2));

      const variance = interArrivals.reduce((acc, val) => acc + Math.pow(val - iatMean, 2), 0) / interArrivals.length;
      iatStdDev = Number(Math.sqrt(variance).toFixed(2));

      if (iatMean > 0) {
        cv = Number((iatStdDev / iatMean).toFixed(3));
        // Periodicity score: High when CV is very low (low jitter)
        periodicityScore = Number(Math.max(0, 1 - Math.min(1.0, cv)).toFixed(3));
      }
    } else {
      // Default to 1.0s synthetic step if uniform flows
      iatMean = Number((windowDurationSec / Math.max(1, activeObs.length)).toFixed(2));
      periodicityScore = 0.5;
    }

    // Packet size consistency: 1 - min(1, stdDev / avg)
    const packetSizeConsistency = avgPacketSize > 0
      ? Number(Math.max(0, 1 - Math.min(1.0, packetSizeStdDev / avgPacketSize)).toFixed(3))
      : 1.0;

    // Jitter percentage: (stdDev / mean) * 100%
    const jitterPercentage = iatMean > 0 ? Number(((iatStdDev / iatMean) * 100).toFixed(1)) : 0;

    // Destination repetition count: max count to a single destination
    let maxRepetition = 0;
    for (const cnt of dstCounts.values()) {
      if (cnt > maxRepetition) maxRepetition = cnt;
    }

    // Heuristic Threat Tag for feature record preview
    let threatTag: FeatureVector['detectedThreatIndicator'] = 'Normal';
    if (synCount > 20 && synToAckRatio > 10) {
      threatTag = 'SYN Flood';
    } else if (sourceIpEntropy > 6.5) {
      threatTag = 'Spoofed-Source Flood';
    } else if (protoCounts['NTP'] > 20 || (primaryProtocol === 'UDP' && bytesPerSecond > 500000 && destinationConcentration > 0.8)) {
      threatTag = 'UDP Reflection/Amplification';
    } else if (primaryProtocol === 'UDP' && packetsPerSecond > 20000) {
      threatTag = 'UDP Flood';
    } else if (periodicityScore >= 0.75 && jitterPercentage <= 15 && activeObs.length >= 3) {
      threatTag = 'Botnet C2 Beaconing';
    } else if (trafficGrowthRate > 150) {
      threatTag = 'Anomaly';
    }

    const windowMidMs = Math.round((currentWindowStart + currentWindowEnd) / 2);
    const windowTimeStr = new Date(windowMidMs).toISOString().replace('T', ' ').substring(11, 19);

    featureVectors.push({
      id: `feat-win-${windowIndex + 1}`,
      windowIndex: windowIndex + 1,
      windowStartMs: currentWindowStart,
      windowEndMs: currentWindowEnd,
      windowDurationSec,
      timestamp: windowTimeStr,
      sourceSummary: uniqueSourceIps > 1 ? `${dominantSrcIp} (+${uniqueSourceIps - 1} hosts)` : dominantSrcIp,
      destinationSummary: `${dominantDstIp}:${dominantDstPort}`,
      protocol: primaryProtocol,
      packetCount: totalPackets,
      byteCount: totalBytes,
      flowDurationMs,
      packetsPerSecond,
      bytesPerSecond,
      averagePacketSize: avgPacketSize,
      minPacketSize,
      maxPacketSize,
      primaryProtocol,
      sourceIp: dominantSrcIp,
      destinationIp: dominantDstIp,
      sourcePort: dominantSrcPort,
      destinationPort: dominantDstPort,
      synPacketCount: synCount,
      ackPacketCount: ackCount,
      synToAckRatio,
      uniqueSourceIpCount: uniqueSourceIps,
      sourceIpEntropy,
      destinationConcentration,
      trafficGrowthRate,
      connectionFrequency,
      interArrivalTimeMean: iatMean,
      interArrivalTimeStdDev: iatStdDev,
      interArrivalTimeMin: iatMin,
      interArrivalTimeMax: iatMax,
      coefficientOfVariation: cv,
      periodicityScore,
      destinationRepetitionCount: maxRepetition,
      packetSizeConsistency,
      jitterPercentage,
      observationCount: activeObs.length,
      detectedThreatIndicator: threatTag
    });

    windowIndex++;
    currentWindowStart += stepMs;

    // Safety guard to avoid runaway iterations
    if (windowIndex > 100) break;
  }

  // Compute Overall Dataset Summary
  let allPkts = 0;
  let allBytes = 0;
  const allSourceIps = new Set<string>();
  const allDestIps = new Set<string>();
  const overallProtos: Record<string, number> = {};

  observations.forEach((obs) => {
    allPkts += obs.packetCount;
    allBytes += obs.byteCount;
    allSourceIps.add(obs.sourceIp);
    allDestIps.add(obs.destinationIp);
    overallProtos[obs.protocol] = (overallProtos[obs.protocol] || 0) + obs.packetCount;
  });

  const totalDurationSec = Math.max(1, (maxTs - minTs) / 1000);
  const avgPPS = Math.round(allPkts / totalDurationSec);
  const avgBPS = Math.round(allBytes / totalDurationSec);

  const protocolPercentages: Record<string, number> = {};
  for (const [proto, count] of Object.entries(overallProtos)) {
    protocolPercentages[proto] = Number(((count / Math.max(1, allPkts)) * 100).toFixed(1));
  }

  const avgEntropy = featureVectors.length > 0
    ? Number((featureVectors.reduce((acc, f) => acc + f.sourceIpEntropy, 0) / featureVectors.length).toFixed(2))
    : 0;

  const peakPeriodicity = featureVectors.length > 0
    ? Number(Math.max(...featureVectors.map((f) => f.periodicityScore)).toFixed(3))
    : 0;

  const summary: PassiveDatasetSummary = {
    totalFlows: observations.length,
    totalPackets: allPkts,
    totalBytes: allBytes,
    analysisWindow: `${config.windowDurationSeconds}s window / ${config.stepSeconds}s step`,
    protocolsObserved: overallProtos,
    protocolPercentages,
    uniqueSourceIps: allSourceIps.size,
    uniqueDestinationIps: allDestIps.size,
    averagePacketRate: avgPPS,
    averageByteRate: avgBPS,
    averageEntropy: avgEntropy,
    peakPeriodicityScore: peakPeriodicity,
    timeRangeStart: new Date(minTs).toISOString().replace('T', ' ').substring(0, 19),
    timeRangeEnd: new Date(maxTs).toISOString().replace('T', ' ').substring(0, 19)
  };

  return {
    featureVectors,
    summary
  };
}

function getEmptySummary(config: SlidingWindowConfig): PassiveDatasetSummary {
  return {
    totalFlows: 0,
    totalPackets: 0,
    totalBytes: 0,
    analysisWindow: `${config.windowDurationSeconds}s window / ${config.stepSeconds}s step`,
    protocolsObserved: {},
    protocolPercentages: {},
    uniqueSourceIps: 0,
    uniqueDestinationIps: 0,
    averagePacketRate: 0,
    averageByteRate: 0,
    averageEntropy: 0,
    peakPeriodicityScore: 0,
    timeRangeStart: 'N/A',
    timeRangeEnd: 'N/A'
  };
}
