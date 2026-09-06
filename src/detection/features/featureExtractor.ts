/**
 * Comprehensive Feature Extraction Module
 * Extracts General, DDoS, C2, Anomaly, and Data Quality features from normalized TrafficFlow batches.
 */

import { TrafficFlow, FlowFeatures, ProtocolType, BaselineMetrics } from '../types';
import { ENGINE_CONFIG } from '../config';
import { evaluateSourceIpEntropy } from './entropy';
import { calculateDestinationConcentration } from './concentration';
import { analyzeTemporalPeriodicity } from './spectral';

export function extractFlowFeatures(
  flows: TrafficFlow[],
  baseline: BaselineMetrics = ENGINE_CONFIG.baseline,
  timeWindowOverrideMs?: number
): FlowFeatures {
  if (!flows || flows.length === 0) {
    return getEmptyFeatures(baseline);
  }

  // 1. Time Window and Counts
  let minTime = Infinity;
  let maxTime = -Infinity;
  let totalPackets = 0;
  let totalBytes = 0;
  const sourceIps: string[] = [];
  const destIps: string[] = [];
  const destWeights: number[] = [];
  const allPacketSizes: number[] = [];
  const allInterArrivals: number[] = [];
  const protoCounts: Record<ProtocolType, number> = {
    TCP: 0,
    UDP: 0,
    ICMP: 0,
    DNS: 0,
    TLS: 0,
    NTP: 0,
    SSDP: 0,
    OTHER: 0
  };
  const portCounts: Map<number, number> = new Map();

  let synCount = 0;
  let ackCount = 0;
  let udpCount = 0;

  for (const flow of flows) {
    if (flow.timestampMs < minTime) minTime = flow.timestampMs;
    if (flow.timestampMs + flow.durationMs > maxTime) maxTime = flow.timestampMs + flow.durationMs;

    totalPackets += flow.packetCount;
    totalBytes += flow.byteCount;

    sourceIps.push(flow.sourceIP);
    destIps.push(flow.destinationIP);
    destWeights.push(flow.packetCount);

    protoCounts[flow.protocol] = (protoCounts[flow.protocol] || 0) + flow.packetCount;
    portCounts.set(flow.destinationPort, (portCounts.get(flow.destinationPort) || 0) + flow.packetCount);
    portCounts.set(flow.sourcePort, (portCounts.get(flow.sourcePort) || 0) + flow.packetCount);

    if (flow.protocol === 'UDP' || flow.protocol === 'NTP' || flow.protocol === 'DNS' || flow.protocol === 'SSDP') {
      udpCount += flow.packetCount;
    }

    if (flow.tcpFlags) {
      for (const flag of flow.tcpFlags) {
        if (flag.includes('SYN') && !flag.includes('ACK')) synCount += flow.packetCount;
        if (flag.includes('ACK')) ackCount += flow.packetCount;
      }
    }

    if (flow.packetSizes && flow.packetSizes.length > 0) {
      allPacketSizes.push(...flow.packetSizes);
    } else {
      const avg = Math.round(flow.byteCount / (flow.packetCount || 1));
      allPacketSizes.push(avg);
    }

    if (flow.interArrivalTimes && flow.interArrivalTimes.length > 0) {
      allInterArrivals.push(...flow.interArrivalTimes);
    } else if (flow.durationMs > 0 && flow.packetCount > 1) {
      const avgIat = flow.durationMs / (flow.packetCount - 1);
      allInterArrivals.push(avgIat);
    }
  }

  const windowDurationMs = timeWindowOverrideMs || Math.max(1000, maxTime - minTime || 2000);
  const windowDurationSec = windowDurationMs / 1000;

  // General Feature Calculations
  const packetsPerSecond = Math.round(totalPackets / windowDurationSec);
  const bytesPerSecond = Math.round(totalBytes / windowDurationSec);

  let avgPacketSize = 0;
  let packetSizeStdDev = 0;
  let variance = 0;
  if (allPacketSizes.length > 0) {
    avgPacketSize = allPacketSizes.reduce((a, b) => a + b, 0) / allPacketSizes.length;
    variance = allPacketSizes.reduce((a, b) => a + Math.pow(b - avgPacketSize, 2), 0) / allPacketSizes.length;
    packetSizeStdDev = Math.sqrt(variance);
  }

  const uniqueSourceIps = new Set(sourceIps).size;
  const uniqueDestIps = new Set(destIps).size;

  const protocolList: ProtocolType[] = ['TCP', 'UDP', 'ICMP', 'DNS', 'TLS', 'NTP', 'SSDP', 'OTHER'];
  const protocolPercentages: Record<ProtocolType, number> = {
    TCP: 0,
    UDP: 0,
    ICMP: 0,
    DNS: 0,
    TLS: 0,
    NTP: 0,
    SSDP: 0,
    OTHER: 0
  };

  if (totalPackets > 0) {
    let runningSum = 0;
    let dominantProto: ProtocolType = 'TCP';
    let highestCount = -1;

    for (const proto of protocolList) {
      const count = protoCounts[proto] || 0;
      const pct = Number(((count / totalPackets) * 100).toFixed(1));
      protocolPercentages[proto] = pct;
      runningSum += pct;
      if (count > highestCount) {
        highestCount = count;
        dominantProto = proto;
      }
    }

    // Mathematically balance any floating point / toFixed(1) residual so sum is exactly 100.0%
    const residual = Number((100.0 - runningSum).toFixed(1));
    if (residual !== 0 && highestCount > 0) {
      protocolPercentages[dominantProto] = Number((protocolPercentages[dominantProto] + residual).toFixed(1));
    }
  }

  const topPorts = Array.from(portCounts.entries())
    .map(([port, count]) => ({
      port,
      count,
      percentage: totalPackets > 0 ? Number(((count / totalPackets) * 100).toFixed(1)) : 0
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  const destPortDistribution: Record<number, number> = {};
  for (const [p, c] of portCounts.entries()) {
    destPortDistribution[p] = c;
  }

  // 2. DDoS Features
  const entropyResult = evaluateSourceIpEntropy(sourceIps, baseline.baselineEntropy);
  const concentrationResult = calculateDestinationConcentration(destIps, destWeights);

  const synPacketRate = Math.round(synCount / windowDurationSec);
  const ackPacketRate = Math.round(ackCount / windowDurationSec);
  const udpPacketRate = Math.round(udpCount / windowDurationSec);
  const synToAckRatio = ackCount > 0 ? Number((synCount / ackCount).toFixed(2)) : synCount > 0 ? 50.0 : 1.0;

  const ppsDeviationFromBaseline = Number((packetsPerSecond / (baseline.baselinePacketsPerSecond || 1)).toFixed(2));
  const bpsDeviationFromBaseline = Number((bytesPerSecond / (baseline.baselineBytesPerSecond || 1)).toFixed(2));
  const uniqueSourceRatio = totalPackets > 0 ? Number((uniqueSourceIps / totalPackets).toFixed(3)) : 0;

  const targetVIPConcentration = concentrationResult.topTargets.map((t) => ({
    ip: t.destination,
    count: t.count,
    percentage: t.sharePercentage
  }));

  const halfOpenEstimate = Math.max(0, synCount - ackCount);

  // 3. C2 Features
  const spectralResult = analyzeTemporalPeriodicity(allInterArrivals);

  // Connection interval consistency: 1 - min(1, CV)
  const intervalConsistency = Number(Math.max(0, 1 - Math.min(1, spectralResult.coefficientOfVariation)).toFixed(2));
  // Packet size consistency: 1 - min(1, stdDev / avg)
  const sizeConsistency = avgPacketSize > 0 ? Number(Math.max(0, 1 - Math.min(1, packetSizeStdDev / avgPacketSize)).toFixed(2)) : 0;

  // Destination persistence: max repeated contacts to single external destination
  const destFrequencyMap: Map<string, number> = new Map();
  for (const dst of destIps) {
    destFrequencyMap.set(dst, (destFrequencyMap.get(dst) || 0) + 1);
  }
  let maxRepeatedDestCount = 0;
  for (const count of destFrequencyMap.values()) {
    if (count > maxRepeatedDestCount) maxRepeatedDestCount = count;
  }

  // 4. Anomaly Features (Statistically Grounded Z-Scores)
  const zScorePPS = Number(((packetsPerSecond - baseline.baselinePacketsPerSecond) / (baseline.baselinePacketsPerSecond * 0.25)).toFixed(2));
  const zScoreBPS = Number(((bytesPerSecond - baseline.baselineBytesPerSecond) / (baseline.baselineBytesPerSecond * 0.30)).toFixed(2));
  const zScoreEntropy = Number(((entropyResult.entropy - baseline.baselineEntropy) / 0.5).toFixed(2));
  const entropyDeviation = entropyResult.deviation;
  const trafficRateDeviation = Number(Math.max(0, ppsDeviationFromBaseline - 1.0).toFixed(2));

  let unusualProtocolDeviation = 0;
  if (protocolPercentages.UDP > 60 || protocolPercentages.NTP > 20 || protocolPercentages.TCP > 85) {
    unusualProtocolDeviation = 1.8;
  }

  const unusualDestinationConcentration = Number((concentrationResult.hhi - baseline.baselineDestinationHHI).toFixed(2));

  // Statistically Grounded Anomaly Score (0 - 100)
  let rawAnomalyScore = 0;
  if (zScorePPS > 2) rawAnomalyScore += Math.min(35, zScorePPS * 8);
  if (zScoreBPS > 2) rawAnomalyScore += Math.min(25, zScoreBPS * 5);
  if (Math.abs(zScoreEntropy) > 2) rawAnomalyScore += Math.min(20, Math.abs(zScoreEntropy) * 7);
  if (concentrationResult.hhi > 0.75) rawAnomalyScore += 20;

  const anomalyScore = Math.min(100, Math.max(0, Math.round(rawAnomalyScore)));

  // 5. Data Quality Assessment
  const qualityReasons: string[] = [];
  let qualityScore = 100;

  if (flows.length < 5) {
    qualityScore -= 40;
    qualityReasons.push(`Low flow sample count (${flows.length} flows).`);
  } else if (flows.length < 20) {
    qualityScore -= 15;
    qualityReasons.push(`Moderate flow sample count (${flows.length} flows).`);
  }

  if (windowDurationSec < 3) {
    qualityScore -= 20;
    qualityReasons.push(`Short temporal observation window (${windowDurationSec.toFixed(1)}s).`);
  }

  if (allInterArrivals.length < ENGINE_CONFIG.c2.minSamplesForFFT) {
    qualityReasons.push(`Limited temporal samples (${allInterArrivals.length} intervals, min ${ENGINE_CONFIG.c2.minSamplesForFFT} needed for spectral FFT).`);
  }

  let qualityLevel: 'HIGH' | 'MEDIUM' | 'LOW' = 'HIGH';
  if (qualityScore < 50) {
    qualityLevel = 'LOW';
  } else if (qualityScore < 80) {
    qualityLevel = 'MEDIUM';
  }

  return {
    timeWindowMs: windowDurationMs,
    general: {
      packetsPerSecond,
      bytesPerSecond,
      averagePacketSize: Number(avgPacketSize.toFixed(1)),
      packetSizeStdDev: Number(packetSizeStdDev.toFixed(1)),
      packetSizeVariance: Number(variance.toFixed(1)),
      flowDurationMs: windowDurationMs,
      flowDuration: Number(windowDurationSec.toFixed(2)),
      connectionFrequency: Number((flows.length / windowDurationSec).toFixed(2)),
      packetCount: totalPackets,
      byteCount: totalBytes,
      uniqueSourceIPCount: uniqueSourceIps,
      uniqueDestinationIPCount: uniqueDestIps,
      protocolDistribution: protoCounts,
      protocolPercentages,
      destinationPortDistribution: destPortDistribution,
      topDestinationPorts: topPorts
    },
    ddos: {
      synPacketRate,
      ackPacketRate,
      synToAckRatio,
      udpPacketRate,
      sourceIPCount: uniqueSourceIps,
      sourceIPEntropy: entropyResult.entropy,
      destinationConcentrationHHI: concentrationResult.hhi,
      ppsDeviationFromBaseline,
      bpsDeviationFromBaseline,
      uniqueSourceRatio,
      targetVIPConcentration,
      halfOpenEstimate
    },
    c2: {
      meanInterArrivalTimeMs: spectralResult.meanIntervalMs,
      stdDevInterArrivalTimeMs: spectralResult.stdDevIntervalMs,
      coefficientOfVariation: spectralResult.coefficientOfVariation,
      periodicityScore: spectralResult.periodicityScore,
      jitterPercentage: spectralResult.jitterPercentage,
      connectionCount: flows.length,
      destinationConcentration: concentrationResult.hhi,
      payloadConsistencyScore: sizeConsistency,
      repeatedDestinationFrequency: maxRepeatedDestCount,
      repeatedConnectionFrequency: flows.length,
      packetSizeConsistency: sizeConsistency,
      connectionIntervalConsistency: intervalConsistency,
      destinationPersistenceSeconds: windowDurationSec,
      fftAnalysis: {
        hasSufficientSamples: spectralResult.hasSufficientSamples,
        sampleCount: spectralResult.sampleCount,
        dominantFrequencyHz: spectralResult.dominantFrequencyHz,
        dominantPeriodSeconds: spectralResult.dominantPeriodSeconds,
        peakSpectralPower: spectralResult.peakSpectralPower,
        statusMessage: spectralResult.statusMessage
      }
    },
    anomaly: {
      zScorePPS,
      zScoreBPS,
      zScoreEntropy,
      entropyDeviation,
      trafficRateDeviation,
      unusualProtocolDeviation,
      unusualDestinationConcentration,
      anomalyScore,
      methodLabel: 'STATISTICAL ANALYSIS',
      methodDetails: 'Sliding-window z-score baseline divergence and multi-moment entropy variance.'
    },
    dataQuality: {
      level: qualityLevel,
      score: qualityScore,
      flowCount: flows.length,
      packetCount: totalPackets,
      temporalCoverageSeconds: Number(windowDurationSec.toFixed(1)),
      hasPacketLevelDetails: allPacketSizes.length > 0,
      reasons: qualityReasons
    }
  };
}

function getEmptyFeatures(baseline: BaselineMetrics): FlowFeatures {
  return {
    timeWindowMs: 0,
    general: {
      packetsPerSecond: 0,
      bytesPerSecond: 0,
      averagePacketSize: 0,
      packetSizeStdDev: 0,
      packetSizeVariance: 0,
      flowDurationMs: 0,
      flowDuration: 0,
      connectionFrequency: 0,
      packetCount: 0,
      byteCount: 0,
      uniqueSourceIPCount: 0,
      uniqueDestinationIPCount: 0,
      protocolDistribution: { TCP: 0, UDP: 0, ICMP: 0, DNS: 0, TLS: 0, NTP: 0, SSDP: 0, OTHER: 0 },
      protocolPercentages: { TCP: 0, UDP: 0, ICMP: 0, DNS: 0, TLS: 0, NTP: 0, SSDP: 0, OTHER: 0 },
      destinationPortDistribution: {},
      topDestinationPorts: []
    },
    ddos: {
      synPacketRate: 0,
      ackPacketRate: 0,
      synToAckRatio: 1.0,
      udpPacketRate: 0,
      sourceIPCount: 0,
      sourceIPEntropy: baseline.baselineEntropy,
      destinationConcentrationHHI: baseline.baselineDestinationHHI,
      ppsDeviationFromBaseline: 1.0,
      bpsDeviationFromBaseline: 1.0,
      uniqueSourceRatio: 0,
      targetVIPConcentration: [],
      halfOpenEstimate: 0
    },
    c2: {
      meanInterArrivalTimeMs: 0,
      stdDevInterArrivalTimeMs: 0,
      coefficientOfVariation: 0,
      periodicityScore: 0,
      jitterPercentage: 0,
      connectionCount: 0,
      destinationConcentration: 0,
      payloadConsistencyScore: 0,
      repeatedDestinationFrequency: 0,
      repeatedConnectionFrequency: 0,
      packetSizeConsistency: 0,
      connectionIntervalConsistency: 0,
      destinationPersistenceSeconds: 0,
      fftAnalysis: {
        hasSufficientSamples: false,
        sampleCount: 0,
        statusMessage: 'Insufficient temporal samples: No flows available.'
      }
    },
    anomaly: {
      zScorePPS: 0,
      zScoreBPS: 0,
      zScoreEntropy: 0,
      entropyDeviation: 0,
      trafficRateDeviation: 0,
      unusualProtocolDeviation: 0,
      unusualDestinationConcentration: 0,
      anomalyScore: 0,
      methodLabel: 'STATISTICAL ANALYSIS',
      methodDetails: 'Passive sliding window idle.'
    },
    dataQuality: {
      level: 'LOW',
      score: 0,
      flowCount: 0,
      packetCount: 0,
      temporalCoverageSeconds: 0,
      hasPacketLevelDetails: false,
      reasons: ['No flows ingested or observed in this time window.']
    }
  };
}
