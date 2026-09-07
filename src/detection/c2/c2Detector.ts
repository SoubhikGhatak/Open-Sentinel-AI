/**
 * Dedicated Passive Botnet C2 Beacon Detection Engine
 * 
 * Strict Passive Invariant:
 * The system remains completely passive. It performs ZERO active scanning,
 * probing, DNS queries, TCP handshakes, callbacks, packet transmissions,
 * or mitigation commands back to monitored endpoints.
 * 
 * Detection methodology:
 * 1. Flow inter-arrival time (IAT)
 * 2. Mean IAT
 * 3. Standard deviation of IAT
 * 4. Coefficient of variation (CV = sigma / mu)
 * 5. Periodicity score
 * 6. Connection frequency (Hz)
 * 7. Repeated destination IP/domain/port concentration
 * 8. Packet-size consistency
 * 9. Destination concentration
 * 10. Temporal regularity
 * 
 * Scoring mechanism:
 * Transparent "Passive Behavioural Analysis" model normalizing:
 * C2 Confidence = periodicity (25%) + IAT regularity (20%) + destination repetition (20%)
 *               + connection frequency (15%) + packet-size consistency (20%) = 100%
 */

import { TrafficFlow, C2BeaconCluster, ProtocolType } from '../types';
import { ENGINE_CONFIG } from '../config';
import { analyzeTemporalPeriodicity } from '../features/spectral';

// Known simulated passive domain mappings
const KNOWN_DESTINATION_DOMAINS: Record<string, string> = {
  '185.220.101.42': 'cdn-cloudsync-telemetry.org',
  '194.26.29.114': 'edge-analytics-sync.org',
  '198.51.100.220': 'fastpoll-session-stream.io',
  '203.0.113.155': 'update-catalog-cache.com',
  '198.51.100.89': 'telemetry-service-cloud.net',
  '192.168.10.50': 'corp-dc01.corp.internal',
  '192.168.10.45': 'portal-ingress-vip.corp.internal',
  '192.168.20.10': 'database-cluster.corp.internal',
  '192.168.10.1': 'api-gateway.corp.internal',
  '216.239.35.0': 'time.google.com',
  '129.6.15.28': 'time.nist.gov'
};

export function detectC2Beacons(flows: TrafficFlow[]): C2BeaconCluster[] {
  if (!flows || flows.length === 0) return [];

  // 1. Calculate total outbound flows per source IP to compute real destination concentration
  const hostOutboundCounts: Map<string, number> = new Map();
  for (const flow of flows) {
    hostOutboundCounts.set(flow.sourceIP, (hostOutboundCounts.get(flow.sourceIP) || 0) + 1);
  }

  // 2. Group flows by conversational pairing: (source IP -> destination IP:destination Port)
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
    const protocol: ProtocolType = firstFlow.protocol;
    const destDomain = KNOWN_DESTINATION_DOMAINS[destIp] || (destPort === 123 ? 'pool.ntp.org' : `node-${destIp.replace(/\./g, '-')}.net`);

    // 3. Compute Inter-Arrival Times (IAT)
    const intervalsMs: number[] = [];
    const timelineEvents: C2BeaconCluster['timelineEvents'] = [];

    for (let i = 0; i < convFlows.length; i++) {
      const current = convFlows[i];
      let deltaMs = 0;
      if (i > 0) {
        deltaMs = current.timestampMs - convFlows[i - 1].timestampMs;
        if (deltaMs > 0) {
          intervalsMs.push(deltaMs);
        }
      }

      timelineEvents.push({
        id: current.id || `tl-${i}`,
        timestamp: current.timestamp ? current.timestamp.replace('T', ' ').substring(0, 19) : new Date(current.timestampMs).toISOString().replace('T', ' ').substring(0, 19),
        timestampMs: current.timestampMs,
        sourceIp,
        destinationIp: destIp,
        destinationPort: destPort,
        bytes: current.byteCount,
        intervalSeconds: Number((deltaMs / 1000).toFixed(2))
      });
    }

    // Also include any internal inter-arrival times from within the flow records if single flow with bursts
    for (const flow of convFlows) {
      if (flow.interArrivalTimes && flow.interArrivalTimes.length > 0) {
        for (const iat of flow.interArrivalTimes) {
          if (iat > 0) intervalsMs.push(iat);
        }
      }
    }

    // 4. Collect packet sizes across all flows in the conversation
    const sizes: number[] = [];
    for (const flow of convFlows) {
      if (flow.packetSizes && flow.packetSizes.length > 0) {
        sizes.push(...flow.packetSizes);
      } else {
        sizes.push(Math.round(flow.byteCount / (flow.packetCount || 1)));
      }
    }

    // 5. Statistical moments of Packet Size
    const sizeSum = sizes.reduce((a, b) => a + b, 0);
    const sizeMean = sizes.length > 0 ? Math.round(sizeSum / sizes.length) : 0;
    const sizeVar = sizes.length > 0 ? sizes.reduce((acc, s) => acc + Math.pow(s - sizeMean, 2), 0) / sizes.length : 0;
    const sizeStdDev = Math.round(Math.sqrt(sizeVar));

    // Packet-size consistency (0.0 - 1.0): 1 = completely identical packet sizes
    const sizeTolerance = Math.max(15, sizeMean * 0.20);
    const packetSizeConsistency = sizeMean > 0
      ? Number(Math.max(0, 1 - Math.min(1, sizeStdDev / sizeTolerance)).toFixed(2))
      : 0;

    // 6. Spectral & Temporal Periodicity Analysis
    const spectral = analyzeTemporalPeriodicity(intervalsMs);
    const meanSec = Number((spectral.meanIntervalMs / 1000).toFixed(2));
    const stdDevSec = Number((spectral.stdDevIntervalMs / 1000).toFixed(2));
    const cv = Number(spectral.coefficientOfVariation.toFixed(3)); // sigma / mu
    const jitterPct = Number(spectral.jitterPercentage.toFixed(1));
    const periodicityScore = Number(spectral.periodicityScore.toFixed(2)); // 0.0 - 1.0
    const connectionFrequencyHz = meanSec > 0 ? Number((1 / meanSec).toFixed(4)) : 0;

    // 7. Destination Concentration
    const totalHostOutbound = hostOutboundCounts.get(sourceIp) || convFlows.length;
    const destinationConcentration = Number((convFlows.length / totalHostOutbound).toFixed(2));

    // 8. IAT Regularity (0.0 - 1.0)
    const iatRegularityScore = Number(Math.max(0, 1 - Math.min(1, jitterPct / 25)).toFixed(2));

    // 9. Destination Repetition Factor (0.0 - 1.0)
    const destinationRepetition = Number(Math.min(1.0, Math.max(convFlows.length, intervalsMs.length) / 12).toFixed(2));

    // 10. Connection Frequency Suitability (0.0 - 1.0)
    // Automated beacons typically range from 0.003 Hz (300s sleep) to 1.0 Hz (1s fast beacon)
    let connectionFreqScore = 0.5;
    if (meanSec >= 2 && meanSec <= 360) {
      connectionFreqScore = 1.0;
    } else if (meanSec > 0) {
      connectionFreqScore = 0.7;
    }

    // 11. Transparent Scoring Model ("Passive Behavioural Analysis"):
    // Total 100 points:
    // • Periodicity Score (25%)
    // • IAT Regularity / Low Jitter (20%)
    // • Destination Repetition & Concentration (20%)
    // • Connection Frequency (15%)
    // • Packet-Size Consistency (20%)
    const periodicityContrib = Number((periodicityScore * 25).toFixed(1));
    const iatRegularityContrib = Number((iatRegularityScore * 20).toFixed(1));
    const destinationRepetitionContrib = Number(((destinationRepetition * 0.5 + destinationConcentration * 0.5) * 20).toFixed(1));
    const connectionFreqContrib = Number((connectionFreqScore * 15).toFixed(1));
    const packetSizeConsistencyContrib = Number((packetSizeConsistency * 20).toFixed(1));

    let c2Confidence = Math.min(100, Math.max(5, Math.round(
      periodicityContrib +
      iatRegularityContrib +
      destinationRepetitionContrib +
      connectionFreqContrib +
      packetSizeConsistencyContrib
    )));

    // 12. Benign Periodic vs Malicious C2 Distinction:
    // If destination is standard time sync (NTP 123) or known benign DNS/health check:
    const isNtpService = destPort === 123 || protocol === 'NTP';
    const isStandardDns = destPort === 53 && (destIp === '192.168.10.50' || destIp === '8.8.8.8');
    const isBenignService = isNtpService || isStandardDns;

    let classification: C2BeaconCluster['classification'] = 'Background Traffic';
    let severity: 'Critical' | 'High' | 'Medium' | 'Low' = 'Low';
    let potentialFamily: string | undefined = undefined;
    const evidence: string[] = [];

    if (isBenignService) {
      classification = 'Benign Periodic Traffic';
      severity = 'Low';
      c2Confidence = Math.min(22, Math.round(c2Confidence * 0.25));
      evidence.push(`THREAT: NONE (BENIGN SERVICE DETECTED)`);
      evidence.push(`Confidence: ${c2Confidence}% | Severity: LOW`);
      evidence.push(`Evidence:`);
      evidence.push(`• Benign periodic protocol recognized: ${isNtpService ? 'Network Time Protocol (NTP port 123)' : 'Standard DNS Query (port 53)'}`);
      evidence.push(`• ${convFlows.length} scheduled synchronization pulses to ${destDomain}`);
      evidence.push(`• Mean IAT: ${meanSec} seconds (expected routine synchronization interval)`);
      evidence.push(`• Standard system heartbeat filtered from threat alerting queue`);
      potentialFamily = 'Benign System Service (NTP/DNS Routine Sync)';
    } else if (intervalsMs.length < 2 && convFlows.length < 3) {
      classification = 'Background Traffic';
      severity = 'Low';
      c2Confidence = Math.min(20, c2Confidence);
      evidence.push(`THREAT: BACKGROUND TRAFFIC`);
      evidence.push(`Confidence: ${c2Confidence}% | Severity: LOW`);
      evidence.push(`Evidence:`);
      evidence.push(`• Sparse interaction (${convFlows.length} flows observed, ${intervalsMs.length} intervals)`);
      evidence.push(`• Insufficient temporal evidence for beacon classification`);
      evidence.push(`• Variable packet sizes: mean ${sizeMean}B (σ = ${sizeStdDev}B)`);
    } else if (c2Confidence >= 75 && convFlows.length >= 3 && jitterPct <= 20) {
      classification = 'High-Confidence C2 Beacon';
      severity = c2Confidence >= 90 ? 'Critical' : 'High';

      evidence.push(`THREAT: BOTNET C2 BEACONING`);
      evidence.push(`Confidence: ${c2Confidence}% | Severity: ${severity}`);
      evidence.push(`Evidence:`);
      evidence.push(`• ${convFlows.length} repeated connections to the same destination (${destIp}:${destPort})`);
      evidence.push(`• Mean IAT: ${meanSec} seconds`);
      evidence.push(`• Standard deviation of IAT: ${stdDevSec} seconds`);
      evidence.push(`• Coefficient of variation: ${cv}`);
      evidence.push(`• Periodicity score: ${periodicityScore}`);
      evidence.push(`• Destination concentration: ${destinationConcentration}`);
      evidence.push(`• Consistent packet-size pattern detected (mean: ${sizeMean} B, σ: ${sizeStdDev} B)`);
      evidence.push(`• Passive Behavioural Analysis score: ${c2Confidence} / 100`);

      if (spectral.hasSufficientSamples && spectral.peakSpectralPower && spectral.peakSpectralPower > 0.5) {
        evidence.push(`• Spectral FFT peak detected at ${spectral.dominantFrequencyHz} Hz (${(spectral.peakSpectralPower * 100).toFixed(0)}% spectral power)`);
      } else {
        evidence.push(`• ${spectral.statusMessage}`);
      }

      // Behavioral heuristic correlation
      if (Math.abs(meanSec - 30) < 6 && sizeMean >= 300 && sizeMean <= 400) {
        potentialFamily = 'Simulated Cobalt Strike-like beacon pattern (30s sleep profile, uniform payload)';
      } else if (Math.abs(meanSec - 45) < 6 && sizeMean >= 300 && sizeMean <= 400) {
        potentialFamily = 'Simulated Cobalt Strike-like beacon pattern (45s sleep profile, uniform payload)';
      } else if (meanSec <= 10 && sizeMean <= 300) {
        potentialFamily = 'Simulated High-Frequency interactive C2 session (5s heartbeat profile)';
      } else if (meanSec >= 120) {
        potentialFamily = 'Simulated Low-and-Slow APT implant beacon (stealth extended sleep)';
      } else if (jitterPct >= 10) {
        potentialFamily = 'Simulated Jittered C2 beacon with evasion randomness profile';
      } else {
        potentialFamily = 'Simulated C2 beacon scenario';
      }
    } else if (c2Confidence >= 55) {
      classification = 'Suspicious Periodic Communication';
      severity = 'High';
      evidence.push(`THREAT: SUSPICIOUS PERIODIC COMMUNICATION`);
      evidence.push(`Confidence: ${c2Confidence}% | Severity: HIGH`);
      evidence.push(`Evidence:`);
      evidence.push(`• ${convFlows.length} recurring connections to ${destIp}:${destPort}`);
      evidence.push(`• Mean IAT: ${meanSec} seconds with ${jitterPct}% jitter`);
      evidence.push(`• Periodicity score: ${periodicityScore}`);
      evidence.push(`• Destination concentration: ${destinationConcentration}`);
      evidence.push(`• Packet sizes: mean ${sizeMean} B, σ = ${sizeStdDev} B`);
      evidence.push(`• Passive Behavioural Analysis score: ${c2Confidence} / 100`);
      potentialFamily = 'Suspicious Periodic Callback Profile';
    } else if (c2Confidence >= 35) {
      classification = 'Potential C2 Beacon';
      severity = 'Medium';
      evidence.push(`THREAT: POTENTIAL C2 BEACON`);
      evidence.push(`Confidence: ${c2Confidence}% | Severity: MEDIUM`);
      evidence.push(`Evidence:`);
      evidence.push(`• Weak periodicity observed (score: ${periodicityScore}, jitter: ${jitterPct}%)`);
      evidence.push(`• Mean IAT: ${meanSec}s across ${convFlows.length} connections`);
      evidence.push(`• Passive Behavioural Analysis score: ${c2Confidence} / 100`);
    } else {
      classification = 'Background Traffic';
      severity = 'Low';
      evidence.push(`THREAT: BACKGROUND TRAFFIC`);
      evidence.push(`Confidence: ${c2Confidence}% | Severity: LOW`);
      evidence.push(`Evidence:`);
      evidence.push(`• Nominal organic interaction: high jitter (${jitterPct}%) and variable payload sizes`);
      evidence.push(`• Dispersed destination pattern (concentration: ${destinationConcentration})`);
    }

    const firstSeen = convFlows[0]?.timestamp || new Date(convFlows[0].timestampMs).toISOString();
    const lastSeen = convFlows[convFlows.length - 1]?.timestamp || new Date(convFlows[convFlows.length - 1].timestampMs).toISOString();

    clusters.push({
      id: `c2-${key.replace(/[^a-zA-Z0-9]/g, '-')}`,
      sourceIp,
      destinationIp: destIp,
      destinationDomain: destDomain,
      destinationPort: destPort,
      protocol,
      connectionCount: convFlows.length,
      meanIntervalSeconds: meanSec,
      stdDevIntervalSeconds: stdDevSec,
      coefficientOfVariation: cv,
      jitterPercentage: jitterPct,
      connectionFrequencyHz,
      packetSizeMean: sizeMean,
      packetSizeStdDev: sizeStdDev,
      packetSizeConsistency,
      periodicityScore,
      iatRegularityScore,
      c2Confidence,
      c2SuspicionScore: c2Confidence,
      destinationConcentration,
      payloadConsistencyScore: packetSizeConsistency,
      severity,
      classification,
      potentialC2FamilyCorrelation: potentialFamily,
      evidence,
      firstSeen,
      lastSeen,
      fftStatus: spectral.statusMessage,
      fftPeakPower: spectral.peakSpectralPower || (periodicityScore * 0.9),
      scoreBreakdown: {
        periodicityContrib,
        iatRegularityContrib,
        destinationRepetitionContrib,
        connectionFreqContrib,
        packetSizeConsistencyContrib
      },
      timelineEvents
    });
  }

  // Sort: High-Confidence C2 Beacon first, then suspicious, then potential, then benign, then background
  clusters.sort((a, b) => {
    const score = (c: C2BeaconCluster) =>
      c.classification === 'High-Confidence C2 Beacon' || c.classification === 'High-confidence Beaconing Pattern' ? 5 :
      c.classification === 'Suspicious Periodic Communication' || c.classification === 'Suspicious Periodic Traffic' ? 4 :
      c.classification === 'Potential C2 Beacon' ? 3 :
      c.classification === 'Benign Periodic Traffic' ? 2 : 1;
    return (score(b) * 1000 + b.c2Confidence) - (score(a) * 1000 + a.c2Confidence);
  });

  return clusters;
}
