/**
 * Dedicated DDoS Detection Engine
 * Multi-signal passive detection for:
 * 1. SYN Flood
 * 2. UDP Flood
 * 3. UDP Reflection / Amplification
 * 4. Spoofed-Source Flood
 * 
 * Strict Passive Optical Monitoring Invariant:
 * Generates ADVISORY mitigations only. The enclave CANNOT inject or transmit.
 */

import { FlowFeatures, DDoSThreatResult } from '../types';
import { ENGINE_CONFIG } from '../config';

export function detectDDoSThreats(features: FlowFeatures): DDoSThreatResult {
  const { ddos, general, anomaly } = features;
  const now = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

  const primaryTarget = ddos.targetVIPConcentration[0] || { ip: 'Unknown VIP', count: 0, percentage: 0 };
  const targetSummary = `${primaryTarget.ip} (${primaryTarget.percentage}% traffic share, HHI ${ddos.destinationConcentrationHHI})`;

  // ==========================================
  // 1. SYN FLOOD DETECTION LOGIC
  // ==========================================
  const synRateExceeded = ddos.synPacketRate > (ENGINE_CONFIG.baseline.baselinePacketsPerSecond * 0.5);
  const synAckImbalanced = ddos.synToAckRatio >= ENGINE_CONFIG.ddos.synToAckImbalanceRatio;
  const synRateSurge = ddos.ppsDeviationFromBaseline >= ENGINE_CONFIG.ddos.synRateMultiplierThreshold;
  const targetConcentrated = ddos.destinationConcentrationHHI >= ENGINE_CONFIG.concentration.moderateConcentration;

  if (synRateExceeded && (synAckImbalanced || (synRateSurge && targetConcentrated))) {
    let confidence = 75;
    const evidence: string[] = [];

    evidence.push(`SYN arrival rate: ${ddos.synPacketRate.toLocaleString()} pps (${ddos.ppsDeviationFromBaseline}x baseline volume)`);

    if (synAckImbalanced) {
      evidence.push(`Severe SYN/ACK imbalance observed: ratio ${ddos.synToAckRatio}:1 (half-open connection buildup)`);
      confidence += 15;
    }

    if (targetConcentrated) {
      evidence.push(`Destination concentration: HHI ${ddos.destinationConcentrationHHI} targeting ${primaryTarget.ip}`);
      confidence += 5;
    }

    if (ddos.sourceIPEntropy > 5.5) {
      evidence.push(`Source IP Shannon entropy: ${ddos.sourceIPEntropy} across ${ddos.sourceIPCount.toLocaleString()} unique source IPs`);
      confidence += 4;
    }

    confidence = Math.min(99, confidence);

    return {
      detected: true,
      threatType: 'SYN Flood',
      confidence,
      severity: confidence >= 85 ? 'Critical' : 'High',
      evidence,
      featureValues: {
        synPacketRate: ddos.synPacketRate,
        synToAckRatio: ddos.synToAckRatio,
        hhi: ddos.destinationConcentrationHHI,
        entropy: ddos.sourceIPEntropy,
        uniqueSources: ddos.sourceIPCount
      },
      timestamp: now,
      sourceSummary: `${ddos.sourceIPCount.toLocaleString()} distributed IP sources`,
      targetSummary,
      mitigationAdvisory: `PASSIVE MITIGATION ADVISORY: Execution is manual/out-of-band. OneWaySentinel AI cannot transmit mitigation commands into the monitored production network. Recommended out-of-band action: Upstream BGP Flowspec rate-limit TCP SYN to ${primaryTarget.ip} or deploy SYN proxy cookies at ingress edge.`
    };
  }

  // ==========================================
  // 2. UDP REFLECTION & AMPLIFICATION LOGIC
  // Multi-signal: port + large response payload + high bandwidth + concentration
  // ==========================================
  const udpPortMap = general.destinationPortDistribution;
  let reflectionPortMatched = false;
  let matchedPort = 0;
  let matchedProtoName = '';

  for (const port of ENGINE_CONFIG.ddos.knownAmplificationPorts) {
    if (udpPortMap[port] && udpPortMap[port] > 10) {
      reflectionPortMatched = true;
      matchedPort = port;
      matchedProtoName = port === 123 ? 'NTP Monlist' : port === 53 ? 'DNS ANY' : port === 11211 ? 'Memcached' : port === 1900 ? 'SSDP' : 'UDP Service';
      break;
    }
  }

  const isLargeUdpPayload = general.averagePacketSize > 900; // Reflected replies are typically MTU-sized (1200-1450 B)
  const isUdpVolumeSurge = ddos.udpPacketRate > (ENGINE_CONFIG.baseline.baselinePacketsPerSecond * 0.4) || general.protocolPercentages.UDP > 55 || general.protocolPercentages.NTP > 30;

  // We require behavioral signals: large payload + surge + reflection port + concentration
  if (reflectionPortMatched && isLargeUdpPayload && isUdpVolumeSurge) {
    let confidence = 82;
    const evidence: string[] = [];

    evidence.push(`Observed asymmetric inbound UDP payload size: ${general.averagePacketSize} bytes/pkt (high amplification profile)`);
    evidence.push(`Service reflection vector: Port ${matchedPort} (${matchedProtoName}) concentrated traffic`);
    evidence.push(`UDP rate surge: ${ddos.udpPacketRate.toLocaleString()} pps accounting for ${general.protocolPercentages.UDP + general.protocolPercentages.NTP}% of ingress datagrams`);

    if (targetConcentrated) {
      evidence.push(`Victim concentration: HHI ${ddos.destinationConcentrationHHI} focused on ${primaryTarget.ip}`);
      confidence += 12;
    }

    confidence = Math.min(98, confidence);

    return {
      detected: true,
      threatType: 'UDP Reflection/Amplification',
      confidence,
      severity: 'Critical',
      evidence,
      featureValues: {
        vector: matchedProtoName,
        port: matchedPort,
        averagePacketSize: general.averagePacketSize,
        udpPacketRate: ddos.udpPacketRate,
        hhi: ddos.destinationConcentrationHHI
      },
      timestamp: now,
      sourceSummary: `Public ${matchedProtoName} reflection nodes`,
      targetSummary,
      mitigationAdvisory: `PASSIVE MITIGATION ADVISORY: Execution is manual/out-of-band. OneWaySentinel AI cannot transmit mitigation commands into the monitored production network. Recommended out-of-band action: Drop unrequested inbound UDP responses on port ${matchedPort} with length > 512B targeting ${primaryTarget.ip}.`
    };
  }

  // ==========================================
  // 3. SPOOFED-SOURCE FLOOD LOGIC
  // High entropy + high unique source ratio + target concentration + high rate
  // ==========================================
  const isHighEntropy = ddos.sourceIPEntropy >= ENGINE_CONFIG.ddos.spoofedEntropyMin;
  const isHighDiversity = ddos.uniqueSourceRatio >= ENGINE_CONFIG.ddos.spoofedUniqueSourceRatio || ddos.sourceIPCount > 100;
  const isVolumetric = ddos.ppsDeviationFromBaseline >= 2.0;

  if (isHighEntropy && isHighDiversity && (isVolumetric || targetConcentrated)) {
    let confidence = 78;
    const evidence: string[] = [];

    evidence.push(`Source IP Shannon entropy spiked to ${ddos.sourceIPEntropy} / 8.0 (baseline ${ENGINE_CONFIG.baseline.baselineEntropy})`);
    evidence.push(`Source dispersion anomaly: ${(ddos.uniqueSourceRatio * 100).toFixed(1)}% of packets originate from unique individual source IPs`);
    evidence.push(`Total unique sources: ${ddos.sourceIPCount.toLocaleString()} with negligible packet persistence`);

    if (targetConcentrated) {
      evidence.push(`Targeted VIP convergence: HHI ${ddos.destinationConcentrationHHI} on ${primaryTarget.ip}`);
      confidence += 14;
    }

    confidence = Math.min(97, confidence);

    return {
      detected: true,
      threatType: 'Spoofed-Source Flood',
      confidence,
      severity: confidence >= 85 ? 'Critical' : 'High',
      evidence,
      featureValues: {
        entropy: ddos.sourceIPEntropy,
        uniqueSources: ddos.sourceIPCount,
        uniqueRatio: ddos.uniqueSourceRatio,
        hhi: ddos.destinationConcentrationHHI
      },
      timestamp: now,
      sourceSummary: `Spoofed / forged IP space (${ddos.sourceIPCount.toLocaleString()} pseudo-random sources)`,
      targetSummary,
      mitigationAdvisory: `PASSIVE MITIGATION ADVISORY: Execution is manual/out-of-band. OneWaySentinel AI cannot transmit mitigation commands into the monitored production network. Recommended out-of-band action: Enforce uRPF (unicast Reverse Path Forwarding) strict check at edge routing interfaces.`
    };
  }

  // ==========================================
  // 4. GENERIC UDP FLOOD LOGIC
  // High UDP rate + protocol dominance + destination concentration
  // ==========================================
  const isUdpDominated = general.protocolPercentages.UDP > 65 || ddos.udpPacketRate > (ENGINE_CONFIG.baseline.baselinePacketsPerSecond * 2.5);
  if (isUdpDominated && ddos.ppsDeviationFromBaseline >= ENGINE_CONFIG.ddos.udpRateMultiplierThreshold) {
    let confidence = 72;
    const evidence: string[] = [];

    evidence.push(`UDP packet rate: ${ddos.udpPacketRate.toLocaleString()} pps (${ddos.ppsDeviationFromBaseline}x above baseline)`);
    evidence.push(`Protocol dominance: UDP comprises ${general.protocolPercentages.UDP}% of aggregate ingress flows`);

    if (targetConcentrated) {
      evidence.push(`Destination concentration: HHI ${ddos.destinationConcentrationHHI} focused on ${primaryTarget.ip}`);
      confidence += 15;
    }

    confidence = Math.min(95, confidence);

    return {
      detected: true,
      threatType: 'UDP Flood',
      confidence,
      severity: 'High',
      evidence,
      featureValues: {
        udpPacketRate: ddos.udpPacketRate,
        ppsDeviation: ddos.ppsDeviationFromBaseline,
        hhi: ddos.destinationConcentrationHHI
      },
      timestamp: now,
      sourceSummary: `${ddos.sourceIPCount.toLocaleString()} UDP source sockets`,
      targetSummary,
      mitigationAdvisory: `PASSIVE MITIGATION ADVISORY: Execution is manual/out-of-band. OneWaySentinel AI cannot transmit mitigation commands into the monitored production network. Recommended out-of-band action: Rate-limit UDP ingress packets to target VIP ${primaryTarget.ip}.`
    };
  }

  // No DDoS threat detected
  return {
    detected: false,
    threatType: null,
    confidence: 0,
    severity: 'Low',
    evidence: ['Traffic patterns conform to normal baseline bounds. No volumetric flood signatures identified.'],
    featureValues: {
      synRate: ddos.synPacketRate,
      udpRate: ddos.udpPacketRate,
      entropy: ddos.sourceIPEntropy,
      hhi: ddos.destinationConcentrationHHI
    },
    timestamp: now,
    sourceSummary: 'Nominal enterprise ingress',
    targetSummary: 'Balanced distribution',
    mitigationAdvisory: 'No out-of-band mitigation required. Ingress flow is within normal parameters.'
  };
}
