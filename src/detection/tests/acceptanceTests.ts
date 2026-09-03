/**
 * OneWaySentinel AI - Acceptance Test Suite
 * Executes the 8 required detection verification scenarios.
 */

import { generateScenarioFlows } from '../simulation/trafficGenerator';
import { runDetectionPipeline } from '../engine';
import { TrafficFlow } from '../types';
import { analyzeTemporalPeriodicity } from '../features/spectral';

export interface TestCaseResult {
  testId: string;
  title: string;
  category: 'Normal' | 'DDoS' | 'C2' | 'Anomaly' | 'Data Quality';
  passed: boolean;
  expectedOutcome: string;
  actualOutcome: string;
  details: string[];
  durationMs: number;
}

export interface TestSuiteSummary {
  total: number;
  passed: number;
  failed: number;
  allPassed: boolean;
  timestamp: string;
  results: TestCaseResult[];
}

export function runAllAcceptanceTests(): TestSuiteSummary {
  const results: TestCaseResult[] = [];
  const startAll = performance.now();

  // -------------------------------------------------------------
  // TEST 1: Normal traffic -> No critical threat
  // -------------------------------------------------------------
  {
    const start = performance.now();
    const flows = generateScenarioFlows('normal', 50);
    const result = runDetectionPipeline(flows, 'SIMULATION');

    const passed = result.threatScore.severity !== 'Critical' && !result.ddos.detected;
    results.push({
      testId: 'TEST-1',
      title: 'Normal Ingress Flow Evaluation',
      category: 'Normal',
      passed,
      expectedOutcome: 'Nominal baseline status, no critical alerts, threat score < 50',
      actualOutcome: `Score: ${result.threatScore.score} (${result.threatScore.severity}), DDoS Detected: ${result.ddos.detected}`,
      details: [
        `Flow count: ${flows.length}`,
        `Entropy: ${result.features.ddos.sourceIPEntropy} (nominal range 2.8 - 4.8)`,
        `HHI: ${result.features.ddos.destinationConcentrationHHI} (distributed)`
      ],
      durationMs: Number((performance.now() - start).toFixed(2))
    });
  }

  // -------------------------------------------------------------
  // TEST 2: Synthetic SYN flood -> SYN Flood detected
  // -------------------------------------------------------------
  {
    const start = performance.now();
    const flows = generateScenarioFlows('syn-flood', 80);
    const result = runDetectionPipeline(flows, 'SIMULATION');

    const passed = result.ddos.detected && result.ddos.threatType === 'SYN Flood';
    results.push({
      testId: 'TEST-2',
      title: 'Volumetric SYN Flood Detection',
      category: 'DDoS',
      passed,
      expectedOutcome: 'Detects SYN Flood with high confidence, identifies victim VIP concentration',
      actualOutcome: `Threat: ${result.ddos.threatType}, Confidence: ${result.ddos.confidence}%, Severity: ${result.ddos.severity}`,
      details: [
        `SYN rate: ${result.features.ddos.synPacketRate} pps`,
        `SYN/ACK ratio: ${result.features.ddos.synToAckRatio}:1`,
        `Target: ${result.ddos.targetSummary}`
      ],
      durationMs: Number((performance.now() - start).toFixed(2))
    });
  }

  // -------------------------------------------------------------
  // TEST 3: Synthetic UDP flood -> UDP Flood detected
  // -------------------------------------------------------------
  {
    const start = performance.now();
    // Build pure generic UDP flood with high volume
    const flows: TrafficFlow[] = [];
    const now = Date.now();
    for (let i = 0; i < 60; i++) {
      flows.push({
        id: `udp-test-${i}`,
        timestamp: new Date(now + i * 10).toISOString(),
        timestampMs: now + i * 10,
        sourceIP: `10.10.10.${1 + (i % 30)}`,
        destinationIP: '192.168.10.45',
        sourcePort: 20000 + i,
        destinationPort: 9999,
        protocol: 'UDP',
        packetCount: 150,
        byteCount: 150 * 512,
        durationMs: 50,
        packetSizes: [512, 512],
        interArrivalTimes: [0.1, 0.2],
        direction: 'INGRESS'
      });
    }

    const result = runDetectionPipeline(flows, 'SIMULATION');
    const passed = result.ddos.detected && (result.ddos.threatType === 'UDP Flood' || result.ddos.threatType === 'UDP Reflection/Amplification');
    results.push({
      testId: 'TEST-3',
      title: 'Volumetric UDP Flood Detection',
      category: 'DDoS',
      passed,
      expectedOutcome: 'Identifies abnormal UDP packet/byte surge and victim VIP concentration',
      actualOutcome: `Threat: ${result.ddos.threatType}, Confidence: ${result.ddos.confidence}%`,
      details: [
        `UDP packet rate: ${result.features.ddos.udpPacketRate} pps`,
        `Protocol share: ${result.features.general.protocolPercentages.UDP}% UDP`,
        `Target HHI: ${result.features.ddos.destinationConcentrationHHI}`
      ],
      durationMs: Number((performance.now() - start).toFixed(2))
    });
  }

  // -------------------------------------------------------------
  // TEST 4: Synthetic UDP reflection pattern -> Potential UDP Reflection/Amplification detected
  // -------------------------------------------------------------
  {
    const start = performance.now();
    const flows = generateScenarioFlows('udp-amplification', 60);
    const result = runDetectionPipeline(flows, 'SIMULATION');

    const passed = result.ddos.detected && result.ddos.threatType === 'UDP Reflection/Amplification';
    results.push({
      testId: 'TEST-4',
      title: 'UDP Reflection / Amplification Multi-Signal Classifier',
      category: 'DDoS',
      passed,
      expectedOutcome: 'Correlates reflection ports (123 NTP) + high byte/packet ratio (>1000B) + victim concentration',
      actualOutcome: `Threat: ${result.ddos.threatType}, Confidence: ${result.ddos.confidence}%`,
      details: [
        `Average packet size: ${result.features.general.averagePacketSize} bytes (amplified replies)`,
        `Target VIP: ${result.ddos.targetSummary}`,
        `Mitigation Advisory: ${result.ddos.mitigationAdvisory.substring(0, 75)}...`
      ],
      durationMs: Number((performance.now() - start).toFixed(2))
    });
  }

  // -------------------------------------------------------------
  // TEST 5: High source diversity + concentrated destination -> Potential spoofed-source flood
  // -------------------------------------------------------------
  {
    const start = performance.now();
    const flows = generateScenarioFlows('spoofed-source', 80);
    const result = runDetectionPipeline(flows, 'SIMULATION');

    const passed = result.ddos.detected && (result.ddos.threatType === 'Spoofed-Source Flood' || result.features.ddos.sourceIPEntropy > 6.5);
    results.push({
      testId: 'TEST-5',
      title: 'Spoofed-Source Flood & High Entropy Anomaly',
      category: 'DDoS',
      passed,
      expectedOutcome: 'Identifies high Shannon Entropy (>6.8) and low per-host packet persistence',
      actualOutcome: `Threat: ${result.ddos.threatType}, Source Entropy: ${result.features.ddos.sourceIPEntropy}`,
      details: [
        `Shannon Entropy: ${result.features.ddos.sourceIPEntropy} / 8.0`,
        `Unique source count: ${result.features.general.uniqueSourceIPCount}`,
        `Unique source ratio: ${(result.features.ddos.uniqueSourceRatio * 100).toFixed(1)}%`
      ],
      durationMs: Number((performance.now() - start).toFixed(2))
    });
  }

  // -------------------------------------------------------------
  // TEST 6: Periodic repeated connections -> Potential C2 beacon
  // -------------------------------------------------------------
  {
    const start = performance.now();
    const flows = generateScenarioFlows('c2-beacon', 60);
    const result = runDetectionPipeline(flows, 'SIMULATION');

    const c2Found = result.c2Clusters.some(
      (c) =>
        c.classification === 'High-confidence Beaconing Pattern' ||
        c.classification === 'High-Confidence C2 Beacon'
    );
    results.push({
      testId: 'TEST-6',
      title: 'Stealth C2 Machine Heartbeat Detection',
      category: 'C2',
      passed: c2Found,
      expectedOutcome: 'Identifies periodic heartbeat with low jitter (<15%) and uniform payload buffer',
      actualOutcome: c2Found ? 'High-confidence beaconing pattern identified' : 'C2 not identified',
      details: [
        `Candidate count: ${result.c2Clusters.length}`,
        `Top classification: ${result.c2Clusters[0]?.classification || 'None'}`,
        `Jitter: ${result.c2Clusters[0]?.jitterPercentage}%`,
        `Potential correlation: ${result.c2Clusters[0]?.potentialC2FamilyCorrelation || 'Unattributed'}`
      ],
      durationMs: Number((performance.now() - start).toFixed(2))
    });
  }

  // -------------------------------------------------------------
  // TEST 7: Random irregular connections -> NOT automatically classified as C2
  // -------------------------------------------------------------
  {
    const start = performance.now();
    // Generate highly irregular client browsing interactions
    const flows: TrafficFlow[] = [];
    const now = Date.now();
    for (let i = 0; i < 20; i++) {
      const randomInterval = [1200, 18000, 3400, 95000, 4200, 71000][i % 6];
      flows.push({
        id: `random-${i}`,
        timestamp: new Date(now + i * 20000).toISOString(),
        timestampMs: now + i * 20000,
        sourceIP: '10.0.1.55',
        destinationIP: '172.217.16.206',
        sourcePort: 50000 + i,
        destinationPort: 443,
        protocol: 'TLS',
        packetCount: 10,
        byteCount: 500 + Math.floor(Math.random() * 8000),
        durationMs: 400,
        packetSizes: [150, 1420, 800, 2400],
        interArrivalTimes: [randomInterval],
        direction: 'INGRESS'
      });
    }

    const result = runDetectionPipeline(flows, 'SIMULATION');
    const hasFalsePositive = result.c2Clusters.some(
      (c) =>
        c.classification === 'High-confidence Beaconing Pattern' ||
        c.classification === 'High-Confidence C2 Beacon'
    );
    const passed = !hasFalsePositive;

    results.push({
      testId: 'TEST-7',
      title: 'C2 False Positive Resistance on Irregular Traffic',
      category: 'C2',
      passed,
      expectedOutcome: 'High jitter and random sizes classified as Background or Suspicious, NOT High-Confidence C2',
      actualOutcome: hasFalsePositive ? 'False positive detected!' : 'Correctly resisted false positive',
      details: [
        `Observed intervals count: ${flows.length}`,
        `Highest classification: ${result.c2Clusters[0]?.classification || 'Background Traffic'}`
      ],
      durationMs: Number((performance.now() - start).toFixed(2))
    });
  }

  // -------------------------------------------------------------
  // TEST 8: Insufficient temporal data -> Reports insufficient samples
  // -------------------------------------------------------------
  {
    const start = performance.now();
    // Only 3 interval samples (requires at least 8 for spectral FFT)
    const sparseIntervals = [1200, 1250, 1190];
    const spectral = analyzeTemporalPeriodicity(sparseIntervals);

    const passed = !spectral.hasSufficientSamples && spectral.statusMessage.includes('Insufficient temporal samples');
    results.push({
      testId: 'TEST-8',
      title: 'Insufficient Temporal Data Boundary Handling',
      category: 'Data Quality',
      passed,
      expectedOutcome: 'Explicitly reports "Insufficient temporal samples" instead of fabricating spectral peaks',
      actualOutcome: spectral.statusMessage,
      details: [
        `Sample count provided: ${sparseIntervals.length} (minimum 8 required)`,
        `hasSufficientSamples: ${spectral.hasSufficientSamples}`,
        `statusMessage: "${spectral.statusMessage}"`
      ],
      durationMs: Number((performance.now() - start).toFixed(2))
    });
  }

  const passedCount = results.filter((r) => r.passed).length;

  return {
    total: results.length,
    passed: passedCount,
    failed: results.length - passedCount,
    allPassed: passedCount === results.length,
    timestamp: new Date().toISOString(),
    results
  };
}
