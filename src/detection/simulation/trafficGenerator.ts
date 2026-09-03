/**
 * OneWaySentinel AI - Realistic Deterministic Traffic Flow Generator
 * Generates structured, deterministic network flow and packet metadata for:
 * 1. NORMAL_BASELINE
 * 2. SYN_FLOOD
 * 3. UDP_FLOOD
 * 4. UDP_REFLECTION
 * 5. SPOOFED_SOURCE_FLOOD
 * 6. C2_BEACONING
 * 7. MIXED_ATTACK
 * 
 * Strict Passive Invariant: All generated traffic represents observed passive ingress optical tap data.
 */

import { TrafficFlow, ProtocolType } from '../types';

export type SimulationScenarioId =
  | 'normal'
  | 'baseline'
  | 'NORMAL_BASELINE'
  | 'syn-flood'
  | 'SYN_FLOOD'
  | 'udp-flood'
  | 'UDP_FLOOD'
  | 'udp-amplification'
  | 'udp-reflection'
  | 'UDP_REFLECTION'
  | 'spoofed-source'
  | 'spoofed-source-flood'
  | 'SPOOFED_SOURCE_FLOOD'
  | 'c2-beacon'
  | 'c2-beaconing'
  | 'C2_BEACONING'
  | 'mixed-attack'
  | 'MIXED_ATTACK'
  | 'traffic-anomaly';

let globalFlowSeq = 0;

export function normalizeScenarioId(id: string): string {
  const clean = id.toUpperCase().replace(/-/g, '_');
  if (clean === 'NORMAL' || clean === 'BASELINE' || clean === 'NORMAL_BASELINE') return 'NORMAL_BASELINE';
  if (clean === 'SYN_FLOOD') return 'SYN_FLOOD';
  if (clean === 'UDP_FLOOD') return 'UDP_FLOOD';
  if (clean === 'UDP_AMPLIFICATION' || clean === 'UDP_REFLECTION') return 'UDP_REFLECTION';
  if (clean === 'SPOOFED_SOURCE' || clean === 'SPOOFED_SOURCE_FLOOD') return 'SPOOFED_SOURCE_FLOOD';
  if (clean === 'C2_BEACON' || clean === 'C2_BEACONING') return 'C2_BEACONING';
  if (clean === 'MIXED_ATTACK') return 'MIXED_ATTACK';
  if (clean === 'TRAFFIC_ANOMALY') return 'TRAFFIC_ANOMALY';
  return 'NORMAL_BASELINE';
}

export function generateScenarioFlows(
  scenarioId: SimulationScenarioId | string,
  count: number = 70,
  baseTimeMs: number = Date.now() - 60000
): TrafficFlow[] {
  const flows: TrafficFlow[] = [];
  const batchTag = Math.random().toString(36).substring(2, 6);
  const normalizedId = normalizeScenarioId(scenarioId);

  switch (normalizedId) {
    // -------------------------------------------------------------
    // 1. NORMAL_BASELINE
    // Routine HTTPS, DNS, API traffic, balanced protocols, ~3.7 entropy, low concentration HHI ~0.25
    // -------------------------------------------------------------
    case 'NORMAL_BASELINE': {
      const clientSubnets = ['10.0.1', '10.0.2', '10.0.3', '10.0.4'];
      const serverVIPs = [
        '192.168.10.45', // Web App VIP
        '192.168.10.50', // Internal DNS
        '192.168.20.10', // Core DB
        '192.168.10.1'   // API Gateway
      ];
      const protoList: ProtocolType[] = ['TCP', 'TLS', 'UDP', 'DNS'];

      for (let i = 0; i < count; i++) {
        const subnet = clientSubnets[i % clientSubnets.length];
        const srcIp = `${subnet}.${10 + (i % 80)}`;
        const dstIp = serverVIPs[i % serverVIPs.length];
        const proto = protoList[i % protoList.length];
        const dstPort = proto === 'TLS' ? 443 : proto === 'DNS' ? 53 : proto === 'UDP' ? 8080 : 80;
        const timeOffset = i * 850;
        const pkts = 8 + (i % 15);
        const avgSize = 550 + ((i * 37) % 500);
        const flowDuration = 300 + (i % 400);
        const interArrival = Number((flowDuration / Math.max(1, pkts - 1)).toFixed(2));
        const idStr = `sim-norm-${batchTag}-${++globalFlowSeq}-${i}`;

        flows.push({
          id: idStr,
          flowId: idStr,
          timestamp: new Date(baseTimeMs + timeOffset).toISOString(),
          timestampMs: baseTimeMs + timeOffset,
          sourceIP: srcIp,
          destinationIP: dstIp,
          sourcePort: 32768 + (i * 17) % 28000,
          destinationPort: dstPort,
          protocol: proto,
          packetCount: pkts,
          byteCount: pkts * avgSize,
          bytes: pkts * avgSize,
          packetLength: avgSize,
          durationMs: flowDuration,
          packetSizes: [avgSize, Math.round(avgSize * 0.85), Math.round(avgSize * 1.15)],
          interArrivalTimes: [interArrival, interArrival * 1.2, interArrival * 0.8],
          interArrivalTime: interArrival,
          tcpFlags: proto === 'TCP' || proto === 'TLS' ? ['ACK', 'PSH'] : [],
          direction: 'INGRESS',
          payloadSnippet: `0x4500003c [Passive Ingress L3 Capture - Nominal Enterprise Session ${i}]`
        });
      }
      break;
    }

    // -------------------------------------------------------------
    // 2. SYN_FLOOD
    // High-frequency TCP SYN packet burst targeting VIP 192.168.10.45:443,
    // no ACK completion, SYN/ACK ratio > 20:1, high PPS, low inter-arrival times
    // -------------------------------------------------------------
    case 'SYN_FLOOD': {
      const targetVIP = '192.168.10.45';
      const targetPort = 443;

      for (let i = 0; i < count; i++) {
        const srcSubnet = 100 + (i % 40);
        const srcHost = 1 + ((i * 7) % 253);
        const srcIp = `198.51.${srcSubnet}.${srcHost}`;
        const srcPort = 20000 + ((i * 31) % 40000);
        const timeOffset = i * 12; // Extremely tight arrival: 12ms
        const pkts = 55 + (i % 45);
        const idStr = `sim-syn-${batchTag}-${++globalFlowSeq}-${i}`;

        flows.push({
          id: idStr,
          flowId: idStr,
          timestamp: new Date(baseTimeMs + timeOffset).toISOString(),
          timestampMs: baseTimeMs + timeOffset,
          sourceIP: srcIp,
          destinationIP: targetVIP,
          sourcePort: srcPort,
          destinationPort: targetPort,
          protocol: 'TCP',
          packetCount: pkts,
          byteCount: pkts * 64, // Small 64-byte SYN probe
          bytes: pkts * 64,
          packetLength: 64,
          durationMs: 40,
          packetSizes: [64, 64, 64, 64],
          interArrivalTimes: [0.15, 0.22, 0.18, 0.25],
          interArrivalTime: 0.2,
          tcpFlags: ['SYN'], // Zero ACK completion -> severe imbalance
          direction: 'INGRESS',
          payloadSnippet: `0x4500003c 7a424000 4006... [Passive L3 Capture - TCP SYN Flag Set, Seq 0x${(i * 1024).toString(16)}]`
        });
      }
      break;
    }

    // -------------------------------------------------------------
    // 3. UDP_FLOOD
    // High-volume generic UDP packet burst targeting port 8080/UDP service,
    // elevated PPS and BPS, high UDP protocol dominance (> 70%)
    // -------------------------------------------------------------
    case 'UDP_FLOOD': {
      const targetVIP = '192.168.10.1'; // API Gateway service
      const targetPort = 8080;

      for (let i = 0; i < count; i++) {
        const srcSubnet = 110 + (i % 30);
        const srcHost = 1 + ((i * 11) % 250);
        const srcIp = `198.18.${srcSubnet}.${srcHost}`;
        const srcPort = 10000 + ((i * 23) % 50000);
        const timeOffset = i * 18;
        const pkts = 45 + (i % 40);
        const packetSize = 384; // Moderate generic UDP payload
        const idStr = `sim-udp-${batchTag}-${++globalFlowSeq}-${i}`;

        flows.push({
          id: idStr,
          flowId: idStr,
          timestamp: new Date(baseTimeMs + timeOffset).toISOString(),
          timestampMs: baseTimeMs + timeOffset,
          sourceIP: srcIp,
          destinationIP: targetVIP,
          sourcePort: srcPort,
          destinationPort: targetPort,
          protocol: 'UDP',
          packetCount: pkts,
          byteCount: pkts * packetSize,
          bytes: pkts * packetSize,
          packetLength: packetSize,
          durationMs: 65,
          packetSizes: [packetSize, packetSize, packetSize],
          interArrivalTimes: [0.35, 0.4, 0.38],
          interArrivalTime: 0.38,
          tcpFlags: [],
          direction: 'INGRESS',
          payloadSnippet: `0x45000180 [Passive UDP Datagram Flood - Unsolicited Direct Stream]`
        });
      }
      break;
    }

    // -------------------------------------------------------------
    // 4. UDP_REFLECTION
    // High inbound volume with large asymmetric packet sizes (1200-1450B),
    // originating from known reflection ports (123 NTP, 53 DNS, 11211 Memcached, 1900 SSDP)
    // -------------------------------------------------------------
    case 'UDP_REFLECTION': {
      const targetVIP = '192.168.20.10'; // Core DB Gateway
      const targetPort = 5432;
      const ampVectors = [
        { port: 123, proto: 'NTP' as ProtocolType, size: 1420 },
        { port: 53, proto: 'DNS' as ProtocolType, size: 1380 },
        { port: 11211, proto: 'UDP' as ProtocolType, size: 1450 },
        { port: 1900, proto: 'SSDP' as ProtocolType, size: 1280 }
      ];

      for (let i = 0; i < count; i++) {
        const vec = ampVectors[i % ampVectors.length];
        const ampServerIp = `203.0.113.${15 + (i % 25)}`;
        const timeOffset = i * 15;
        const pkts = 50 + (i % 45);
        const payloadSize = vec.size;
        const idStr = `sim-refl-${batchTag}-${++globalFlowSeq}-${i}`;

        flows.push({
          id: idStr,
          flowId: idStr,
          timestamp: new Date(baseTimeMs + timeOffset).toISOString(),
          timestampMs: baseTimeMs + timeOffset,
          sourceIP: ampServerIp,
          destinationIP: targetVIP,
          sourcePort: vec.port,
          destinationPort: targetPort,
          protocol: vec.proto,
          packetCount: pkts,
          byteCount: pkts * payloadSize,
          bytes: pkts * payloadSize,
          packetLength: payloadSize,
          durationMs: 90,
          packetSizes: [payloadSize, payloadSize, payloadSize],
          interArrivalTimes: [0.25, 0.3, 0.28],
          interArrivalTime: 0.28,
          tcpFlags: [],
          direction: 'INGRESS',
          payloadSnippet: `0x4500058c [Passive Ingress Amplified ${vec.proto} Datagram Response, Port ${vec.port}]`
        });
      }
      break;
    }

    // -------------------------------------------------------------
    // 5. SPOOFED_SOURCE_FLOOD
    // High-entropy randomized source IP population from pseudo-random/bogon subnets,
    // Shannon entropy > 6.8 / 8.0, high unique source ratio, concentrated target VIP
    // -------------------------------------------------------------
    case 'SPOOFED_SOURCE_FLOOD': {
      const targetVIP = '192.168.10.1'; // API Gateway
      const targetPort = 8080;

      for (let i = 0; i < count; i++) {
        // High diversity across bogon & random IPv4 ranges
        const oct1 = 100 + ((i * 13) % 110);
        const oct2 = (i * 37) % 255;
        const oct3 = (i * 71) % 255;
        const oct4 = 1 + ((i * 97) % 253);
        const randomSpoofedIp = `${oct1}.${oct2}.${oct3}.${oct4}`;

        const timeOffset = i * 20;
        const pkts = 25 + (i % 30);
        const idStr = `sim-spoof-${batchTag}-${++globalFlowSeq}-${i}`;

        flows.push({
          id: idStr,
          flowId: idStr,
          timestamp: new Date(baseTimeMs + timeOffset).toISOString(),
          timestampMs: baseTimeMs + timeOffset,
          sourceIP: randomSpoofedIp,
          destinationIP: targetVIP,
          sourcePort: 1024 + ((i * 131) % 62000),
          destinationPort: targetPort,
          protocol: 'UDP',
          packetCount: pkts,
          byteCount: pkts * 128,
          bytes: pkts * 128,
          packetLength: 128,
          durationMs: 70,
          packetSizes: [128, 128, 128],
          interArrivalTimes: [0.6, 0.8, 0.7],
          interArrivalTime: 0.7,
          tcpFlags: [],
          direction: 'INGRESS',
          payloadSnippet: `0x45000080 [Passive L3 Ingress - Forged Non-Routable Bogon IP Address]`
        });
      }
      break;
    }

    // -------------------------------------------------------------
    // 6. C2_BEACONING
    // Low-volume, highly periodic communication between compromised internal host 10.0.4.118
    // and external destination, uniform payload size (340B), mean inter-arrival time (45s), low jitter (< 5%)
    // -------------------------------------------------------------
    case 'C2_BEACONING': {
      const compromisedHost = '10.0.4.118';
      const c2Ip = '198.51.100.89';
      const c2Port = 8443;
      const beaconPayloadSize = 340; // Uniform 340B malleable C2 frame

      for (let i = 0; i < count; i++) {
        const isBeacon = i % 3 === 0;

        if (isBeacon) {
          // Strict periodic heartbeat: 45s interval with ±1.5s jitter (< 3.5%)
          const jitterMs = ((i % 5) - 2) * 450;
          const timeOffset = i * 15000 + jitterMs;
          const idStr = `sim-c2-${batchTag}-${++globalFlowSeq}-${i}`;

          flows.push({
            id: idStr,
            flowId: idStr,
            timestamp: new Date(baseTimeMs + timeOffset).toISOString(),
            timestampMs: baseTimeMs + timeOffset,
            sourceIP: compromisedHost,
            destinationIP: c2Ip,
            sourcePort: 49500 + (i % 50),
            destinationPort: c2Port,
            protocol: 'TLS',
            packetCount: 14,
            byteCount: 14 * beaconPayloadSize,
            bytes: 14 * beaconPayloadSize,
            packetLength: beaconPayloadSize,
            durationMs: 160,
            packetSizes: [340, 340, 340, 340],
            interArrivalTimes: [44850, 45150, 44920, 45080],
            interArrivalTime: 45000,
            tcpFlags: ['SYN', 'ACK', 'PSH'],
            direction: 'INGRESS',
            payloadSnippet: `0x1603030154 [TLS Client Hello / Simulated Cobalt Strike-like Malleable Profile 340B]`
          });
        } else {
          // Interleaved routine internal background traffic
          const timeOffset = i * 15000;
          const idStr = `sim-bg-${batchTag}-${++globalFlowSeq}-${i}`;

          flows.push({
            id: idStr,
            flowId: idStr,
            timestamp: new Date(baseTimeMs + timeOffset).toISOString(),
            timestampMs: baseTimeMs + timeOffset,
            sourceIP: `10.0.2.${15 + (i % 40)}`,
            destinationIP: `192.168.10.${50 + (i % 4)}`,
            sourcePort: 40000 + (i * 19) % 20000,
            destinationPort: 443,
            protocol: 'TCP',
            packetCount: 6,
            byteCount: 3900,
            bytes: 3900,
            packetLength: 650,
            durationMs: 220,
            packetSizes: [800, 1100, 450, 1400],
            interArrivalTimes: [1400, 3800, 7200],
            interArrivalTime: 4100,
            tcpFlags: ['ACK', 'PSH'],
            direction: 'INGRESS',
            payloadSnippet: `0x45000320 [Passive Background Flow Session]`
          });
        }
      }
      break;
    }

    // -------------------------------------------------------------
    // 7. MIXED_ATTACK
    // Multi-vector composite scenario: concurrent TCP SYN flood burst + UDP amplification reflection
    // + background stealth C2 beacon
    // -------------------------------------------------------------
    case 'MIXED_ATTACK': {
      const synTargetVIP = '192.168.10.45';
      const ampTargetVIP = '192.168.20.10';
      const compromisedHost = '10.0.4.118';
      const c2Ip = '198.51.100.89';

      for (let i = 0; i < count; i++) {
        const mod = i % 3;
        const timeOffset = i * 20;

        if (mod === 0) {
          // Vector A: TCP SYN Flood burst
          const srcIp = `198.51.${100 + (i % 30)}.${1 + (i % 250)}`;
          const pkts = 40 + (i % 30);
          const idStr = `sim-mix-syn-${batchTag}-${++globalFlowSeq}-${i}`;

          flows.push({
            id: idStr,
            flowId: idStr,
            timestamp: new Date(baseTimeMs + timeOffset).toISOString(),
            timestampMs: baseTimeMs + timeOffset,
            sourceIP: srcIp,
            destinationIP: synTargetVIP,
            sourcePort: 25000 + (i * 13) % 30000,
            destinationPort: 443,
            protocol: 'TCP',
            packetCount: pkts,
            byteCount: pkts * 64,
            bytes: pkts * 64,
            packetLength: 64,
            durationMs: 35,
            packetSizes: [64, 64, 64],
            interArrivalTimes: [0.15, 0.2, 0.18],
            interArrivalTime: 0.18,
            tcpFlags: ['SYN'],
            direction: 'INGRESS',
            payloadSnippet: `0x4500003c [Multi-Vector 1/3: TCP SYN Flood Probe]`
          });
        } else if (mod === 1) {
          // Vector B: UDP NTP Amplification Reflection
          const ampServerIp = `203.0.113.${20 + (i % 15)}`;
          const pkts = 35 + (i % 25);
          const payloadSize = 1420;
          const idStr = `sim-mix-amp-${batchTag}-${++globalFlowSeq}-${i}`;

          flows.push({
            id: idStr,
            flowId: idStr,
            timestamp: new Date(baseTimeMs + timeOffset).toISOString(),
            timestampMs: baseTimeMs + timeOffset,
            sourceIP: ampServerIp,
            destinationIP: ampTargetVIP,
            sourcePort: 123,
            destinationPort: 5432,
            protocol: 'NTP',
            packetCount: pkts,
            byteCount: pkts * payloadSize,
            bytes: pkts * payloadSize,
            packetLength: payloadSize,
            durationMs: 80,
            packetSizes: [payloadSize, payloadSize, payloadSize],
            interArrivalTimes: [0.3, 0.35, 0.32],
            interArrivalTime: 0.32,
            tcpFlags: [],
            direction: 'INGRESS',
            payloadSnippet: `0x4500058c [Multi-Vector 2/3: Amplified NTP Monlist Response]`
          });
        } else {
          // Vector C: Stealth C2 Beaconing
          const idStr = `sim-mix-c2-${batchTag}-${++globalFlowSeq}-${i}`;

          flows.push({
            id: idStr,
            flowId: idStr,
            timestamp: new Date(baseTimeMs + timeOffset).toISOString(),
            timestampMs: baseTimeMs + timeOffset,
            sourceIP: compromisedHost,
            destinationIP: c2Ip,
            sourcePort: 49800 + (i % 30),
            destinationPort: 8443,
            protocol: 'TLS',
            packetCount: 12,
            byteCount: 12 * 340,
            bytes: 12 * 340,
            packetLength: 340,
            durationMs: 140,
            packetSizes: [340, 340, 340],
            interArrivalTimes: [44900, 45100, 45050],
            interArrivalTime: 45000,
            tcpFlags: ['SYN', 'ACK', 'PSH'],
            direction: 'INGRESS',
            payloadSnippet: `0x1603030154 [Multi-Vector 3/3: Stealth Simulated C2 Beacon 340B]`
          });
        }
      }
      break;
    }

    // -------------------------------------------------------------
    // Generic / Fallback Protocol Anomaly
    // -------------------------------------------------------------
    case 'TRAFFIC_ANOMALY':
    default: {
      const anomalousPort = 6667;
      for (let i = 0; i < count; i++) {
        const timeOffset = i * 250;
        const pkts = 15 + (i % 10);
        const idStr = `sim-anom-${batchTag}-${++globalFlowSeq}-${i}`;

        flows.push({
          id: idStr,
          flowId: idStr,
          timestamp: new Date(baseTimeMs + timeOffset).toISOString(),
          timestampMs: baseTimeMs + timeOffset,
          sourceIP: `10.0.2.${40 + (i % 10)}`,
          destinationIP: `192.168.30.${10 + (i % 5)}`,
          sourcePort: 38000 + i,
          destinationPort: anomalousPort,
          protocol: 'TCP',
          packetCount: pkts,
          byteCount: pkts * 512,
          bytes: pkts * 512,
          packetLength: 512,
          durationMs: 120,
          packetSizes: [512, 512, 512],
          interArrivalTimes: [5, 12, 8],
          interArrivalTime: 8,
          tcpFlags: ['SYN', 'RST'],
          direction: 'INGRESS',
          payloadSnippet: `0x45000200 [Passive Ingress Anomaly - Non-standard Port Scan]`
        });
      }
      break;
    }
  }

  return flows;
}
