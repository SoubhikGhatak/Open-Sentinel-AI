/**
 * OneWaySentinel AI - Built-in Sample Passive Datasets
 * Realistically constructed passive network capture flow datasets for offline verification & testing.
 * Strictly passive analysis.
 */

import { PassiveObservation } from './types';

export interface SampleDatasetMeta {
  id: string;
  name: string;
  category: 'Baseline' | 'DDoS' | 'C2' | 'Anomaly';
  description: string;
  format: 'PCAP' | 'CSV' | 'JSON';
  expectedThreat: string;
  observationCount: number;
}

export const SAMPLE_DATASET_DEFINITIONS: SampleDatasetMeta[] = [
  {
    id: 'sample-normal',
    name: 'Normal Enterprise Baseline Traffic',
    category: 'Baseline',
    description: 'Legitimate routine enterprise ingress: HTTPS web services, DNS lookups, API gateway requests, and TLS microservices with natural human jitter and balanced SYN/ACK ratios.',
    format: 'CSV',
    expectedThreat: 'Normal Baseline',
    observationCount: 36
  },
  {
    id: 'sample-syn-flood',
    name: 'SYN Flood Volumetric Attack',
    category: 'DDoS',
    description: 'High-frequency TCP SYN packet burst directed at public web VIP (192.168.10.45:443). Zero ACKs returned, driving SYN/ACK ratio > 40:1.',
    format: 'PCAP',
    expectedThreat: 'SYN Flood',
    observationCount: 42
  },
  {
    id: 'sample-udp-flood',
    name: 'UDP Flood Ingress Burst',
    category: 'DDoS',
    description: 'High-datagram UDP volume stream directed at internal authoritative DNS server (192.168.10.50:53) to saturate edge port buffers.',
    format: 'CSV',
    expectedThreat: 'UDP Flood',
    observationCount: 38
  },
  {
    id: 'sample-udp-amplification',
    name: 'UDP Reflection & Amplification',
    category: 'DDoS',
    description: 'Reflected volumetric attack leveraging external misconfigured NTP servers (port 123) with 55x response amplification targeting database proxy.',
    format: 'JSON',
    expectedThreat: 'UDP Reflection/Amplification',
    observationCount: 35
  },
  {
    id: 'sample-spoofed-source',
    name: 'Distributed Spoofed-Source Flood',
    category: 'DDoS',
    description: 'High-entropy packet burst utilizing forged bogon source IPs, resulting in Shannon entropy H(X) > 7.1 across randomized source ports.',
    format: 'PCAP',
    expectedThreat: 'Spoofed-Source Flood',
    observationCount: 48
  },
  {
    id: 'sample-c2-beacon',
    name: 'Periodic C2 Beaconing Callback',
    category: 'C2',
    description: 'Low-and-slow stealth machine heartbeats with precise periodicity (45s ± 2.8% jitter) and uniform 240-byte payloads to external command IP.',
    format: 'JSON',
    expectedThreat: 'Botnet C2 Beaconing',
    observationCount: 32
  }
];

export function getSamplePassiveDataset(datasetId: string): {
  meta: SampleDatasetMeta;
  observations: PassiveObservation[];
} {
  const baseTimeMs = Date.now() - 60000;

  switch (datasetId) {
    case 'sample-syn-flood':
      return {
        meta: SAMPLE_DATASET_DEFINITIONS[1],
        observations: generateSynFloodSample(baseTimeMs)
      };
    case 'sample-udp-flood':
      return {
        meta: SAMPLE_DATASET_DEFINITIONS[2],
        observations: generateUdpFloodSample(baseTimeMs)
      };
    case 'sample-udp-amplification':
      return {
        meta: SAMPLE_DATASET_DEFINITIONS[3],
        observations: generateUdpAmpSample(baseTimeMs)
      };
    case 'sample-spoofed-source':
      return {
        meta: SAMPLE_DATASET_DEFINITIONS[4],
        observations: generateSpoofedSourceSample(baseTimeMs)
      };
    case 'sample-c2-beacon':
      return {
        meta: SAMPLE_DATASET_DEFINITIONS[5],
        observations: generateC2BeaconSample(baseTimeMs)
      };
    case 'sample-normal':
    default:
      return {
        meta: SAMPLE_DATASET_DEFINITIONS[0],
        observations: generateNormalBaselineSample(baseTimeMs)
      };
  }
}

// 1. Normal Enterprise Baseline Sample
function generateNormalBaselineSample(baseTimeMs: number): PassiveObservation[] {
  const obs: PassiveObservation[] = [];
  const clients = ['10.0.1.15', '10.0.1.42', '10.0.2.88', '10.0.3.104', '192.168.1.55', '172.16.0.12'];
  const servers = [
    { ip: '192.168.10.45', port: 443, proto: 'TLS' as const },
    { ip: '192.168.10.50', port: 53, proto: 'DNS' as const },
    { ip: '192.168.20.10', port: 443, proto: 'TLS' as const },
    { ip: '10.0.0.1', port: 80, proto: 'TCP' as const }
  ];

  for (let i = 0; i < 36; i++) {
    const timeMs = baseTimeMs + i * 1500 + Math.floor(Math.random() * 400);
    const client = clients[i % clients.length];
    const srv = servers[i % servers.length];
    const isTcp = srv.proto === 'TCP' || srv.proto === 'TLS';
    const pkts = Math.floor(Math.random() * 8) + 2;
    const avgSize = srv.proto === 'DNS' ? 84 : 720;
    const bytes = pkts * avgSize;

    obs.push({
      id: `sample-norm-${i + 1}`,
      timestamp: new Date(timeMs).toISOString(),
      timestampMs: timeMs,
      sourceIp: client,
      destinationIp: srv.ip,
      sourcePort: 49152 + Math.floor(Math.random() * 15000),
      destinationPort: srv.port,
      protocol: srv.proto,
      packetCount: pkts,
      byteCount: bytes,
      durationMs: 400 + Math.floor(Math.random() * 800),
      tcpFlags: isTcp ? ['SYN', 'ACK'] : undefined,
      packetSizes: [avgSize, Math.round(avgSize * 1.2), Math.round(avgSize * 0.8)],
      interArrivalTimes: [120, 180, 240],
      payloadSnippet: `0x17030300... [Legitimate ${srv.proto} Ingress]`,
      rawSource: 'CSV'
    });
  }
  return obs;
}

// 2. SYN Flood Sample
function generateSynFloodSample(baseTimeMs: number): PassiveObservation[] {
  const obs: PassiveObservation[] = [];
  const targetIp = '192.168.10.45';
  const targetPort = 443;

  for (let i = 0; i < 42; i++) {
    const timeMs = baseTimeMs + i * 1100;
    const botOctet = 100 + (i % 6);
    const srcIp = `198.51.100.${botOctet}`;
    const pkts = 450 + Math.floor(Math.random() * 200);
    const bytes = pkts * 64; // Standard 64-byte TCP SYN packet

    obs.push({
      id: `sample-syn-${i + 1}`,
      timestamp: new Date(timeMs).toISOString(),
      timestampMs: timeMs,
      sourceIp: srcIp,
      destinationIp: targetIp,
      sourcePort: 1024 + Math.floor(Math.random() * 60000),
      destinationPort: targetPort,
      protocol: 'TCP',
      packetCount: pkts,
      byteCount: bytes,
      durationMs: 800,
      tcpFlags: ['SYN'], // Strictly SYN, no ACKs
      packetSizes: [64],
      interArrivalTimes: [0.05, 0.08, 0.04],
      payloadSnippet: `0x4500003c... TCP Flag: SYN [Half-Open Burst]`,
      rawSource: 'PCAP'
    });
  }
  return obs;
}

// 3. UDP Flood Sample
function generateUdpFloodSample(baseTimeMs: number): PassiveObservation[] {
  const obs: PassiveObservation[] = [];
  const targetIp = '192.168.10.50';
  const targetPort = 53;

  for (let i = 0; i < 38; i++) {
    const timeMs = baseTimeMs + i * 1300;
    const srcIp = `203.0.113.${10 + (i % 8)}`;
    const pkts = 380 + Math.floor(Math.random() * 150);
    const bytes = pkts * 512;

    obs.push({
      id: `sample-udp-${i + 1}`,
      timestamp: new Date(timeMs).toISOString(),
      timestampMs: timeMs,
      sourceIp: srcIp,
      destinationIp: targetIp,
      sourcePort: 5000 + Math.floor(Math.random() * 20000),
      destinationPort: targetPort,
      protocol: 'UDP',
      packetCount: pkts,
      byteCount: bytes,
      durationMs: 900,
      packetSizes: [512],
      interArrivalTimes: [0.1, 0.12, 0.08],
      payloadSnippet: `0x00010000... UDP Direct Flood Datagram`,
      rawSource: 'CSV'
    });
  }
  return obs;
}

// 4. UDP Amplification Sample
function generateUdpAmpSample(baseTimeMs: number): PassiveObservation[] {
  const obs: PassiveObservation[] = [];
  const targetIp = '192.168.20.10'; // Core DB Proxy
  const targetPort = 5432;

  for (let i = 0; i < 35; i++) {
    const timeMs = baseTimeMs + i * 1400;
    const reflectorIp = `192.0.2.${50 + (i % 4)}`; // Misconfigured NTP Reflector
    const pkts = 280 + Math.floor(Math.random() * 120);
    const bytes = pkts * 1420; // High byte payload amplification (monlist response)

    obs.push({
      id: `sample-amp-${i + 1}`,
      timestamp: new Date(timeMs).toISOString(),
      timestampMs: timeMs,
      sourceIp: reflectorIp,
      destinationIp: targetIp,
      sourcePort: 123, // NTP source port
      destinationPort: targetPort,
      protocol: 'NTP',
      packetCount: pkts,
      byteCount: bytes,
      durationMs: 950,
      packetSizes: [1420],
      interArrivalTimes: [0.08, 0.06],
      payloadSnippet: `0xd70004fa... NTP Monlist Response (55x Amplification)`,
      rawSource: 'JSON'
    });
  }
  return obs;
}

// 5. Spoofed-Source Flood Sample
function generateSpoofedSourceSample(baseTimeMs: number): PassiveObservation[] {
  const obs: PassiveObservation[] = [];
  const targetIp = '192.168.10.1';
  const targetPort = 8080;

  for (let i = 0; i < 48; i++) {
    const timeMs = baseTimeMs + i * 1000;
    // Forged Bogon IP addresses across diverse subnets -> Maximum Shannon entropy
    const oct1 = 11 + ((i * 17) % 200);
    const oct2 = 45 + ((i * 31) % 180);
    const oct3 = 78 + ((i * 47) % 150);
    const srcIp = `${oct1}.${oct2}.${oct3}.${(i * 13) % 250 + 1}`;

    const pkts = 320 + Math.floor(Math.random() * 180);
    const bytes = pkts * 96;

    obs.push({
      id: `sample-bogon-${i + 1}`,
      timestamp: new Date(timeMs).toISOString(),
      timestampMs: timeMs,
      sourceIp: srcIp,
      destinationIp: targetIp,
      sourcePort: 1024 + Math.floor(Math.random() * 64000),
      destinationPort: targetPort,
      protocol: 'TCP',
      packetCount: pkts,
      byteCount: bytes,
      durationMs: 700,
      tcpFlags: ['SYN'],
      packetSizes: [96],
      interArrivalTimes: [0.02, 0.03],
      payloadSnippet: `0x45000060... Spoofed Ingress Bogon Datagram`,
      rawSource: 'PCAP'
    });
  }
  return obs;
}

// 6. C2 Beacon Sample
function generateC2BeaconSample(baseTimeMs: number): PassiveObservation[] {
  const obs: PassiveObservation[] = [];
  const infectedHost = '10.0.4.118';
  const c2Server = '198.51.100.88';
  const c2Port = 8443;
  const nominalIntervalMs = 45000; // 45 second beacon

  // Create 32 periodic observations with low jitter (±2.5%)
  for (let i = 0; i < 32; i++) {
    // Jitter: ±1.2 seconds around 45s interval
    const jitterMs = Math.round((Math.random() - 0.5) * 2400);
    const timeMs = baseTimeMs + i * nominalIntervalMs + jitterMs;
    const uniformPacketSize = 240; // Cobalt Strike TLS Client Hello / Checkin size

    obs.push({
      id: `sample-c2-${i + 1}`,
      timestamp: new Date(timeMs).toISOString(),
      timestampMs: timeMs,
      sourceIp: infectedHost,
      destinationIp: c2Server,
      sourcePort: 51234,
      destinationPort: c2Port,
      protocol: 'TLS',
      packetCount: 4,
      byteCount: uniformPacketSize * 4,
      durationMs: 120,
      tcpFlags: ['SYN', 'ACK', 'PSH'],
      packetSizes: [uniformPacketSize, uniformPacketSize, uniformPacketSize, uniformPacketSize],
      interArrivalTimes: i > 0 ? [nominalIntervalMs + jitterMs] : [45000],
      payloadSnippet: `0x16030100f0... [Automated C2 Heartbeat]`,
      rawSource: 'JSON'
    });
  }
  return obs;
}

/**
 * Converts observations to downloadable CSV format for file upload testing
 */
export function observationsToCsv(observations: PassiveObservation[]): string {
  const headers = ['timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'packets', 'bytes', 'duration_ms', 'tcp_flags'];
  const rows = observations.map((obs) => [
    obs.timestamp,
    obs.sourceIp,
    obs.destinationIp,
    obs.sourcePort,
    obs.destinationPort,
    obs.protocol,
    obs.packetCount,
    obs.byteCount,
    obs.durationMs,
    obs.tcpFlags?.join('|') || ''
  ].join(','));

  return [headers.join(','), ...rows].join('\n');
}

/**
 * Converts observations to downloadable JSON format
 */
export function observationsToJson(observations: PassiveObservation[]): string {
  return JSON.stringify(observations, null, 2);
}
