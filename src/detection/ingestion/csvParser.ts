/**
 * OneWaySentinel AI - CSV Flow Log Parser
 * Parses NetFlow v5/v9, IPFIX, and custom CSV flow exports into normalized PassiveObservation records.
 * Gracefully validates fields, handles malformed rows, and tracks valid vs. invalid lines without crashing.
 */

import { PassiveObservation } from './types';

export interface CsvIngestionResult {
  success: boolean;
  observations: PassiveObservation[];
  validRecords: number;
  invalidRecords: number;
  totalBytes: number;
  totalPackets: number;
  durationSeconds: number;
  error?: string;
  parseErrors: string[];
}

export function parseCsvPassive(csvText: string): CsvIngestionResult {
  if (!csvText || csvText.trim().length === 0) {
    return {
      success: false,
      observations: [],
      validRecords: 0,
      invalidRecords: 0,
      totalBytes: 0,
      totalPackets: 0,
      durationSeconds: 0,
      error: 'Empty CSV payload provided. Expected header row and comma-separated flow records.',
      parseErrors: ['Empty CSV payload']
    };
  }

  const lines = csvText.trim().split(/\r?\n/);
  if (lines.length < 2) {
    return {
      success: false,
      observations: [],
      validRecords: 0,
      invalidRecords: 0,
      totalBytes: 0,
      totalPackets: 0,
      durationSeconds: 0,
      error: 'CSV file contains only a single line or header. At least one flow observation record is required.',
      parseErrors: ['Insufficient rows']
    };
  }

  // Parse header and map column names to lower-cased keys
  const headerRaw = lines[0].split(',').map((h) => h.trim().replace(/^["']|["']$/g, '').toLowerCase());
  const colIndex: Record<string, number> = {};

  headerRaw.forEach((col, idx) => {
    colIndex[col] = idx;
    // Map common aliases
    if (col === 'src_ip' || col === 'sourceip' || col === 'src' || col === 'saddr' || col === 'source') {
      colIndex['_src_ip'] = idx;
    }
    if (col === 'dst_ip' || col === 'destinationip' || col === 'dst' || col === 'daddr' || col === 'destination') {
      colIndex['_dst_ip'] = idx;
    }
    if (col === 'src_port' || col === 'sourceport' || col === 'sport' || col === 'srcport') {
      colIndex['_src_port'] = idx;
    }
    if (col === 'dst_port' || col === 'destinationport' || col === 'dport' || col === 'dstport') {
      colIndex['_dst_port'] = idx;
    }
    if (col === 'protocol' || col === 'proto') {
      colIndex['_protocol'] = idx;
    }
    if (col === 'packets' || col === 'packet_count' || col === 'packetcount' || col === 'pkts') {
      colIndex['_packets'] = idx;
    }
    if (col === 'bytes' || col === 'byte_count' || col === 'bytecount' || col === 'octets') {
      colIndex['_bytes'] = idx;
    }
    if (col === 'duration' || col === 'duration_ms' || col === 'flow_duration') {
      colIndex['_duration'] = idx;
    }
    if (col === 'tcp_flags' || col === 'flags' || col === 'tcpflags') {
      colIndex['_tcp_flags'] = idx;
    }
    if (col === 'timestamp' || col === 'time' || col === 'start_time' || col === 'ts') {
      colIndex['_timestamp'] = idx;
    }
  });

  const srcIdx = colIndex['_src_ip'] ?? colIndex['src_ip'] ?? colIndex['sourceip'];
  const dstIdx = colIndex['_dst_ip'] ?? colIndex['dst_ip'] ?? colIndex['destinationip'];

  if (srcIdx === undefined || dstIdx === undefined) {
    return {
      success: false,
      observations: [],
      validRecords: 0,
      invalidRecords: lines.length - 1,
      totalBytes: 0,
      totalPackets: 0,
      durationSeconds: 0,
      error: `CSV missing required IP address columns. Expected headers like "src_ip" and "dst_ip" or "sourceIP" and "destinationIP". Observed: [${headerRaw.slice(0, 8).join(', ')}]`,
      parseErrors: ['Missing required IP address columns']
    };
  }

  const observations: PassiveObservation[] = [];
  const parseErrors: string[] = [];
  let validCount = 0;
  let invalidCount = 0;
  let totalPackets = 0;
  let totalBytes = 0;
  let minTs = Infinity;
  let maxTs = -Infinity;

  const nowMs = Date.now();

  for (let i = 1; i < lines.length; i++) {
    const rawLine = lines[i].trim();
    if (!rawLine) continue;

    const parts = rawLine.split(',').map((p) => p.trim().replace(/^["']|["']$/g, ''));
    if (parts.length < 2) {
      invalidCount++;
      if (parseErrors.length < 5) parseErrors.push(`Row ${i + 1}: Malformed delimiter or truncated columns.`);
      continue;
    }

    const srcIp = parts[srcIdx];
    const dstIp = parts[dstIdx];

    // Validate IP string format loosely (IPv4 or IPv6)
    if (!srcIp || !dstIp || (!srcIp.includes('.') && !srcIp.includes(':'))) {
      invalidCount++;
      if (parseErrors.length < 5) parseErrors.push(`Row ${i + 1}: Invalid IP address value ("${srcIp}" -> "${dstIp}").`);
      continue;
    }

    const srcPort = parseInt(parts[colIndex['_src_port'] ?? colIndex['src_port'] ?? -1] || '0', 10) || 49152;
    const dstPort = parseInt(parts[colIndex['_dst_port'] ?? colIndex['dst_port'] ?? -1] || '0', 10) || 80;

    const rawProto = (parts[colIndex['_protocol'] ?? colIndex['protocol'] ?? -1] || 'TCP').toUpperCase();
    let protocol: PassiveObservation['protocol'] = 'TCP';
    if (rawProto.includes('UDP') || rawProto === '17') protocol = 'UDP';
    else if (rawProto.includes('ICMP') || rawProto === '1') protocol = 'ICMP';
    else if (rawProto.includes('DNS')) protocol = 'DNS';
    else if (rawProto.includes('TLS') || rawProto.includes('SSL') || dstPort === 443 || dstPort === 8443) protocol = 'TLS';
    else if (rawProto.includes('NTP') || dstPort === 123) protocol = 'NTP';
    else if (rawProto.includes('SSDP') || dstPort === 1900) protocol = 'SSDP';

    const pkts = Math.max(1, parseInt(parts[colIndex['_packets'] ?? colIndex['packets'] ?? -1] || '1', 10) || 1);
    const bytes = Math.max(pkts * 40, parseInt(parts[colIndex['_bytes'] ?? colIndex['bytes'] ?? -1] || '64', 10) || (pkts * 64));
    const durMs = Math.max(0, parseFloat(parts[colIndex['_duration'] ?? colIndex['duration'] ?? -1] || '100') || 100);

    const flagsRaw = parts[colIndex['_tcp_flags'] ?? colIndex['tcp_flags'] ?? -1];
    let tcpFlags: string[] | undefined = undefined;
    if (flagsRaw) {
      tcpFlags = flagsRaw.split(/[|+]/).map((f) => f.trim().toUpperCase()).filter(Boolean);
    } else if (protocol === 'TCP') {
      tcpFlags = ['SYN'];
    }

    const rawTs = parts[colIndex['_timestamp'] ?? colIndex['timestamp'] ?? -1];
    let tsMs = nowMs - (lines.length - i) * 1000;
    if (rawTs) {
      const parsed = Date.parse(rawTs);
      if (!isNaN(parsed)) {
        tsMs = parsed;
      } else {
        const num = Number(rawTs);
        if (!isNaN(num) && num > 100000000) {
          tsMs = num > 1e12 ? num : num * 1000;
        }
      }
    }

    if (tsMs < minTs) minTs = tsMs;
    if (tsMs > maxTs) maxTs = tsMs;

    validCount++;
    totalPackets += pkts;
    totalBytes += bytes;

    const avgPktSize = Math.round(bytes / pkts);
    const avgIat = pkts > 1 && durMs > 0 ? Number((durMs / (pkts - 1)).toFixed(2)) : 0;

    observations.push({
      id: `csv-obs-${validCount}`,
      timestamp: new Date(tsMs).toISOString(),
      timestampMs: tsMs,
      sourceIp: srcIp,
      destinationIp: dstIp,
      sourcePort: srcPort,
      destinationPort: dstPort,
      protocol,
      packetCount: pkts,
      byteCount: bytes,
      durationMs: durMs,
      tcpFlags,
      packetSizes: [avgPktSize],
      interArrivalTimes: avgIat > 0 ? [avgIat] : [],
      payloadSnippet: `Passive CSV Flow #${validCount}`,
      rawSource: 'CSV'
    });
  }

  const durationSec = minTs !== Infinity && maxTs !== -Infinity ? Math.max(1, (maxTs - minTs) / 1000) : 10;

  return {
    success: validCount > 0,
    observations,
    validRecords: validCount,
    invalidRecords: invalidCount,
    totalBytes,
    totalPackets,
    durationSeconds: Number(durationSec.toFixed(2)),
    error: validCount === 0 ? 'No valid flow records could be extracted from the CSV.' : undefined,
    parseErrors
  };
}
