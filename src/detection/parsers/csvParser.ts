/**
 * CSV / NetFlow Flow Log Ingestion Parser
 * Parses standard NetFlow v5/v9, IPFIX, and custom CSV flow exports into normalized TrafficFlow records.
 */

import { TrafficFlow, ProtocolType } from '../types';

export interface CsvParseResult {
  success: boolean;
  flows: TrafficFlow[];
  totalPackets: number;
  totalBytes: number;
  durationSeconds: number;
  error?: string;
  rowCount: number;
}

export function parseCsvFlows(csvText: string): CsvParseResult {
  if (!csvText || csvText.trim().length === 0) {
    return {
      success: false,
      flows: [],
      totalPackets: 0,
      totalBytes: 0,
      durationSeconds: 0,
      rowCount: 0,
      error: 'Empty CSV payload provided. Expected header row and comma-separated flow records.'
    };
  }

  const lines = csvText.trim().split(/\r?\n/);
  if (lines.length < 2) {
    return {
      success: false,
      flows: [],
      totalPackets: 0,
      totalBytes: 0,
      durationSeconds: 0,
      rowCount: lines.length,
      error: 'CSV file contains only a header or single line. At least one flow record is required.'
    };
  }

  // Parse header and map column indexes
  const header = lines[0].toLowerCase().split(',').map((h) => h.trim().replace(/['"]/g, ''));
  const colIndex: Record<string, number> = {};

  header.forEach((name, idx) => {
    colIndex[name] = idx;
    // Map common NetFlow aliases
    if (name.includes('src') && name.includes('ip')) colIndex['sourceip'] = idx;
    if (name.includes('dst') && name.includes('ip')) colIndex['destinationip'] = idx;
    if (name.includes('src') && name.includes('port')) colIndex['sourceport'] = idx;
    if (name.includes('dst') && name.includes('port')) colIndex['destinationport'] = idx;
    if (name.includes('proto')) colIndex['protocol'] = idx;
    if (name.includes('pkt') || name.includes('packets')) colIndex['packetcount'] = idx;
    if (name.includes('byte') || name.includes('octets')) colIndex['bytecount'] = idx;
    if (name.includes('time') || name.includes('stamp')) colIndex['timestamp'] = idx;
    if (name.includes('dur')) colIndex['duration'] = idx;
    if (name.includes('flag')) colIndex['tcpflags'] = idx;
  });

  // Verify minimal required fields
  const hasIp = (colIndex['sourceip'] !== undefined && colIndex['destinationip'] !== undefined) ||
                (colIndex['src_ip'] !== undefined && colIndex['dst_ip'] !== undefined) ||
                (colIndex['src'] !== undefined && colIndex['dst'] !== undefined);

  if (!hasIp) {
    return {
      success: false,
      flows: [],
      totalPackets: 0,
      totalBytes: 0,
      durationSeconds: 0,
      rowCount: lines.length,
      error: 'CSV format unrecognized. Missing required source and destination IP column headers (e.g. sourceIP, destinationIP).'
    };
  }

  const flows: TrafficFlow[] = [];
  let totalPkts = 0;
  let totalBts = 0;
  let minTs = Infinity;
  let maxTs = -Infinity;

  for (let i = 1; i < lines.length; i++) {
    const row = lines[i].split(',').map((c) => c.trim().replace(/['"]/g, ''));
    if (row.length < 3) continue;

    const srcIp = row[colIndex['sourceip'] ?? colIndex['src_ip'] ?? colIndex['src'] ?? 0] || '192.168.1.100';
    const dstIp = row[colIndex['destinationip'] ?? colIndex['dst_ip'] ?? colIndex['dst'] ?? 1] || '10.0.0.1';
    const srcPort = parseInt(row[colIndex['sourceport'] ?? colIndex['src_port'] ?? 2] || '0', 10) || 49152;
    const dstPort = parseInt(row[colIndex['destinationport'] ?? colIndex['dst_port'] ?? 3] || '0', 10) || 80;

    const rawProto = (row[colIndex['protocol'] ?? colIndex['proto'] ?? 4] || 'TCP').toUpperCase();
    let protocol: ProtocolType = 'TCP';
    if (rawProto.includes('UDP') || rawProto === '17') protocol = 'UDP';
    else if (rawProto.includes('ICMP') || rawProto === '1') protocol = 'ICMP';
    else if (rawProto.includes('DNS')) protocol = 'DNS';
    else if (rawProto.includes('TLS') || rawProto.includes('SSL') || dstPort === 443) protocol = 'TLS';
    else if (rawProto.includes('NTP') || dstPort === 123) protocol = 'NTP';

    const pkts = parseInt(row[colIndex['packetcount'] ?? colIndex['packets'] ?? 5] || '1', 10) || 1;
    const bytes = parseInt(row[colIndex['bytecount'] ?? colIndex['bytes'] ?? 6] || '64', 10) || (pkts * 64);
    const durMs = parseFloat(row[colIndex['duration'] ?? colIndex['duration_ms'] ?? 7] || '100') || 100;

    const flagsRaw = row[colIndex['tcpflags'] ?? colIndex['flags'] ?? 8];
    const flags = flagsRaw ? flagsRaw.split('|').map((f) => f.trim().toUpperCase()) : protocol === 'TCP' ? ['SYN', 'ACK'] : [];

    const rawTs = row[colIndex['timestamp'] ?? colIndex['time'] ?? 9];
    let tsMs = Date.now() - (lines.length - i) * 1000;
    if (rawTs) {
      const parsed = Date.parse(rawTs);
      if (!isNaN(parsed)) tsMs = parsed;
    }

    if (tsMs < minTs) minTs = tsMs;
    if (tsMs > maxTs) maxTs = tsMs;

    totalPkts += pkts;
    totalBts += bytes;

    flows.push({
      id: `csv-flow-${Date.now().toString(36)}-${i}`,
      timestamp: new Date(tsMs).toISOString(),
      timestampMs: tsMs,
      sourceIP: srcIp,
      destinationIP: dstIp,
      sourcePort: srcPort,
      destinationPort: dstPort,
      protocol,
      packetCount: pkts,
      byteCount: bytes,
      durationMs: durMs,
      packetSizes: [Math.round(bytes / pkts)],
      interArrivalTimes: pkts > 1 ? [durMs / (pkts - 1)] : [],
      tcpFlags: flags,
      direction: 'INGRESS'
    });
  }

  const durationSec = minTs !== Infinity && maxTs !== -Infinity ? Math.max(1, (maxTs - minTs) / 1000) : 10;

  return {
    success: true,
    flows,
    totalPackets: totalPkts,
    totalBytes: totalBts,
    durationSeconds: Number(durationSec.toFixed(1)),
    rowCount: flows.length
  };
}
