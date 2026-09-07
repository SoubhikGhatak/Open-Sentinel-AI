/**
 * OneWaySentinel AI - JSON / JSONL Passive Flow Parser
 * Parses JSON arrays or newline-delimited JSON (JSONL) flow records into normalized PassiveObservation records.
 */

import { PassiveObservation } from './types';

export interface JsonIngestionResult {
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

export function parseJsonPassive(jsonText: string): JsonIngestionResult {
  if (!jsonText || jsonText.trim().length === 0) {
    return {
      success: false,
      observations: [],
      validRecords: 0,
      invalidRecords: 0,
      totalBytes: 0,
      totalPackets: 0,
      durationSeconds: 0,
      error: 'Empty JSON payload provided.',
      parseErrors: ['Empty JSON payload']
    };
  }

  const trimmed = jsonText.trim();
  let rawRecords: any[] = [];
  const parseErrors: string[] = [];

  // Determine if it is standard JSON array or JSONL
  if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
    try {
      rawRecords = JSON.parse(trimmed);
      if (!Array.isArray(rawRecords)) {
        rawRecords = [rawRecords];
      }
    } catch (e: any) {
      return {
        success: false,
        observations: [],
        validRecords: 0,
        invalidRecords: 1,
        totalBytes: 0,
        totalPackets: 0,
        durationSeconds: 0,
        error: `JSON parse error: ${e?.message || 'Invalid JSON syntax'}. If using JSONL, ensure each record is separated by a newline.`,
        parseErrors: [e?.message || 'Invalid JSON syntax']
      };
    }
  } else {
    // Treat as JSONL or concatenated objects
    const lines = trimmed.split(/\r?\n/);
    lines.forEach((line, idx) => {
      const lineTrim = line.trim();
      if (!lineTrim) return;
      try {
        const obj = JSON.parse(lineTrim);
        rawRecords.push(obj);
      } catch (e: any) {
        parseErrors.push(`Line ${idx + 1}: Invalid JSON line: ${e?.message || 'syntax error'}`);
      }
    });
  }

  if (rawRecords.length === 0) {
    return {
      success: false,
      observations: [],
      validRecords: 0,
      invalidRecords: parseErrors.length,
      totalBytes: 0,
      totalPackets: 0,
      durationSeconds: 0,
      error: 'No valid JSON flow objects discovered in payload.',
      parseErrors
    };
  }

  const observations: PassiveObservation[] = [];
  let validCount = 0;
  let invalidCount = parseErrors.length;
  let totalPackets = 0;
  let totalBytes = 0;
  let minTs = Infinity;
  let maxTs = -Infinity;
  const nowMs = Date.now();

  rawRecords.forEach((item, idx) => {
    if (!item || typeof item !== 'object') {
      invalidCount++;
      return;
    }

    const srcIp = item.src_ip || item.sourceIP || item.src || item.source_ip || item.saddr || item.source;
    const dstIp = item.dst_ip || item.destinationIP || item.dst || item.destination_ip || item.daddr || item.destination;

    if (!srcIp || !dstIp || typeof srcIp !== 'string' || typeof dstIp !== 'string') {
      invalidCount++;
      if (parseErrors.length < 5) {
        parseErrors.push(`Record #${idx + 1}: Missing required source or destination IP fields.`);
      }
      return;
    }

    const srcPort = parseInt(item.src_port || item.sourcePort || item.sport || item.srcport || '0', 10) || 49152;
    const dstPort = parseInt(item.dst_port || item.destinationPort || item.dport || item.dstport || '0', 10) || 80;

    const rawProto = String(item.protocol || item.proto || 'TCP').toUpperCase();
    let protocol: PassiveObservation['protocol'] = 'TCP';
    if (rawProto.includes('UDP') || rawProto === '17') protocol = 'UDP';
    else if (rawProto.includes('ICMP') || rawProto === '1') protocol = 'ICMP';
    else if (rawProto.includes('DNS')) protocol = 'DNS';
    else if (rawProto.includes('TLS') || rawProto.includes('SSL') || dstPort === 443 || dstPort === 8443) protocol = 'TLS';
    else if (rawProto.includes('NTP') || dstPort === 123) protocol = 'NTP';
    else if (rawProto.includes('SSDP') || dstPort === 1900) protocol = 'SSDP';

    const pkts = Math.max(1, parseInt(item.packets || item.packet_count || item.packetCount || item.pkts || '1', 10) || 1);
    const bytes = Math.max(pkts * 40, parseInt(item.bytes || item.byte_count || item.byteCount || item.octets || '64', 10) || (pkts * 64));
    const durMs = Math.max(0, parseFloat(item.duration || item.duration_ms || item.flow_duration || '100') || 100);

    let tcpFlags: string[] | undefined = undefined;
    if (Array.isArray(item.tcp_flags || item.flags)) {
      tcpFlags = (item.tcp_flags || item.flags).map((f: any) => String(f).toUpperCase());
    } else if (typeof (item.tcp_flags || item.flags) === 'string') {
      tcpFlags = String(item.tcp_flags || item.flags).split(/[|+]/).map((f) => f.trim().toUpperCase()).filter(Boolean);
    } else if (protocol === 'TCP') {
      tcpFlags = ['SYN'];
    }

    let tsMs = nowMs - (rawRecords.length - idx) * 1000;
    const rawTs = item.timestamp || item.time || item.ts || item.start_time;
    if (rawTs) {
      if (typeof rawTs === 'number') {
        tsMs = rawTs > 1e12 ? rawTs : rawTs * 1000;
      } else {
        const parsed = Date.parse(rawTs);
        if (!isNaN(parsed)) tsMs = parsed;
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
      id: `json-obs-${validCount}`,
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
      packetSizes: Array.isArray(item.packetSizes) ? item.packetSizes : [avgPktSize],
      interArrivalTimes: Array.isArray(item.interArrivalTimes) ? item.interArrivalTimes : avgIat > 0 ? [avgIat] : [],
      payloadSnippet: item.payloadSnippet || `Passive JSON Record #${validCount}`,
      rawSource: trimmed.startsWith('[') ? 'JSON' : 'JSONL'
    });
  });

  const durationSec = minTs !== Infinity && maxTs !== -Infinity ? Math.max(1, (maxTs - minTs) / 1000) : 10;

  return {
    success: validCount > 0,
    observations,
    validRecords: validCount,
    invalidRecords: invalidCount,
    totalBytes,
    totalPackets,
    durationSeconds: Number(durationSec.toFixed(2)),
    error: validCount === 0 ? 'No valid flow records could be decoded from the JSON input.' : undefined,
    parseErrors
  };
}
