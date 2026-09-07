/**
 * OneWaySentinel AI - Binary PCAP Packet Metadata Parser
 * Strictly passive dissection. Never transmits, injects, or replays packets.
 */

import { PassiveObservation } from './types';

export interface PcapIngestionResult {
  success: boolean;
  observations: PassiveObservation[];
  validPackets: number;
  invalidPackets: number;
  totalBytes: number;
  durationSeconds: number;
  error?: string;
  metadata: {
    snaplen: number;
    nanosecondResolution: boolean;
    linkType: number;
    magic: string;
  };
}

/**
 * Parses a standard libpcap binary file into normalized PassiveObservation records.
 * Extracts packet metadata only: timestamp, src_ip, dst_ip, src_port, dst_port,
 * protocol, packet length, and TCP flags where available.
 */
export function parsePcapPassive(arrayBuffer: ArrayBuffer): PcapIngestionResult {
  if (!arrayBuffer || arrayBuffer.byteLength < 24) {
    return {
      success: false,
      observations: [],
      validPackets: 0,
      invalidPackets: 0,
      totalBytes: 0,
      durationSeconds: 0,
      error: `Invalid PCAP file: buffer length (${arrayBuffer ? arrayBuffer.byteLength : 0} bytes) is below standard 24-byte libpcap global header.`,
      metadata: { snaplen: 0, nanosecondResolution: false, linkType: 0, magic: '0x0' }
    };
  }

  const dataView = new DataView(arrayBuffer);

  // 1. Validate magic number
  const magic = dataView.getUint32(0, false);
  let isLittleEndian = false;
  let isNano = false;

  if (magic === 0xa1b2c3d4) {
    isLittleEndian = false;
  } else if (magic === 0xd4c3b2a1) {
    isLittleEndian = true;
  } else if (magic === 0xa1b23c4d) {
    isLittleEndian = false;
    isNano = true;
  } else if (magic === 0x4d3cb2a1) {
    isLittleEndian = true;
    isNano = true;
  } else if (magic === 0x0a0d0d0a) {
    return {
      success: false,
      observations: [],
      validPackets: 0,
      invalidPackets: 0,
      totalBytes: 0,
      durationSeconds: 0,
      error: 'PCAPNG format detected (Magic 0x0A0D0D0A). Please upload standard libpcap (.pcap), CSV, or JSON.',
      metadata: { snaplen: 0, nanosecondResolution: false, linkType: 0, magic: '0x0a0d0d0a' }
    };
  } else {
    return {
      success: false,
      observations: [],
      validPackets: 0,
      invalidPackets: 0,
      totalBytes: 0,
      durationSeconds: 0,
      error: `Unsupported PCAP format: magic bytes 0x${magic.toString(16).padStart(8, '0')} do not match standard libpcap header.`,
      metadata: { snaplen: 0, nanosecondResolution: false, linkType: 0, magic: `0x${magic.toString(16)}` }
    };
  }

  const snaplen = dataView.getUint32(16, isLittleEndian);
  const linkType = dataView.getUint32(20, isLittleEndian);

  let offset = 24;
  let validPackets = 0;
  let invalidPackets = 0;
  let totalBytes = 0;
  let firstTsMs = Infinity;
  let lastTsMs = -Infinity;

  const observations: PassiveObservation[] = [];
  let prevPacketTsMs: number | null = null;

  while (offset + 16 <= dataView.byteLength) {
    const tsSec = dataView.getUint32(offset, isLittleEndian);
    const tsSub = dataView.getUint32(offset + 4, isLittleEndian);
    const inclLen = dataView.getUint32(offset + 8, isLittleEndian);
    const origLen = dataView.getUint32(offset + 12, isLittleEndian);
    offset += 16;

    if (offset + inclLen > dataView.byteLength) {
      // Corrupt or truncated tail packet
      invalidPackets++;
      break;
    }

    const tsMs = tsSec * 1000 + Math.floor(isNano ? tsSub / 1000000 : tsSub / 1000);
    if (tsMs < firstTsMs) firstTsMs = tsMs;
    if (tsMs > lastTsMs) lastTsMs = tsMs;

    // Dissect link layer
    let pktOffset = offset;
    let etherType = 0x0800; // Default IPv4

    if (linkType === 1) {
      // Ethernet II (14 bytes)
      if (inclLen >= 14) {
        etherType = dataView.getUint16(pktOffset + 12, false);
        pktOffset += 14;

        // 802.1Q VLAN Tagging
        if (etherType === 0x8100 && inclLen >= 18) {
          etherType = dataView.getUint16(pktOffset + 2, false);
          pktOffset += 4;
        }
      } else {
        invalidPackets++;
        offset += inclLen;
        continue;
      }
    } else if (linkType === 101 || linkType === 12) {
      // Raw IP / IPv4 direct
      etherType = 0x0800;
    }

    if (etherType === 0x0800 && pktOffset + 20 <= offset + inclLen) {
      // Dissect IPv4
      const ihl = (dataView.getUint8(pktOffset) & 0x0f) * 4;
      const protocolNum = dataView.getUint8(pktOffset + 9);
      const srcIp = `${dataView.getUint8(pktOffset + 12)}.${dataView.getUint8(pktOffset + 13)}.${dataView.getUint8(pktOffset + 14)}.${dataView.getUint8(pktOffset + 15)}`;
      const dstIp = `${dataView.getUint8(pktOffset + 16)}.${dataView.getUint8(pktOffset + 17)}.${dataView.getUint8(pktOffset + 18)}.${dataView.getUint8(pktOffset + 19)}`;

      const l4Offset = pktOffset + ihl;
      let srcPort = 0;
      let dstPort = 0;
      let protoName: PassiveObservation['protocol'] = 'OTHER';
      const tcpFlags: string[] = [];

      if (protocolNum === 6 && l4Offset + 20 <= offset + inclLen) {
        // TCP
        protoName = 'TCP';
        srcPort = dataView.getUint16(l4Offset, false);
        dstPort = dataView.getUint16(l4Offset + 2, false);
        const flagsByte = dataView.getUint8(l4Offset + 13);
        if (flagsByte & 0x02) tcpFlags.push('SYN');
        if (flagsByte & 0x10) tcpFlags.push('ACK');
        if (flagsByte & 0x01) tcpFlags.push('FIN');
        if (flagsByte & 0x04) tcpFlags.push('RST');
        if (flagsByte & 0x08) tcpFlags.push('PSH');

        if (dstPort === 443 || srcPort === 443 || dstPort === 8443 || srcPort === 8443) {
          protoName = 'TLS';
        }
      } else if (protocolNum === 17 && l4Offset + 8 <= offset + inclLen) {
        // UDP
        protoName = 'UDP';
        srcPort = dataView.getUint16(l4Offset, false);
        dstPort = dataView.getUint16(l4Offset + 2, false);

        if (dstPort === 53 || srcPort === 53) protoName = 'DNS';
        else if (dstPort === 123 || srcPort === 123) protoName = 'NTP';
        else if (dstPort === 1900 || srcPort === 1900) protoName = 'SSDP';
      } else if (protocolNum === 1) {
        protoName = 'ICMP';
      }

      const packetIat = prevPacketTsMs !== null ? Math.max(0, tsMs - prevPacketTsMs) : 0;
      prevPacketTsMs = tsMs;

      validPackets++;
      totalBytes += origLen;

      // Extract brief passive payload preview safely (hex)
      let payloadSnippet = '';
      const payloadStart = l4Offset + (protoName === 'TCP' ? 20 : 8);
      if (payloadStart < offset + inclLen) {
        const snippetLen = Math.min(16, offset + inclLen - payloadStart);
        const hexParts: string[] = [];
        for (let b = 0; b < snippetLen; b++) {
          hexParts.push(dataView.getUint8(payloadStart + b).toString(16).padStart(2, '0'));
        }
        payloadSnippet = `0x${hexParts.join('')}`;
      }

      observations.push({
        id: `pcap-obs-${validPackets}`,
        timestamp: new Date(tsMs).toISOString(),
        timestampMs: tsMs,
        sourceIp: srcIp,
        destinationIp: dstIp,
        sourcePort: srcPort,
        destinationPort: dstPort,
        protocol: protoName,
        packetCount: 1,
        byteCount: origLen,
        durationMs: 0,
        tcpFlags: tcpFlags.length > 0 ? tcpFlags : undefined,
        packetSizes: [origLen],
        interArrivalTimes: packetIat > 0 ? [packetIat] : [],
        payloadSnippet: payloadSnippet || undefined,
        rawSource: 'PCAP'
      });
    } else {
      // Non-IPv4 or malformed header
      invalidPackets++;
    }

    offset += inclLen;
  }

  const durationSec = firstTsMs !== Infinity && lastTsMs !== -Infinity ? Math.max(1, (lastTsMs - firstTsMs) / 1000) : 1;

  return {
    success: true,
    observations,
    validPackets,
    invalidPackets,
    totalBytes,
    durationSeconds: Number(durationSec.toFixed(2)),
    metadata: {
      snaplen,
      nanosecondResolution: isNano,
      linkType,
      magic: `0x${magic.toString(16).padStart(8, '0')}`
    }
  };
}
