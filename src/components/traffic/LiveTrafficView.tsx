import React, { useState } from 'react';
import {
  Activity,
  Filter,
  Search,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Pause,
  Play,
  ArrowDownRight,
  ShieldAlert,
  X
} from 'lucide-react';
import { NetworkPacket, SimulationScenario } from '../../types';

interface LiveTrafficViewProps {
  packets: NetworkPacket[];
  isStreaming: boolean;
  onToggleStreaming: () => void;
  activeScenario: SimulationScenario;
}

export const LiveTrafficView: React.FC<LiveTrafficViewProps> = ({
  packets,
  isStreaming,
  onToggleStreaming,
  activeScenario
}) => {
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [anomalyOnly, setAnomalyOnly] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedPacket, setSelectedPacket] = useState<NetworkPacket | null>(null);

  const filteredPackets = packets.filter((pkt) => {
    if (protocolFilter !== 'ALL' && pkt.protocol !== protocolFilter) return false;
    if (anomalyOnly && !pkt.isAnomaly) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        (pkt.sourceIp || '').toLowerCase().includes(q) ||
        (pkt.destIp || '').toLowerCase().includes(q) ||
        (pkt.protocol || '').toLowerCase().includes(q) ||
        String(pkt.sourcePort ?? '').includes(q) ||
        String(pkt.destPort ?? '').includes(q)
      );
    }
    return true;
  });

  return (
    <div id="live-traffic-view" className="space-y-4 select-none">
      {/* Header bar */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-xl">
        <div>
          <h2 className="text-sm font-bold text-slate-100 uppercase tracking-widest flex items-center gap-2">
            <Activity className="w-4 h-4 text-blue-500" />
            Passive Ingress Flow Monitor (One-Way Diode Tap)
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Zero-copy DPDK packet ring buffer capturing physical optical ingress. No reverse packets permitted.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onToggleStreaming}
            className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border font-mono-code font-bold uppercase tracking-wider cursor-pointer transition ${
              isStreaming
                ? 'bg-blue-600/10 text-blue-400 border-blue-500/30 hover:bg-blue-600/20'
                : 'bg-amber-500/10 text-amber-400 border-amber-500/30 hover:bg-amber-500/20'
            }`}
          >
            {isStreaming ? (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-ping" />
                <span>Live Feed Active</span>
                <Pause className="w-3 h-3 ml-1" />
              </>
            ) : (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                <span>Stream Paused</span>
                <Play className="w-3 h-3 ml-1" />
              </>
            )}
          </button>
        </div>
      </div>

      {/* Filter and search controls */}
      <div className="bg-[#11111d] border border-slate-800 rounded-lg p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1 text-slate-500 mr-2 text-[10px] uppercase font-bold tracking-widest">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <span>Protocol:</span>
          </div>
          {['ALL', 'TCP', 'UDP', 'TLS', 'DNS', 'NTP'].map((proto) => (
            <button
              key={proto}
              onClick={() => setProtocolFilter(proto)}
              className={`px-2.5 py-1 rounded text-xs font-mono font-bold uppercase tracking-wider transition cursor-pointer ${
                protocolFilter === proto
                  ? 'bg-blue-600/20 text-blue-400 border border-blue-500/40'
                  : 'bg-[#050508] text-slate-400 border border-slate-800 hover:text-slate-200'
              }`}
            >
              {proto}
            </button>
          ))}

          <label className="flex items-center gap-2 ml-3 text-slate-300 cursor-pointer">
            <input
              type="checkbox"
              checked={anomalyOnly}
              onChange={(e) => setAnomalyOnly(e.target.checked)}
              className="rounded bg-[#050508] border-slate-700 text-red-500 focus:ring-0"
            />
            <span className="text-red-400 font-bold uppercase text-[10px] tracking-wider">Anomalies Only</span>
          </label>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search IP, Port, Protocol..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#050508] border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
          />
        </div>
      </div>

      {/* Packet Table */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg overflow-hidden shadow-sm">
        <div className="overflow-x-auto max-h-[520px]">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-black/40 text-slate-500 uppercase text-[10px] tracking-wider sticky top-0 z-10 border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Source Socket</th>
                <th className="py-2.5 px-3">Destination Socket</th>
                <th className="py-2.5 px-3">Proto</th>
                <th className="py-2.5 px-3">Flags</th>
                <th className="py-2.5 px-3">Len</th>
                <th className="py-2.5 px-3">IAT (ms)</th>
                <th className="py-2.5 px-3">Entropy</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-[11px]">
              {filteredPackets.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-8 text-center text-slate-500 font-sans">
                    No packet flows match the specified filter criteria.
                  </td>
                </tr>
              ) : (
                filteredPackets.map((pkt, idx) => (
                  <tr
                    key={`${pkt.id}-${idx}`}
                    onClick={() => setSelectedPacket(pkt)}
                    className={`transition cursor-pointer ${
                      pkt.isAnomaly
                        ? 'bg-red-950/20 hover:bg-red-950/40 text-red-200'
                        : 'hover:bg-white/5 text-slate-300'
                    }`}
                  >
                    <td className="py-2 px-3 text-slate-400 text-[10px]">
                      {pkt.timestamp
                        ? pkt.timestamp.includes(' ')
                          ? pkt.timestamp.split(' ')?.[1] || pkt.timestamp
                          : pkt.timestamp.includes('T')
                          ? pkt.timestamp.split('T')?.[1]?.substring(0, 8) || pkt.timestamp
                          : pkt.timestamp
                        : '--:--:--'}
                    </td>
                    <td className="py-2 px-3 text-slate-200 font-semibold">
                      {pkt.sourceIp}:{pkt.sourcePort}
                    </td>
                    <td className="py-2 px-3 text-blue-400">
                      {pkt.destIp}:{pkt.destPort}
                    </td>
                    <td className="py-2 px-3">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${
                          pkt.protocol === 'TCP'
                            ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30'
                            : pkt.protocol === 'UDP'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : pkt.protocol === 'TLS'
                            ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                            : 'bg-green-500/20 text-green-400 border border-green-500/30'
                        }`}
                      >
                        {pkt.protocol}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-slate-500 text-[10px]">{pkt.flags || '—'}</td>
                    <td className="py-2 px-3 text-slate-300">{pkt.length} B</td>
                    <td className="py-2 px-3 text-slate-400">{pkt.interArrivalTimeMs}</td>
                    <td className="py-2 px-3">
                      <span className={pkt.shannonEntropy > 6.5 ? 'text-amber-400 font-bold' : 'text-slate-400'}>
                        {pkt.shannonEntropy}
                      </span>
                    </td>
                    <td className="py-2 px-3">
                      {pkt.isAnomaly ? (
                        <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase bg-red-500 text-white inline-flex items-center gap-1">
                          <AlertTriangle className="w-2.5 h-2.5 text-white" />
                          {pkt.threatTag || 'Anomaly'}
                        </span>
                      ) : (
                        <span className="text-green-400 text-[10px] font-bold uppercase inline-flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3 text-green-400" /> Nominal
                        </span>
                      )}
                    </td>
                    <td className="py-2 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedPacket(pkt);
                        }}
                        className="px-2 py-0.5 rounded bg-[#11111d] hover:bg-slate-800 border border-slate-700 text-blue-400 text-[10px] font-mono transition"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Packet Inspection Modal */}
      {selectedPacket && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0a0a12] border border-slate-800 rounded-lg max-w-2xl w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-blue-400" />
                <h3 className="font-bold text-slate-100 text-sm uppercase tracking-widest">
                  Deep Flow Packet Inspector: {selectedPacket.id}
                </h3>
              </div>
              <button
                onClick={() => setSelectedPacket(null)}
                className="text-slate-500 hover:text-slate-200 p-1 rounded-md cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono bg-[#050508] p-3 rounded border border-slate-800">
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Protocol</span>
                <span className="text-blue-400 font-bold">{selectedPacket.protocol}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">Packet Length</span>
                <span className="text-slate-200">{selectedPacket.length} bytes</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">TCP Flags</span>
                <span className="text-amber-400 font-bold">{selectedPacket.flags || 'N/A'}</span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase">IAT (Arrival)</span>
                <span className="text-slate-200">{selectedPacket.interArrivalTimeMs} ms</span>
              </div>
            </div>

            <div className="space-y-2 text-xs">
              <div className="text-slate-500 font-mono font-bold uppercase text-[10px] tracking-wider">Unidirectional Flow Vector:</div>
              <div className="bg-[#050508] p-3 rounded border border-slate-800 font-mono flex items-center justify-between">
                <div>
                  <span className="text-slate-500 text-[9px] uppercase tracking-wider block">SOURCE (INGRESS)</span>
                  <div className="text-slate-200 font-bold text-xs">{selectedPacket.sourceIp}</div>
                  <div className="text-slate-400 text-[10px]">Port: {selectedPacket.sourcePort}</div>
                </div>
                <div className="text-blue-400 text-xs font-bold tracking-widest">
                  ──────▶ [1-WAY] ──────▶
                </div>
                <div>
                  <span className="text-slate-500 text-[9px] uppercase tracking-wider block">DESTINATION (PROTECTED)</span>
                  <div className="text-blue-400 font-bold text-xs">{selectedPacket.destIp}</div>
                  <div className="text-slate-400 text-[10px]">Port: {selectedPacket.destPort}</div>
                </div>
              </div>
            </div>

            {/* Hex Dump & Raw Payload Snippet */}
            <div className="space-y-1">
              <span className="text-[10px] text-slate-500 font-mono uppercase font-bold tracking-wider block">
                Payload Snippet & Dissector:
              </span>
              <pre className="bg-[#050508] p-3 rounded border border-slate-800 text-xs font-mono text-blue-300 overflow-x-auto whitespace-pre-wrap">
                {selectedPacket.payloadSnippet || '0x4500003c 7a2b4000 4006... [Standard L3/L4 Raw Ingress Header]'}
              </pre>
            </div>

            {/* Analytical Assessment */}
            <div className="p-3 rounded border bg-[#050508] border-slate-800 text-xs space-y-1">
              <span className="text-slate-400 font-semibold block text-[11px] uppercase tracking-wider">Passive Threat Assessment:</span>
              <p className="text-slate-300 text-xs leading-relaxed">
                {selectedPacket.isAnomaly
                  ? `Anomalous pattern identified (${selectedPacket.threatTag}). Exceeds standard baseline variance. Confidence score calculated via passive sliding-window heuristics.`
                  : 'Packet flow is fully compliant with baseline statistical expectations. No signatures or entropy violations detected.'}
              </p>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedPacket(null)}
                className="px-4 py-1.5 rounded bg-[#11111d] hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono font-bold uppercase tracking-wider cursor-pointer"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
