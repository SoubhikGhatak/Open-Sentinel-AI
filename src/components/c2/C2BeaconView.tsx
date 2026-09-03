import React, { useState } from 'react';
import {
  Radio,
  Activity,
  AlertTriangle,
  Fingerprint,
  Clock,
  CheckCircle2,
  ShieldAlert,
  Search,
  Zap,
  Info
} from 'lucide-react';
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell
} from 'recharts';
import { C2BeaconCandidate, SimulationScenario } from '../../types';

interface C2BeaconViewProps {
  beacons: C2BeaconCandidate[];
  activeScenario: SimulationScenario;
}

export const C2BeaconView: React.FC<C2BeaconViewProps> = ({ beacons, activeScenario }) => {
  const [selectedBeacon, setSelectedBeacon] = useState<C2BeaconCandidate>(beacons[0]);
  const isC2Scenario = activeScenario.id === 'c2-beacon';

  // Synthetic scatter data: Connection interval (s) vs Payload Size (bytes)
  const scatterData = [
    { interval: 45.2, size: 340, jitter: 3.4, name: '10.0.4.118 (Simulated Cobalt Strike-like pattern)', confidence: 94, color: '#ef4444' },
    { interval: 44.9, size: 340, jitter: 3.2, name: '10.0.4.118 (Simulated Cobalt Strike-like pattern)', confidence: 94, color: '#ef4444' },
    { interval: 45.8, size: 342, jitter: 3.6, name: '10.0.4.118 (Simulated Cobalt Strike-like pattern)', confidence: 94, color: '#ef4444' },
    { interval: 45.1, size: 340, jitter: 3.1, name: '10.0.4.118 (Simulated Cobalt Strike-like pattern)', confidence: 94, color: '#ef4444' },
    { interval: 120.2, size: 512, jitter: 5.1, name: '10.0.8.44 (Simulated Sliver-like scenario)', confidence: 89, color: '#f59e0b' },
    { interval: 119.8, size: 512, jitter: 4.8, name: '10.0.8.44 (Simulated Sliver-like scenario)', confidence: 89, color: '#f59e0b' },
    { interval: 300.5, size: 890, jitter: 12.8, name: '10.0.12.203 (Simulated C2 beacon scenario)', confidence: 78, color: '#a855f7' },
    // Normal noise background
    { interval: 12.4, size: 1420, jitter: 45.0, name: 'Normal HTTP flow', confidence: 12, color: '#334155' },
    { interval: 28.1, size: 840, jitter: 62.0, name: 'Normal API poll', confidence: 18, color: '#334155' },
    { interval: 8.5, size: 210, jitter: 80.0, name: 'Normal DNS sync', confidence: 8, color: '#334155' }
  ];

  return (
    <div id="c2-beacon-view" className="space-y-4 select-none">
      {/* Header */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-xl">
        <div>
          <h2 className="text-sm font-bold text-slate-100 uppercase tracking-widest flex items-center gap-2">
            <Radio className="w-4 h-4 text-purple-400" />
            Passive Botnet C2 Beacon Detection (FFT & Spectral Jitter)
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Statistical detection of stealthy low-and-slow command & control callbacks without decrypting payload contents.
          </p>
        </div>

        <div className="bg-[#050508] px-3 py-1.5 rounded border border-slate-800 text-xs flex items-center gap-2 font-mono">
          <span className="text-slate-500 text-[10px] uppercase tracking-wider">Analysis State:</span>
          <span className={`font-bold text-xs uppercase ${isC2Scenario ? 'text-red-400' : 'text-green-400'}`}>
            {isC2Scenario ? 'Simulated C2 Beacon Scenario Detected' : 'Continuous Spectral FFT Monitor'}
          </span>
        </div>
      </div>

      {/* Detection Pillars: Periodicity, Payload Variance, JA3 Fingerprint */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="bg-[#11111d] border border-slate-800 rounded-lg p-3.5">
          <div className="flex items-center justify-between text-xs text-slate-500 mb-1 font-mono uppercase text-[10px] tracking-wider">
            <span>FFT Periodicity Analysis</span>
            <Clock className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <div className="text-xl font-bold font-mono text-blue-400">
            0.022 Hz <span className="text-xs text-slate-500 font-normal">(T = 45.2s)</span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Sharp spectral peak in inter-arrival time frequency confirms synthetic machine timing over human interaction.
          </p>
        </div>

        <div className="bg-[#11111d] border border-slate-800 rounded-lg p-3.5">
          <div className="flex items-center justify-between text-xs text-slate-500 mb-1 font-mono uppercase text-[10px] tracking-wider">
            <span>Payload Length Variance</span>
            <Activity className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono text-amber-400">
            σ² = 1.4 B² <span className="text-xs text-slate-500 font-normal">(Low Variance)</span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Uniform outbound heartbeat sizes (340 bytes) indicative of programmatic C2 polling routines.
          </p>
        </div>

        <div className="bg-[#11111d] border border-slate-800 rounded-lg p-3.5">
          <div className="flex items-center justify-between text-xs text-slate-500 mb-1 font-mono uppercase text-[10px] tracking-wider">
            <span>JA3 TLS Hash Signature</span>
            <Fingerprint className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-xl font-bold font-mono text-purple-300 truncate">
            a0e9f5d6...
          </div>
          <p className="text-xs text-slate-500 mt-1">
            TLS Client Hello cipher suite sequence matches simulated Cobalt Strike-like malleable C2 profile.
          </p>
        </div>
      </div>

      {/* Scatter Chart: Inter-Arrival Interval vs Payload Size */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-[#0a0a12] border border-slate-800 rounded-lg p-4 shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <div>
              <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-purple-400" />
                Connection Interval vs. Payload Size (Beacon Clustering)
              </h3>
              <p className="text-xs text-slate-500">
                Tight clusters with low jitter stand out from random background traffic.
              </p>
            </div>
            <div className="flex items-center gap-3 text-[10px] font-mono">
              <span className="flex items-center gap-1 text-red-400">
                <span className="w-2 h-2 rounded-full bg-red-500" /> Simulated Cobalt Strike
              </span>
              <span className="flex items-center gap-1 text-amber-400">
                <span className="w-2 h-2 rounded-full bg-amber-500" /> Simulated Sliver
              </span>
              <span className="flex items-center gap-1 text-slate-500">
                <span className="w-2 h-2 rounded-full bg-slate-600" /> Background Noise
              </span>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart margin={{ top: 20, right: 20, bottom: 10, left: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1b1b26" vertical={false} />
                <XAxis
                  type="number"
                  dataKey="interval"
                  name="Interval"
                  unit="s"
                  stroke="#64748b"
                  tick={{ fontSize: 10, fill: '#64748b' }}
                  label={{ value: 'Inter-Arrival Time (Seconds)', position: 'insideBottomRight', offset: -5, fill: '#64748b', fontSize: 10 }}
                />
                <YAxis
                  type="number"
                  dataKey="size"
                  name="Size"
                  unit="B"
                  stroke="#64748b"
                  tick={{ fontSize: 10, fill: '#64748b' }}
                  label={{ value: 'Payload Size (Bytes)', angle: -90, position: 'insideLeft', fill: '#64748b', fontSize: 10 }}
                />
                <Tooltip
                  cursor={{ strokeDasharray: '3 3' }}
                  contentStyle={{ backgroundColor: '#0a0a12', borderColor: '#334155', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace' }}
                />
                <Scatter name="Flows" data={scatterData}>
                  {scatterData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Scatter>
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Selected Beacon Dossier */}
        <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2 mb-2">
              <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
              Beacon Dossier Inspector
            </h3>

            {selectedBeacon && (
              <div className="space-y-2.5 text-xs font-mono">
                <div className="bg-[#050508] p-2.5 rounded border border-slate-800">
                  <span className="text-slate-500 text-[9px] uppercase tracking-wider block">INTERNAL COMPROMISED HOST</span>
                  <span className="text-slate-100 font-bold text-xs">{selectedBeacon.sourceIp}</span>
                  <span className="text-slate-500 text-[10px] block">Workstation-Finance-02</span>
                </div>

                <div className="bg-[#050508] p-2.5 rounded border border-slate-800">
                  <span className="text-slate-500 text-[9px] uppercase tracking-wider block">C2 EXTERNAL LISTENER</span>
                  <span className="text-red-400 font-bold text-xs">{selectedBeacon.destinationC2}</span>
                  <span className="text-slate-400 text-[10px] block truncate">{selectedBeacon.c2Domain}</span>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div className="bg-[#050508] p-2 rounded border border-slate-800">
                    <span className="text-slate-500 text-[9px] uppercase tracking-wider block">PERIODICITY</span>
                    <span className="text-blue-400 font-bold">{selectedBeacon.periodicitySeconds}s</span>
                  </div>
                  <div className="bg-[#050508] p-2 rounded border border-slate-800">
                    <span className="text-slate-500 text-[9px] uppercase tracking-wider block">JITTER VARIANCE</span>
                    <span className="text-amber-400 font-bold">±{selectedBeacon.jitterPercentage}%</span>
                  </div>
                </div>

                <div className="bg-[#050508] p-2.5 rounded border border-slate-800">
                  <span className="text-slate-500 text-[9px] uppercase tracking-wider block">MALWARE CORRELATION</span>
                  <span className="text-purple-300 font-bold">{selectedBeacon.knownMalwareFamily}</span>
                  <div className="text-[10px] text-slate-400 mt-1">
                    Confidence: <strong className="text-green-400">{selectedBeacon.confidenceScore}%</strong> (FFT: {selectedBeacon.fftPeakPower})
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-slate-800 text-[10px] font-mono text-slate-500">
            ENCLAVE INVARIANT: Active quarantine host isolation blocked on diode; published to SOC advisory.
          </div>
        </div>
      </div>

      {/* Suspected C2 Beacons Table */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 shadow-sm">
        <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2 mb-3">
          <Radio className="w-3.5 h-3.5 text-purple-400" />
          Active C2 Beacon Candidates (Tracked by Passive Diode)
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-black/40 text-slate-500 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Internal Host</th>
                <th className="py-2.5 px-3">External C2 Socket</th>
                <th className="py-2.5 px-3">C2 Domain</th>
                <th className="py-2.5 px-3">Interval</th>
                <th className="py-2.5 px-3">Jitter</th>
                <th className="py-2.5 px-3">JA3 Hash</th>
                <th className="py-2.5 px-3">Classification</th>
                <th className="py-2.5 px-3">Confidence</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-[11px]">
              {beacons.map((beacon, idx) => (
                <tr
                  key={`${beacon.id}-${idx}`}
                  onClick={() => setSelectedBeacon(beacon)}
                  className={`hover:bg-white/5 transition cursor-pointer ${
                    selectedBeacon?.id === beacon.id ? 'bg-purple-950/20 text-purple-200' : 'text-slate-300'
                  }`}
                >
                  <td className="py-2.5 px-3 font-bold text-slate-200">{beacon.sourceIp}</td>
                  <td className="py-2.5 px-3 text-red-400">{beacon.destinationC2}</td>
                  <td className="py-2.5 px-3 text-slate-400 truncate max-w-xs font-mono text-[11px]">{beacon.c2Domain}</td>
                  <td className="py-2.5 px-3 text-blue-400">{beacon.periodicitySeconds}s</td>
                  <td className="py-2.5 px-3 text-amber-400">±{beacon.jitterPercentage}%</td>
                  <td className="py-2.5 px-3 text-slate-500">{beacon.ja3Hash.substring(0, 10)}...</td>
                  <td className="py-2.5 px-3 font-bold text-slate-200">{beacon.knownMalwareFamily}</td>
                  <td className="py-2.5 px-3 font-bold text-green-400">{beacon.confidenceScore}%</td>
                  <td className="py-2.5 px-3 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedBeacon(beacon);
                      }}
                      className="px-2 py-0.5 rounded bg-[#11111d] text-blue-400 hover:bg-slate-800 border border-slate-700 text-[10px] font-mono transition cursor-pointer"
                    >
                      Select
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
