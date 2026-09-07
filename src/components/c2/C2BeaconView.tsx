import React, { useState, useMemo } from 'react';
import {
  Radio,
  Activity,
  AlertTriangle,
  Fingerprint,
  Clock,
  CheckCircle2,
  ShieldAlert,
  ShieldCheck,
  Zap,
  Info,
  ChevronDown,
  ChevronUp,
  BarChart3,
  Layers,
  Lock,
  ArrowRight,
  TrendingUp,
  Sliders,
  Sparkles
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
import { FullAnalysisPipelineResult } from '../../detection/engine';

interface C2BeaconViewProps {
  beacons: C2BeaconCandidate[];
  activeScenario: SimulationScenario;
  pipeline?: FullAnalysisPipelineResult;
}

export const C2BeaconView: React.FC<C2BeaconViewProps> = ({ beacons, activeScenario, pipeline }) => {
  // Combine pipeline candidates and initial beacons
  const candidateList = useMemo(() => {
    if (pipeline?.c2Candidates && pipeline.c2Candidates.length > 0) {
      return pipeline.c2Candidates;
    }
    return beacons;
  }, [pipeline?.c2Candidates, beacons]);

  const [selectedCandidateId, setSelectedCandidateId] = useState<string>(
    candidateList[0]?.id || 'c2-01'
  );
  const [showEvidenceDetails, setShowEvidenceDetails] = useState<boolean>(true);

  // Auto-sync selection when candidates update
  React.useEffect(() => {
    if (candidateList.length > 0) {
      if (!candidateList.some((c) => c.id === selectedCandidateId)) {
        setSelectedCandidateId(candidateList[0].id);
      }
    }
  }, [candidateList, selectedCandidateId]);

  const activeCandidate = useMemo(() => {
    return candidateList.find((c) => c.id === selectedCandidateId) || candidateList[0] || null;
  }, [candidateList, selectedCandidateId]);

  const isC2Scenario =
    activeScenario.category === 'C2' ||
    activeScenario.id.startsWith('c2-') ||
    (activeCandidate && (activeCandidate.confidenceScore >= 70 || activeCandidate.status === 'Confirmed Beacon'));

  // Metrics extraction for active candidate
  const meanIAT = activeCandidate?.meanIAT ?? activeCandidate?.periodicitySeconds ?? 30.0;
  const stdDevIAT = activeCandidate?.stdDevIAT ?? (meanIAT * ((activeCandidate?.jitterPercentage ?? 3) / 100));
  const cv = activeCandidate?.coefficientOfVariation ?? (meanIAT > 0 ? stdDevIAT / meanIAT : 0);
  const periodicity = activeCandidate?.periodicityScore ?? activeCandidate?.fftPeakPower ?? 0.94;
  const consistency = activeCandidate?.packetSizeConsistency ?? 0.98;
  const concentration = activeCandidate?.destinationConcentration ?? 0.92;
  const frequencyHz = activeCandidate?.connectionFrequencyHz ?? (meanIAT > 0 ? 1 / meanIAT : 0);
  const confidence = activeCandidate?.c2Confidence ?? activeCandidate?.confidenceScore ?? 92;
  const classification = activeCandidate?.classification ?? (confidence >= 80 ? 'High-Confidence C2 Beacon' : 'Suspicious Periodic Communication');
  const severity = activeCandidate?.severity ?? (confidence >= 85 ? 'Critical' : confidence >= 70 ? 'High' : 'Medium');
  const isBenign = activeCandidate?.isBenignPeriodicService || classification === 'Benign Periodic Traffic';

  // Scatter chart data
  const scatterData = useMemo(() => {
    if (pipeline?.c2Clusters && pipeline.c2Clusters.length > 0) {
      const clusterPoints = pipeline.c2Clusters
        .filter((cl) => cl.meanIntervalSeconds > 0)
        .map((cl) => ({
          interval: Number(cl.meanIntervalSeconds.toFixed(1)),
          size: Math.round(cl.packetSizeMean || 340),
          jitter: Number(cl.jitterPercentage.toFixed(1)),
          name: `${cl.sourceIp} -> ${cl.destinationIp}`,
          confidence: cl.c2Confidence ?? 90,
          color: cl.classification.includes('High')
            ? '#ef4444'
            : cl.classification.includes('Suspicious')
            ? '#f59e0b'
            : cl.classification.includes('Benign')
            ? '#10b981'
            : '#8b5cf6'
        }));

      return [
        ...clusterPoints,
        { interval: 14.2, size: 1420, jitter: 54.0, name: 'Normal HTTP flow', confidence: 10, color: '#334155' },
        { interval: 28.5, size: 850, jitter: 68.0, name: 'Normal API poll', confidence: 12, color: '#334155' },
        { interval: 8.1, size: 210, jitter: 82.0, name: 'Normal DNS sync', confidence: 8, color: '#334155' }
      ];
    }

    return [
      { interval: 30.0, size: 340, jitter: 1.5, name: '10.0.4.118 (Periodic C2)', confidence: 95, color: '#ef4444' },
      { interval: 30.2, size: 340, jitter: 1.8, name: '10.0.4.118 (Periodic C2)', confidence: 95, color: '#ef4444' },
      { interval: 29.8, size: 340, jitter: 1.2, name: '10.0.4.118 (Periodic C2)', confidence: 95, color: '#ef4444' },
      { interval: 60.0, size: 488, jitter: 10.5, name: '10.0.6.72 (Jittered C2)', confidence: 82, color: '#f59e0b' },
      { interval: 5.0, size: 256, jitter: 2.2, name: '10.0.8.204 (High-Freq C2)', confidence: 96, color: '#ef4444' },
      { interval: 180.0, size: 412, jitter: 0.4, name: '10.0.12.89 (Low-Freq C2)', confidence: 89, color: '#ef4444' },
      { interval: 14.2, size: 1420, jitter: 54.0, name: 'Normal HTTP flow', confidence: 10, color: '#334155' },
      { interval: 28.5, size: 850, jitter: 68.0, name: 'Normal API poll', confidence: 12, color: '#334155' },
      { interval: 8.1, size: 210, jitter: 82.0, name: 'Normal DNS sync', confidence: 8, color: '#334155' }
    ];
  }, [pipeline?.c2Clusters]);

  // Timeline events for active candidate
  const timelineEvents = useMemo(() => {
    if (activeCandidate?.timelineEvents && activeCandidate.timelineEvents.length > 0) {
      return activeCandidate.timelineEvents;
    }

    // Synthesize realistic sequence for visualization based on meanIAT
    const count = 7;
    const baseTime = Date.now() - count * meanIAT * 1000;
    const events = [];
    for (let i = 0; i < count; i++) {
      const jitterMs = ((i % 5) - 2) * (stdDevIAT * 200);
      const ts = new Date(baseTime + i * meanIAT * 1000 + jitterMs).toISOString().substring(11, 19);
      events.push({
        timestamp: ts,
        deltaSeconds: Number((meanIAT + jitterMs / 1000).toFixed(2)),
        packetSize: activeCandidate?.packetSizeMean || 340,
        jitterDelta: Number((jitterMs / 1000).toFixed(2))
      });
    }
    return events;
  }, [activeCandidate, meanIAT, stdDevIAT]);

  return (
    <div id="c2-beacon-view" className="space-y-4 select-none">
      {/* Header & Architectural Invariant */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-xl">
        <div>
          <div className="flex items-center gap-2">
            <span className="p-1.5 rounded bg-purple-950/60 border border-purple-800/60 text-purple-400">
              <Radio className="w-4 h-4" />
            </span>
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-widest">
              Passive Botnet C2 Beacon Detection Engine
            </h2>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-950/70 text-blue-300 border border-blue-800/60">
              Zero Transmission Tap
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-1">
            Statistical & spectral behavioral analysis across inter-arrival timing (IAT), coefficient of variation, and packet-size consistency.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="bg-[#050508] px-3 py-1.5 rounded border border-slate-800 text-xs font-mono flex items-center gap-2">
            <span className="text-slate-500 text-[10px] uppercase tracking-wider">Engine State:</span>
            <span
              className={`font-bold text-xs uppercase ${
                isBenign
                  ? 'text-emerald-400'
                  : isC2Scenario
                  ? 'text-red-400'
                  : 'text-green-400'
              }`}
            >
              {isBenign
                ? 'Benign Periodic Infrastructure'
                : isC2Scenario
                ? 'Active C2 Beacon Pattern'
                : 'Continuous Passive Monitoring'}
            </span>
          </div>
        </div>
      </div>

      {/* Primary Behavioral Analysis Cards (7 Key Metrics) */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2.5">
        {/* Card 1: Mean IAT */}
        <div className="bg-[#0f0f18] border border-slate-800/80 rounded-lg p-3 flex flex-col justify-between">
          <div className="flex items-center justify-between text-[10px] font-mono uppercase text-slate-400">
            <span>Mean IAT</span>
            <Clock className="w-3.5 h-3.5 text-blue-400" />
          </div>
          <div className="mt-2">
            <div className="text-lg font-bold font-mono text-blue-400">
              {meanIAT > 0 ? `${meanIAT.toFixed(1)}s` : 'N/A'}
            </div>
            <div className="text-[10px] font-mono text-slate-500 mt-0.5 truncate">
              σ = ±{stdDevIAT.toFixed(2)}s
            </div>
          </div>
        </div>

        {/* Card 2: Std Dev IAT */}
        <div className="bg-[#0f0f18] border border-slate-800/80 rounded-lg p-3 flex flex-col justify-between">
          <div className="flex items-center justify-between text-[10px] font-mono uppercase text-slate-400">
            <span>Std Dev (IAT)</span>
            <TrendingUp className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="mt-2">
            <div className="text-lg font-bold font-mono text-cyan-400">
              {stdDevIAT.toFixed(2)}s
            </div>
            <div className="text-[10px] font-mono text-slate-500 mt-0.5 truncate">
              {stdDevIAT < 1.0 ? 'Extremely Low Jitter' : stdDevIAT < 10.0 ? 'Evasion Sleep Jitter' : 'Organic Variance'}
            </div>
          </div>
        </div>

        {/* Card 3: Coefficient of Variation (CV) */}
        <div className="bg-[#0f0f18] border border-slate-800/80 rounded-lg p-3 flex flex-col justify-between">
          <div className="flex items-center justify-between text-[10px] font-mono uppercase text-slate-400">
            <span>Coeff of Var (CV)</span>
            <Sliders className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="mt-2">
            <div className="text-lg font-bold font-mono text-amber-400">
              {cv.toFixed(3)}
            </div>
            <div className="text-[10px] font-mono text-slate-500 mt-0.5 truncate">
              {cv < 0.15 ? 'Critical (CV < 0.15)' : cv < 0.35 ? 'Moderate Periodic' : 'Dispersed (Organic)'}
            </div>
          </div>
        </div>

        {/* Card 4: Periodicity Score */}
        <div className="bg-[#0f0f18] border border-slate-800/80 rounded-lg p-3 flex flex-col justify-between">
          <div className="flex items-center justify-between text-[10px] font-mono uppercase text-slate-400">
            <span>Periodicity Score</span>
            <Sparkles className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="mt-2">
            <div className="text-lg font-bold font-mono text-purple-400">
              {(periodicity * 100).toFixed(0)}%
            </div>
            <div className="text-[10px] font-mono text-slate-500 mt-0.5 truncate">
              Power = {periodicity.toFixed(2)} / 1.0
            </div>
          </div>
        </div>

        {/* Card 5: Connection Frequency */}
        <div className="bg-[#0f0f18] border border-slate-800/80 rounded-lg p-3 flex flex-col justify-between">
          <div className="flex items-center justify-between text-[10px] font-mono uppercase text-slate-400">
            <span>Conn Frequency</span>
            <Activity className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="mt-2">
            <div className="text-lg font-bold font-mono text-emerald-400">
              {frequencyHz.toFixed(3)} Hz
            </div>
            <div className="text-[10px] font-mono text-slate-500 mt-0.5 truncate">
              {(frequencyHz * 60).toFixed(1)} conn/min
            </div>
          </div>
        </div>

        {/* Card 6: Destination Concentration */}
        <div className="bg-[#0f0f18] border border-slate-800/80 rounded-lg p-3 flex flex-col justify-between">
          <div className="flex items-center justify-between text-[10px] font-mono uppercase text-slate-400">
            <span>Dst Concentration</span>
            <BarChart3 className="w-3.5 h-3.5 text-indigo-400" />
          </div>
          <div className="mt-2">
            <div className="text-lg font-bold font-mono text-indigo-400">
              {concentration.toFixed(2)}
            </div>
            <div className="text-[10px] font-mono text-slate-500 mt-0.5 truncate">
              {concentration > 0.85 ? 'Single C2 Node Pin' : 'Distributed'}
            </div>
          </div>
        </div>

        {/* Card 7: Packet-Size Consistency */}
        <div className="bg-[#0f0f18] border border-slate-800/80 rounded-lg p-3 flex flex-col justify-between">
          <div className="flex items-center justify-between text-[10px] font-mono uppercase text-slate-400">
            <span>Size Consistency</span>
            <Layers className="w-3.5 h-3.5 text-rose-400" />
          </div>
          <div className="mt-2">
            <div className="text-lg font-bold font-mono text-rose-400">
              {(consistency * 100).toFixed(0)}%
            </div>
            <div className="text-[10px] font-mono text-slate-500 mt-0.5 truncate">
              Mean: {activeCandidate?.packetSizeMean || 340}B
            </div>
          </div>
        </div>
      </div>

      {/* Middle Grid: Dossier + Scatter Clustering */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Selected Candidate Dossier */}
        <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3 border-b border-slate-800/80 pb-2">
              <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-purple-400" />
                Target Beacon Dossier
              </h3>
              <span
                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                  isBenign
                    ? 'bg-emerald-950/70 text-emerald-300 border border-emerald-800/50'
                    : severity === 'Critical'
                    ? 'bg-red-950/70 text-red-300 border border-red-800/50'
                    : severity === 'High'
                    ? 'bg-amber-950/70 text-amber-300 border border-amber-800/50'
                    : 'bg-blue-950/70 text-blue-300 border border-blue-800/50'
                }`}
              >
                {classification}
              </span>
            </div>

            {activeCandidate && (
              <div className="space-y-2.5 text-xs font-mono">
                <div className="bg-[#050508] p-2.5 rounded border border-slate-800">
                  <span className="text-slate-500 text-[9px] uppercase tracking-wider block">INTERNAL COMPROMISED HOST</span>
                  <div className="flex items-center justify-between mt-0.5">
                    <span className="text-slate-100 font-bold text-xs">{activeCandidate.sourceIp}</span>
                    <span className="text-slate-500 text-[10px]">
                      {activeCandidate.sourceIp === '10.0.4.118'
                        ? 'WS-092 (Workstation Finance)'
                        : activeCandidate.sourceIp === '10.0.6.72'
                        ? 'WS-044 (Engineering Endpoint)'
                        : activeCandidate.sourceIp === '10.0.8.204'
                        ? 'DEV-102 (Dev Server)'
                        : activeCandidate.sourceIp === '10.0.12.89'
                        ? 'SVR-018 (Internal DB Bridge)'
                        : 'Internal Monitored Node'}
                    </span>
                  </div>
                </div>

                <div className="bg-[#050508] p-2.5 rounded border border-slate-800">
                  <span className="text-slate-500 text-[9px] uppercase tracking-wider block">EXTERNAL C2 SOCKET / DOMAIN</span>
                  <div className="mt-0.5">
                    <span className="text-red-400 font-bold text-xs">
                      {activeCandidate.destinationC2 || `${activeCandidate.destinationIp}:${activeCandidate.destinationPort}`}
                    </span>
                    <span className="text-slate-400 text-[10px] block truncate mt-0.5">
                      {activeCandidate.c2Domain}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div className="bg-[#050508] p-2 rounded border border-slate-800">
                    <span className="text-slate-500 text-[9px] uppercase tracking-wider block">CONFIDENCE SCORE</span>
                    <span
                      className={`font-bold text-sm ${
                        isBenign
                          ? 'text-emerald-400'
                          : confidence >= 85
                          ? 'text-red-400'
                          : confidence >= 70
                          ? 'text-amber-400'
                          : 'text-blue-400'
                      }`}
                    >
                      {confidence}%
                    </span>
                  </div>
                  <div className="bg-[#050508] p-2 rounded border border-slate-800">
                    <span className="text-slate-500 text-[9px] uppercase tracking-wider block">OBSERVED CONNECTIONS</span>
                    <span className="text-slate-200 font-bold text-sm">
                      {activeCandidate.beaconCount || activeCandidate.connectionCount || 35} pulses
                    </span>
                  </div>
                </div>

                <div className="bg-[#050508] p-2.5 rounded border border-slate-800">
                  <span className="text-slate-500 text-[9px] uppercase tracking-wider block">BEHAVIORAL CORRELATION</span>
                  <span className="text-purple-300 font-semibold text-[11px] block mt-0.5">
                    {activeCandidate.knownMalwareFamily}
                  </span>
                  {activeCandidate.ja3Hash && (
                    <div className="text-[10px] text-slate-500 mt-1 flex items-center gap-1 truncate">
                      <Fingerprint className="w-3 h-3 text-purple-400 shrink-0" />
                      <span>JA3: {activeCandidate.ja3Hash.substring(0, 24)}...</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-slate-800/80 text-[10px] font-mono text-slate-500 mt-3 flex items-start gap-1.5">
            <Lock className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
            <span>
              <strong>Passive Invariant:</strong> Monitoring enclave contains zero transmit capability. Threat advisories are published out-of-band for SOC firewall/EDR intervention.
            </span>
          </div>
        </div>

        {/* Scatter Chart: Inter-Arrival Interval vs Payload Size */}
        <div className="lg:col-span-2 bg-[#0a0a12] border border-slate-800 rounded-lg p-4 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <div>
                <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                  <Activity className="w-3.5 h-3.5 text-purple-400" />
                  Connection Interval vs. Payload Size (Beacon Clustering)
                </h3>
                <p className="text-xs text-slate-500">
                  Tight clustering of uniform payloads across discrete time intervals reveals automated machine beacons.
                </p>
              </div>
              <div className="flex items-center gap-3 text-[10px] font-mono">
                <span className="flex items-center gap-1 text-red-400">
                  <span className="w-2 h-2 rounded-full bg-red-500" /> High-Conf C2
                </span>
                <span className="flex items-center gap-1 text-amber-400">
                  <span className="w-2 h-2 rounded-full bg-amber-500" /> Jittered / Suspicious
                </span>
                <span className="flex items-center gap-1 text-slate-500">
                  <span className="w-2 h-2 rounded-full bg-slate-600" /> Background Noise
                </span>
              </div>
            </div>

            <div className="h-60 w-full mt-2">
              <ResponsiveContainer width="100%" height="100%">
                <ScatterChart margin={{ top: 15, right: 20, bottom: 10, left: 10 }}>
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

          <div className="text-[10px] font-mono text-slate-500 border-t border-slate-800/80 pt-2 mt-2 flex items-center justify-between">
            <span>High-frequency clusters at bottom-left indicate fast beaconing; low-frequency clusters at bottom-right denote APT sleep profiles.</span>
            <span className="text-purple-400 font-bold">{scatterData.length} analyzed clusters</span>
          </div>
        </div>
      </div>

      {/* Beacon Timeline Visualization */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 shadow-sm">
        <div className="flex items-center justify-between mb-3 border-b border-slate-800/80 pb-2">
          <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <Clock className="w-4 h-4 text-blue-400" />
            Passive Pulse Timeline (Observed Callback Sequence)
          </h3>
          <span className="text-[10px] font-mono text-slate-400">
            Internal Target: <strong className="text-slate-200">{activeCandidate?.sourceIp}</strong> &rarr; C2 Listener:{' '}
            <strong className="text-red-400">{activeCandidate?.destinationC2 || activeCandidate?.destinationIp}</strong>
          </span>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2">
          {timelineEvents.map((evt, idx) => (
            <div
              key={idx}
              className="bg-[#050508] border border-slate-800/80 rounded p-2.5 flex flex-col justify-between font-mono"
            >
              <div className="flex items-center justify-between text-[10px] text-slate-500">
                <span>Pulse #{idx + 1}</span>
                <span className="text-slate-400">{evt.timestamp}</span>
              </div>
              <div className="my-1.5 flex items-baseline justify-between">
                <span className="text-sm font-bold text-blue-400">&Delta; {evt.deltaSeconds}s</span>
                <span className="text-[10px] text-purple-300 font-semibold">{evt.packetSize}B</span>
              </div>
              <div className="text-[9px] text-slate-500 flex items-center justify-between pt-1 border-t border-slate-800/60">
                <span>Jitter:</span>
                <span className={Math.abs(evt.jitterDelta) < 1 ? 'text-emerald-400' : 'text-amber-400'}>
                  {evt.jitterDelta >= 0 ? `+${evt.jitterDelta}s` : `${evt.jitterDelta}s`}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Expandable Detection Evidence Panel: "Why was this detected?" */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 shadow-sm">
        <button
          onClick={() => setShowEvidenceDetails(!showEvidenceDetails)}
          className="w-full flex items-center justify-between text-left cursor-pointer"
        >
          <div className="flex items-center gap-2">
            <Info className="w-4 h-4 text-purple-400" />
            <h3 className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
              Detection Evidence & Signal Attribution (&quot;Why was this detected?&quot;)
            </h3>
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <span>{showEvidenceDetails ? 'Collapse Analysis' : 'Expand Detailed Signals'}</span>
            {showEvidenceDetails ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </button>

        {showEvidenceDetails && (
          <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-4">
            {/* Contributing Signals Table */}
            <div>
              <h4 className="text-[11px] font-mono font-bold text-slate-300 uppercase tracking-wider mb-2">
                Weighted Contributing Behavioral Signals
              </h4>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#050508] text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
                    <tr>
                      <th className="py-2 px-3">Signal Name</th>
                      <th className="py-2 px-3">Observed Telemetry</th>
                      <th className="py-2 px-3">Engine Weight</th>
                      <th className="py-2 px-3">Calculated Contribution</th>
                      <th className="py-2 px-3">Passive Forensic Evaluation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-[11px]">
                    <tr className="hover:bg-white/5">
                      <td className="py-2.5 px-3 font-bold text-slate-200">Periodicity Score</td>
                      <td className="py-2.5 px-3 text-purple-400 font-semibold">{periodicity.toFixed(3)}</td>
                      <td className="py-2.5 px-3 text-slate-400">25%</td>
                      <td className="py-2.5 px-3 text-emerald-400 font-bold">
                        {activeCandidate?.scoreBreakdown?.periodicityContribution ?? (periodicity * 25).toFixed(1)} pts
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">
                        Discrete Fourier Transform confirms sharp spectral impulse matching machine sleep timer.
                      </td>
                    </tr>
                    <tr className="hover:bg-white/5">
                      <td className="py-2.5 px-3 font-bold text-slate-200">IAT Regularity</td>
                      <td className="py-2.5 px-3 text-blue-400 font-semibold">CV = {cv.toFixed(3)} (Mean: {meanIAT.toFixed(1)}s)</td>
                      <td className="py-2.5 px-3 text-slate-400">20%</td>
                      <td className="py-2.5 px-3 text-emerald-400 font-bold">
                        {activeCandidate?.scoreBreakdown?.iatRegularityContribution ?? ((1 - Math.min(1, cv)) * 20).toFixed(1)} pts
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">
                        Extremely low inter-arrival variation rejects organic human browsing behaviors.
                      </td>
                    </tr>
                    <tr className="hover:bg-white/5">
                      <td className="py-2.5 px-3 font-bold text-slate-200">Destination Concentration</td>
                      <td className="py-2.5 px-3 text-indigo-400 font-semibold">{concentration.toFixed(2)}</td>
                      <td className="py-2.5 px-3 text-slate-400">20%</td>
                      <td className="py-2.5 px-3 text-emerald-400 font-bold">
                        {activeCandidate?.scoreBreakdown?.destinationRepetitionContribution ?? (concentration * 20).toFixed(1)} pts
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">
                        Target endpoint exclusively returns to the exact same external C2 IP/socket.
                      </td>
                    </tr>
                    <tr className="hover:bg-white/5">
                      <td className="py-2.5 px-3 font-bold text-slate-200">Connection Frequency</td>
                      <td className="py-2.5 px-3 text-emerald-400 font-semibold">{frequencyHz.toFixed(3)} Hz</td>
                      <td className="py-2.5 px-3 text-slate-400">15%</td>
                      <td className="py-2.5 px-3 text-emerald-400 font-bold">
                        {activeCandidate?.scoreBreakdown?.frequencyContribution ?? 14.5} pts
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">
                        Cadence matches known programmatic polling ranges (0.005 Hz - 0.500 Hz).
                      </td>
                    </tr>
                    <tr className="hover:bg-white/5">
                      <td className="py-2.5 px-3 font-bold text-slate-200">Packet-Size Consistency</td>
                      <td className="py-2.5 px-3 text-rose-400 font-semibold">{(consistency * 100).toFixed(0)}% (σ = ±{activeCandidate?.packetSizeStdDev ?? 0}B)</td>
                      <td className="py-2.5 px-3 text-slate-400">20%</td>
                      <td className="py-2.5 px-3 text-emerald-400 font-bold">
                        {activeCandidate?.scoreBreakdown?.packetSizeContribution ?? (consistency * 20).toFixed(1)} pts
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">
                        Homogeneous payload lengths confirm repetitive heartbeat frames rather than dynamic web payloads.
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            {/* Evidence bullet points */}
            <div className="bg-[#050508] p-3 rounded border border-slate-800/80">
              <h4 className="text-[11px] font-mono font-bold text-slate-300 uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
                Synthesized Forensic Observations
              </h4>
              <ul className="space-y-1 text-xs font-mono text-slate-400">
                {activeCandidate?.evidence && activeCandidate.evidence.length > 0 ? (
                  activeCandidate.evidence.map((ev, i) => (
                    <li key={i} className="flex items-start gap-1.5">
                      <span className="text-purple-400 mt-0.5">&bull;</span>
                      <span>{ev}</span>
                    </li>
                  ))
                ) : (
                  <>
                    <li className="flex items-start gap-1.5">
                      <span className="text-purple-400 mt-0.5">&bull;</span>
                      <span>Observed mean inter-arrival time: {meanIAT.toFixed(1)}s with low jitter ({activeCandidate?.jitterPercentage ?? 2}%).</span>
                    </li>
                    <li className="flex items-start gap-1.5">
                      <span className="text-purple-400 mt-0.5">&bull;</span>
                      <span>Discrete Fourier Transform extracted periodicity score of {periodicity.toFixed(2)}.</span>
                    </li>
                    <li className="flex items-start gap-1.5">
                      <span className="text-purple-400 mt-0.5">&bull;</span>
                      <span>Consistent outbound packet length across consecutive sessions.</span>
                    </li>
                    <li className="flex items-start gap-1.5">
                      <span className="text-purple-400 mt-0.5">&bull;</span>
                      <span>Strict unidirectional observation: Zero reverse packets or MITM handshakes executed by sensor enclave.</span>
                    </li>
                  </>
                )}
              </ul>
            </div>
          </div>
        )}
      </div>

      {/* Suspected C2 Beacons Table (Active Candidate Selection) */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Radio className="w-3.5 h-3.5 text-purple-400" />
              Active Passive C2 Candidates &amp; Conversation Clusters
            </h3>
            <p className="text-xs text-slate-500">
              Select any conversation cluster to inspect its specific behavioral metrics, timeline, and signal attribution.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {candidateList.length} clusters tracked
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-[#050508] text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Internal Host</th>
                <th className="py-2.5 px-3">External Destination</th>
                <th className="py-2.5 px-3">Domain / Service</th>
                <th className="py-2.5 px-3">Mean IAT</th>
                <th className="py-2.5 px-3">Std Dev (IAT)</th>
                <th className="py-2.5 px-3">CV</th>
                <th className="py-2.5 px-3">Periodicity</th>
                <th className="py-2.5 px-3">Classification</th>
                <th className="py-2.5 px-3">Confidence</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-[11px]">
              {candidateList.map((cand, idx) => {
                const isSelected = cand.id === activeCandidate?.id;
                const candMean = cand.meanIAT ?? cand.periodicitySeconds ?? 30.0;
                const candStdDev = cand.stdDevIAT ?? (candMean * ((cand.jitterPercentage ?? 3) / 100));
                const candCv = cand.coefficientOfVariation ?? (candMean > 0 ? candStdDev / candMean : 0);
                const candPeriodicity = cand.periodicityScore ?? cand.fftPeakPower ?? 0.94;
                const candConf = cand.c2Confidence ?? cand.confidenceScore ?? 90;
                const isBen = cand.isBenignPeriodicService || cand.classification === 'Benign Periodic Traffic';

                return (
                  <tr
                    key={`${cand.id}-${idx}`}
                    onClick={() => setSelectedCandidateId(cand.id)}
                    className={`hover:bg-white/5 transition cursor-pointer ${
                      isSelected ? 'bg-purple-950/30 text-purple-200' : 'text-slate-300'
                    }`}
                  >
                    <td className="py-2.5 px-3 font-bold text-slate-200">{cand.sourceIp}</td>
                    <td className="py-2.5 px-3 text-red-400">
                      {cand.destinationC2 || `${cand.destinationIp}:${cand.destinationPort}`}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 truncate max-w-xs font-mono text-[11px]">
                      {cand.c2Domain}
                    </td>
                    <td className="py-2.5 px-3 text-blue-400 font-bold">
                      {candMean > 0 ? `${candMean.toFixed(1)}s` : 'N/A'}
                    </td>
                    <td className="py-2.5 px-3 text-cyan-400">
                      &plusmn;{candStdDev.toFixed(2)}s
                    </td>
                    <td className="py-2.5 px-3 text-amber-400 font-mono">
                      {candCv.toFixed(3)}
                    </td>
                    <td className="py-2.5 px-3 text-purple-400 font-bold">
                      {(candPeriodicity * 100).toFixed(0)}%
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                          isBen
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/50'
                            : candConf >= 85
                            ? 'bg-red-950 text-red-300 border border-red-800/50'
                            : 'bg-amber-950 text-amber-300 border border-amber-800/50'
                        }`}
                      >
                        {cand.classification || (candConf >= 80 ? 'High-Confidence C2' : 'Suspicious Periodic')}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-bold text-green-400">
                      {candConf}%
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedCandidateId(cand.id);
                        }}
                        className={`px-2 py-1 rounded text-[10px] font-mono transition border ${
                          isSelected
                            ? 'bg-purple-900/60 text-purple-200 border-purple-700'
                            : 'bg-[#11111d] text-blue-400 hover:bg-slate-800 border-slate-700'
                        }`}
                      >
                        {isSelected ? 'Inspecting' : 'Inspect'}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
