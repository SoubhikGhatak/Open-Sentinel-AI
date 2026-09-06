import React, { useState } from 'react';
import {
  Zap,
  ShieldAlert,
  AlertTriangle,
  Layers,
  Copy,
  Check,
  Download,
  Info,
  ExternalLink,
  Target
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell
} from 'recharts';
import { SimulationScenario } from '../../types';
import { FullAnalysisPipelineResult } from '../../detection/engine';

interface DDoSViewProps {
  activeScenario: SimulationScenario;
  pipeline?: FullAnalysisPipelineResult;
}

export const DDoSView: React.FC<DDoSViewProps> = ({ activeScenario, pipeline }) => {
  const [copiedRule, setCopiedRule] = useState<boolean>(false);

  const isSynAttack = activeScenario.id === 'syn-flood' || pipeline?.ddos?.threatType === 'SYN Flood';
  const isUdpAmp = activeScenario.id === 'udp-amplification' || pipeline?.ddos?.threatType === 'UDP Reflection/Amplification';
  const isSpoofed = activeScenario.id === 'spoofed-source' || pipeline?.ddos?.threatType === 'Spoofed Source Flood';
  const isUdpFlood = activeScenario.id === 'udp-flood' || pipeline?.ddos?.threatType === 'UDP Flood';

  const ddosFeats = pipeline?.features?.ddos;
  const generalFeats = pipeline?.features?.general;
  const totalPPS = pipeline?.telemetry?.packetsPerSecond || (activeScenario.activeThreat ? 280000 : 45000);
  const totalBPS = pipeline?.telemetry?.bytesPerSecond || (totalPPS * 680);

  const ddosMetrics = {
    synFloodIntensity: ddosFeats ? Math.round(Math.min(100, (ddosFeats.synPacketRate / 5000) * 100)) : (isSynAttack ? 94 : 6),
    udpFloodIntensity: generalFeats ? Math.round(generalFeats.protocolPercentages.UDP) : (isUdpAmp ? 92 : isSpoofed ? 88 : isUdpFlood ? 96 : 8),
    amplificationFactor: isUdpAmp && generalFeats ? Number(Math.max(1.0, generalFeats.averagePacketSize / 64).toFixed(1)) : (isUdpAmp ? 55.4 : 1.0),
    spoofedEntropyScore: ddosFeats ? ddosFeats.sourceIPEntropy : (isSpoofed ? 7.84 : isSynAttack ? 6.95 : 3.72),
    synToAckRatio: ddosFeats ? ddosFeats.synToAckRatio : (isSynAttack ? 48.6 : 1.02),
    halfOpenSynCount: ddosFeats ? ddosFeats.halfOpenEstimate : (isSynAttack ? 428000 : 1240),
    topTargetVips: ddosFeats && ddosFeats.targetVIPConcentration.length > 0
      ? ddosFeats.targetVIPConcentration.map((t) => ({
          ip: `${t.ip}:${isSynAttack ? 443 : isUdpAmp ? 123 : 8080}`,
          name: t.ip === '192.168.10.45' ? 'Web Application VIP' : t.ip === '192.168.20.10' ? 'Core DB Gateway' : t.ip === '192.168.10.1' ? 'API Gateway' : 'Monitored Service',
          pps: Math.round(totalPPS * (t.percentage / 100)),
          risk: t.percentage > 40 && activeScenario.activeThreat ? 'CRITICAL' : t.percentage > 25 ? 'HIGH' : 'NOMINAL'
        }))
      : [
          { ip: '192.168.10.45:443', name: 'Web Application VIP', pps: isSynAttack ? 385000 : 18000, risk: isSynAttack ? 'CRITICAL' : 'NOMINAL' },
          { ip: '192.168.20.10:5432', name: 'Core DB Gateway', pps: isUdpAmp ? 290000 : 12000, risk: isUdpAmp ? 'CRITICAL' : 'NOMINAL' },
          { ip: '192.168.10.1:8080', name: 'API Gateway', pps: isSpoofed ? 175000 : 11000, risk: isSpoofed ? 'HIGH' : 'NOMINAL' },
          { ip: '192.168.10.50:53', name: 'Internal DNS Primary', pps: 9200, risk: 'NOMINAL' }
        ],
    ampVectors: [
      { vector: 'NTP Monlist (Port 123)', factor: 55.4, pps: generalFeats?.destinationPortDistribution[123] || (isUdpAmp ? 180000 : 340), color: '#ec4899' },
      { vector: 'DNS ANY Query (Port 53)', factor: 28.0, pps: generalFeats?.destinationPortDistribution[53] || (isUdpAmp ? 72000 : 1200), color: '#10b981' },
      { vector: 'Memcached Get (11211)', factor: 4000.0, pps: generalFeats?.destinationPortDistribution[11211] || (isUdpAmp ? 41000 : 40), color: '#f59e0b' },
      { vector: 'SSDP Discover (1900)', factor: 30.8, pps: generalFeats?.destinationPortDistribution[1900] || (isUdpAmp ? 17000 : 110), color: '#38bdf8' }
    ]
  };

  const primaryVictim = ddosMetrics.topTargetVips?.[0]?.ip?.split(':')?.[0] || '192.168.10.45';

  const sampleBgpFlowspec = pipeline?.ddos?.mitigationAdvisory || `flowspec route {
  match {
    destination ${primaryVictim}/32;
    protocol ${isSynAttack ? 'tcp' : 'udp'};
    ${isSynAttack ? 'tcp-flags "syn & !ack";\n    packet-length < 80;' : 'destination-port 123;\n    packet-length > 400;'}
  }
  then {
    rate-limit 50000;
    action sample;
  }
}`;

  const copyRuleToClipboard = () => {
    navigator.clipboard.writeText(sampleBgpFlowspec);
    setCopiedRule(true);
    setTimeout(() => setCopiedRule(false), 2000);
  };

  return (
    <div id="ddos-detection-view" className="space-y-4 select-none">
      {/* View Header */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-xl">
        <div>
          <h2 className="text-sm font-bold text-slate-100 uppercase tracking-widest flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-500" />
            Specialized DDoS Vector Detection Engine
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Real-time passive identification of Layer 3/4 volumetric, amplification, and resource exhaustion attacks.
          </p>
        </div>

        <div className="bg-[#050508] px-3 py-1.5 rounded border border-slate-800 text-xs flex items-center gap-2 font-mono">
          <span className="text-slate-500 text-[10px] uppercase tracking-wider">Attack Vector:</span>
          <span className={`font-bold text-xs uppercase ${activeScenario.activeThreat ? 'text-red-400' : 'text-green-400'}`}>
            {activeScenario.activeThreat || 'No Active DDoS Flood'}
          </span>
        </div>
      </div>

      {/* 4 Vector Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* 1. SYN Flood */}
        <div className={`p-4 rounded-lg border transition ${
          isSynAttack ? 'bg-[#11111d] border-red-500/50 shadow-glow-red' : 'bg-[#11111d] border-slate-800'
        }`}>
          <div className="flex items-center justify-between text-xs mb-1">
            <span className="font-mono font-bold text-slate-300 uppercase text-[10px] tracking-wider">1. SYN Flood</span>
            <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${
              isSynAttack ? 'bg-red-500 text-white' : 'bg-[#050508] text-slate-500 border border-slate-800'
            }`}>
              {isSynAttack ? 'ACTIVE SURGE' : 'NOMINAL'}
            </span>
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-2">
            {ddosMetrics.synToAckRatio}:1 <span className="text-xs font-normal text-slate-500 font-sans">SYN/ACK Ratio</span>
          </div>
          <p className="text-xs text-slate-500 mt-2">
            Half-open backlog exhaustion. SYN flood algorithm monitors incomplete TCP 3-way handshakes passively.
          </p>
          <div className="mt-3 pt-2 border-t border-slate-800 text-[10px] font-mono flex justify-between text-slate-400">
            <span>Half-Open Count:</span>
            <span className={isSynAttack ? 'text-red-400 font-bold' : 'text-slate-300'}>
              {ddosMetrics.halfOpenSynCount.toLocaleString()}
            </span>
          </div>
        </div>

        {/* 2. UDP Flood */}
        <div className={`p-4 rounded-lg border transition ${
          isUdpAmp || isSpoofed ? 'bg-[#11111d] border-amber-500/50' : 'bg-[#11111d] border-slate-800'
        }`}>
          <div className="flex items-center justify-between text-xs mb-1">
            <span className="font-mono font-bold text-slate-300 uppercase text-[10px] tracking-wider">2. UDP Flood</span>
            <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${
              isUdpAmp || isSpoofed ? 'bg-amber-500 text-slate-950 font-bold' : 'bg-[#050508] text-slate-500 border border-slate-800'
            }`}>
              {isUdpAmp || isSpoofed ? 'ELEVATED' : 'NOMINAL'}
            </span>
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-2">
            {ddosMetrics.udpFloodIntensity}% <span className="text-xs font-normal text-slate-500 font-sans">Flood Index</span>
          </div>
          <p className="text-xs text-slate-500 mt-2">
            High-volume stateless datagrams directed at non-listening high ports to exhaust network link capacity.
          </p>
          <div className="mt-3 pt-2 border-t border-slate-800 text-[10px] font-mono flex justify-between text-slate-400">
            <span>Bandwidth Consumption:</span>
            <span className={isUdpAmp || isSpoofed ? 'text-amber-400 font-bold' : 'text-slate-300'}>
              {isUdpAmp ? '18.4 Gbps' : isSpoofed ? '6.1 Gbps' : '240 Mbps'}
            </span>
          </div>
        </div>

        {/* 3. UDP Reflection/Amplification */}
        <div className={`p-4 rounded-lg border transition ${
          isUdpAmp ? 'bg-[#11111d] border-red-500/50 shadow-glow-red' : 'bg-[#11111d] border-slate-800'
        }`}>
          <div className="flex items-center justify-between text-xs mb-1">
            <span className="font-mono font-bold text-slate-300 uppercase text-[10px] tracking-wider">3. UDP Amplification</span>
            <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${
              isUdpAmp ? 'bg-red-500 text-white' : 'bg-[#050508] text-slate-500 border border-slate-800'
            }`}>
              {isUdpAmp ? 'AMPLIFY DETECTED' : 'NOMINAL'}
            </span>
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-2">
            {ddosMetrics.amplificationFactor}x <span className="text-xs font-normal text-slate-500 font-sans">Multiplier</span>
          </div>
          <p className="text-xs text-slate-500 mt-2">
            Exploits vulnerable UDP daemons (NTP monlist, DNS ANY, Memcached) with spoofed victim return IP.
          </p>
          <div className="mt-3 pt-2 border-t border-slate-800 text-[10px] font-mono flex justify-between text-slate-400">
            <span>Primary Vector:</span>
            <span className={isUdpAmp ? 'text-red-400 font-bold' : 'text-slate-300'}>
              {isUdpAmp ? 'NTP (Port 123)' : 'None'}
            </span>
          </div>
        </div>

        {/* 4. Spoofed-Source Flood */}
        <div className={`p-4 rounded-lg border transition ${
          isSpoofed ? 'bg-[#11111d] border-purple-500/50' : 'bg-[#11111d] border-slate-800'
        }`}>
          <div className="flex items-center justify-between text-xs mb-1">
            <span className="font-mono font-bold text-slate-300 uppercase text-[10px] tracking-wider">4. Spoofed Source</span>
            <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${
              isSpoofed ? 'bg-purple-600 text-white' : 'bg-[#050508] text-slate-500 border border-slate-800'
            }`}>
              {isSpoofed ? 'ANOMALOUS ENTROPY' : 'NOMINAL'}
            </span>
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-2">
            H(X) = {ddosMetrics.spoofedEntropyScore} <span className="text-xs font-normal text-slate-500 font-sans">bits</span>
          </div>
          <p className="text-xs text-slate-500 mt-2">
            High-entropy source IP dispersion with martian/bogon space injection to evade static IP reputation filters.
          </p>
          <div className="mt-3 pt-2 border-t border-slate-800 text-[10px] font-mono flex justify-between text-slate-400">
            <span>Bogon Space:</span>
            <span className={isSpoofed ? 'text-purple-400 font-bold' : 'text-slate-300'}>
              {isSpoofed ? 'CONFIRMED (100.64.0.0/10)' : '0 Detected'}
            </span>
          </div>
        </div>
      </div>

      {/* Amplification Vectors & Target VIP Concentration */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Reflection & Amplification Vectors Chart */}
        <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4">
          <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2 mb-1">
            <Layers className="w-3.5 h-3.5 text-blue-400" />
            Reflection / Amplification Vector Rates
          </h3>
          <p className="text-xs text-slate-500 mb-3">
            Inbound packet volume across known high-gain UDP reflection services.
          </p>

          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={ddosMetrics.ampVectors} margin={{ top: 10, right: 10, left: -10, bottom: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1b1b26" vertical={false} />
                <XAxis dataKey="vector" stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} angle={-10} textAnchor="end" />
                <YAxis stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} tickFormatter={(val) => `${(val / 1000).toFixed(0)}k`} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0a0a12', borderColor: '#334155', borderRadius: '6px', fontSize: '11px', fontFamily: 'monospace' }}
                  formatter={(val: any) => [`${Number(val).toLocaleString()} PPS`, 'Throughput']}
                />
                <Bar dataKey="pps" radius={[2, 2, 0, 0]}>
                  {ddosMetrics.ampVectors.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Target VIP Destination Concentration */}
        <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2 mb-1">
              <Target className="w-3.5 h-3.5 text-red-400" />
              Targeted Internal VIP Infrastructure
            </h3>
            <p className="text-xs text-slate-500 mb-3">
              Distribution of incoming packet density across protected servers.
            </p>

            <div className="space-y-3">
              {ddosMetrics.topTargetVips.map((vip) => (
                <div key={vip.ip} className="bg-[#11111d] p-3 rounded border border-slate-800">
                  <div className="flex items-center justify-between text-xs mb-1">
                    <div>
                      <span className="font-bold font-mono text-blue-400">{vip.ip}</span>
                      <span className="text-slate-500 ml-2 font-mono text-[11px]">({vip.name})</span>
                    </div>
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold font-mono uppercase tracking-wider ${
                      vip.risk === 'CRITICAL' ? 'bg-red-500 text-white' :
                      vip.risk === 'HIGH' ? 'bg-amber-500 text-slate-950' :
                      'bg-[#050508] text-slate-400 border border-slate-800'
                    }`}>
                      {vip.risk}
                    </span>
                  </div>
                  <div className="flex justify-between text-[10px] text-slate-400 mb-1 font-mono">
                    <span>Rate: {vip.pps.toLocaleString()} pps</span>
                    <span>Load: {((vip.pps / 450000) * 100).toFixed(0)}% Capacity</span>
                  </div>
                  <div className="h-1.5 bg-[#050508] rounded-full overflow-hidden border border-slate-800">
                    <div
                      className={`h-full transition-all duration-500 ${vip.risk === 'CRITICAL' ? 'bg-red-500' : vip.risk === 'HIGH' ? 'bg-amber-500' : 'bg-blue-500'}`}
                      style={{ width: `${Math.min(100, (vip.pps / 400000) * 100)}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Passive Mitigation Advisory (Respecting One-Way Constraint) */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 shadow-sm">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-3">
          <div>
            <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-3.5 h-3.5 text-blue-400" />
              Passive Mitigation Advisory (Out-of-Band BGP Flowspec Generator)
            </h3>
            <p className="text-xs text-slate-500">
              <strong className="text-amber-400">ARCHITECTURAL SAFETY INVARIANT:</strong> The passive enclave cannot inject packets into the production network. Below is an exportable advisory rule for upstream edge routers.
            </p>
          </div>

          <button
            onClick={copyRuleToClipboard}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded bg-[#11111d] hover:bg-slate-800 text-blue-400 border border-slate-700 font-mono text-[10px] font-bold uppercase tracking-wider transition cursor-pointer shrink-0"
          >
            {copiedRule ? (
              <>
                <Check className="w-3.5 h-3.5 text-green-400" />
                <span>Copied to Clipboard</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                <span>Copy BGP Rule</span>
              </>
            )}
          </button>
        </div>

        <pre className="bg-[#050508] p-3 rounded border border-slate-800 text-xs font-mono text-blue-300 overflow-x-auto">
          {sampleBgpFlowspec}
        </pre>
      </div>
    </div>
  );
};
