import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  Cpu,
  Lock,
  ArrowUpRight,
  TrendingUp,
  Layers,
  Clock,
  Radio,
  ExternalLink
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend
} from 'recharts';
import {
  TelemetryMetrics,
  TrafficTimePoint,
  SecurityAlert,
  SimulationScenario
} from '../../types';
import { FullAnalysisPipelineResult } from '../../detection/engine';

interface DashboardViewProps {
  telemetry: TelemetryMetrics;
  timeline: TrafficTimePoint[];
  alerts: SecurityAlert[];
  activeScenario: SimulationScenario;
  pipeline?: FullAnalysisPipelineResult;
  onNavigateTab: (tab: any) => void;
  onSelectAlert: (alert: SecurityAlert) => void;
}

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: '#38bdf8', // sky-400
  UDP: '#f59e0b', // amber-500
  TLS: '#a855f7', // purple-500
  DNS: '#10b981', // emerald-500
  NTP: '#ec4899', // pink-500
  ICMP: '#64748b' // slate-500
};

export const DashboardView: React.FC<DashboardViewProps> = ({
  telemetry,
  timeline,
  alerts,
  activeScenario,
  pipeline,
  onNavigateTab,
  onSelectAlert
}) => {
  // Protocol breakdown calculation from real simulation features
  const proto = pipeline?.features?.general?.protocolPercentages || {
    TCP: 65.0,
    UDP: 22.0,
    TLS: 8.0,
    DNS: 3.0,
    NTP: 1.0,
    ICMP: 1.0,
    SSDP: 0.0,
    OTHER: 0.0
  };

  const totalPPS = telemetry.packetsPerSecond || 1;

  const protocolData = [
    { name: 'TCP (Streams)', value: Math.round(totalPPS * (proto.TCP / 100)), percentage: proto.TCP, color: PROTOCOL_COLORS.TCP },
    { name: 'UDP (Datagrams)', value: Math.round(totalPPS * (proto.UDP / 100)), percentage: proto.UDP, color: PROTOCOL_COLORS.UDP },
    { name: 'DNS (Queries)', value: Math.round(totalPPS * (proto.DNS / 100)), percentage: proto.DNS, color: PROTOCOL_COLORS.DNS },
    { name: 'TLS (Encrypted)', value: Math.round(totalPPS * (proto.TLS / 100)), percentage: proto.TLS, color: PROTOCOL_COLORS.TLS },
    { name: 'NTP (Time Sync)', value: Math.round(totalPPS * (proto.NTP / 100)), percentage: proto.NTP, color: PROTOCOL_COLORS.NTP },
    { name: 'ICMP / Other', value: Math.round(totalPPS * (((proto.ICMP || 0) + (proto.SSDP || 0) + (proto.OTHER || 0)) / 100)), percentage: Number(((proto.ICMP || 0) + (proto.SSDP || 0) + (proto.OTHER || 0)).toFixed(1)), color: PROTOCOL_COLORS.ICMP }
  ].filter((p) => p.percentage > 0 || p.value > 0);

  // Severity counts
  const severityCounts = {
    Critical: alerts.filter((a) => a.severity === 'Critical').length,
    High: alerts.filter((a) => a.severity === 'High').length,
    Medium: alerts.filter((a) => a.severity === 'Medium').length,
    Low: alerts.filter((a) => a.severity === 'Low').length
  };

  const formatBps = (bps: number) => {
    if (bps >= 1e9) return `${(bps / 1e9).toFixed(2)} Gbps`;
    if (bps >= 1e6) return `${(bps / 1e6).toFixed(2)} Mbps`;
    if (bps >= 1e3) return `${(bps / 1e3).toFixed(2)} Kbps`;
    return `${bps} bps`;
  };

  const formatNumber = (num: number) => {
    return new Intl.NumberFormat().format(num);
  };

  return (
    <div id="dashboard-view" className="space-y-4 select-none">
      {/* Primary Status Banner */}
      <div className="bg-[#0a0a12] border border-slate-800/80 rounded-lg p-4 shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-lg bg-[#050508] border border-slate-800 flex items-center justify-center text-blue-400 shrink-0 shadow-glow-blue">
            <Lock className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] uppercase font-mono-code font-bold tracking-widest text-slate-500">Monitoring Mode:</span>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider bg-green-500/10 text-green-400 border border-green-500/20 flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
                STRICT UNIDIRECTIONAL PASSIVE ENCLAVE
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1">
              Fiber Optical Data Diode guarantees <span className="font-semibold text-green-400">0 egress packets</span> toward monitored fabrics. Hardware air-gap in full effect.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs w-full md:w-auto justify-between md:justify-end border-t md:border-t-0 pt-2 md:pt-0 border-slate-800">
          <div className="bg-[#050508] px-3 py-1.5 rounded border border-slate-800 text-center">
            <div className="text-[9px] uppercase font-mono text-slate-500 tracking-wider">Ingress Latency</div>
            <div className="font-mono-code font-bold text-blue-400 text-sm">{telemetry.pipelineLatencyMs} ms</div>
          </div>
          <div className="bg-[#050508] px-3 py-1.5 rounded border border-slate-800 text-center" title="Ensemble statistical & behavioral detection active. Python ML inference socket ready.">
            <div className="text-[9px] uppercase font-mono text-slate-500 tracking-wider">Detection Engine</div>
            <div className="font-mono-code font-bold text-purple-400 text-xs">Statistical Ensemble</div>
          </div>
          <div className="bg-[#050508] px-3 py-1.5 rounded border border-slate-800 text-center">
            <div className="text-[9px] uppercase font-mono text-slate-500 tracking-wider">Reverse Tx Egress</div>
            <div className="font-mono-code font-bold text-green-400 text-sm">0 PKTS (INVARIANT)</div>
          </div>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Packets per second */}
        <div className="bg-[#11111d] border border-slate-800 rounded-lg p-4 flex flex-col justify-center">
          <div className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mb-1 flex items-center justify-between">
            <span>PACKETS / SEC</span>
            <Activity className="w-3 h-3 text-blue-400" />
          </div>
          <div className="text-2xl font-mono text-white font-bold">
            {formatNumber(telemetry.packetsPerSecond)}
          </div>
          <div className="text-xs text-blue-400 font-mono mt-1 flex items-center gap-1">
            <TrendingUp className="w-3 h-3" />
            <span>{(telemetry.packetsPerSecond / 1000).toFixed(1)}k PPS</span>
          </div>
        </div>

        {/* Throughput */}
        <div className="bg-[#11111d] border border-slate-800 rounded-lg p-4 flex flex-col justify-center">
          <div className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mb-1 flex items-center justify-between">
            <span>BANDWIDTH</span>
            <ArrowUpRight className="w-3 h-3 text-blue-400" />
          </div>
          <div className="text-2xl font-mono text-white font-bold">
            {formatBps(telemetry.bytesPerSecond)}
          </div>
          <div className="text-xs text-slate-400 font-mono mt-1">
            Total: {(telemetry.totalBytes / 1e12).toFixed(2)} TB
          </div>
        </div>

        {/* Active Threats (Left border accent from theme) */}
        <div className="bg-[#11111d] border border-slate-800 border-l-red-500/70 border-l-4 rounded-lg p-4 flex flex-col justify-center">
          <div className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mb-1 flex items-center justify-between">
            <span>ACTIVE THREATS</span>
            <ShieldAlert className="w-3 h-3 text-red-500" />
          </div>
          <div className="text-2xl font-mono text-red-500 font-bold">
            {telemetry.activeThreatsCount}
          </div>
          <div className="text-xs text-red-400 font-mono mt-1 truncate">
            {activeScenario?.activeThreat ? activeScenario.activeThreat.split(' ')[0] : 'Normal Flow'}
          </div>
        </div>

        {/* Critical Alerts */}
        <div className="bg-[#11111d] border border-slate-800 border-l-amber-500/70 border-l-4 rounded-lg p-4 flex flex-col justify-center">
          <div className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mb-1 flex items-center justify-between">
            <span>CRITICAL ALERTS</span>
            <AlertTriangle className="w-3 h-3 text-amber-400" />
          </div>
          <div className="text-2xl font-mono text-amber-400 font-bold">
            {telemetry.criticalAlertsCount}
          </div>
          <div className="text-xs text-slate-400 font-mono mt-1">
            Pending Triage
          </div>
        </div>

        {/* AI Confidence */}
        <div className="bg-[#11111d] border border-slate-800 rounded-lg p-4 flex flex-col justify-center">
          <div className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mb-1 flex items-center justify-between">
            <span>AI CONFIDENCE</span>
            <Cpu className="w-3 h-3 text-purple-400" />
          </div>
          <div className="text-2xl font-mono text-purple-400 font-bold">
            {telemetry.averageAiConfidence}%
          </div>
          <div className="text-xs text-green-400 font-mono mt-1">
            Ensemble Index
          </div>
        </div>

        {/* Source IP Entropy */}
        <div className="bg-[#11111d] border border-slate-800 rounded-lg p-4 flex flex-col justify-center">
          <div className="text-[10px] text-slate-500 uppercase font-bold tracking-widest mb-1 flex items-center justify-between">
            <span>IP ENTROPY</span>
            <Layers className="w-3 h-3 text-blue-400" />
          </div>
          <div className="text-2xl font-mono text-white font-bold">
            {telemetry.sourceIPEntropy} <span className="text-xs text-slate-500 font-normal">/ 8</span>
          </div>
          <div className="text-xs text-blue-400 font-mono mt-1">
            {telemetry.sourceIPEntropy > 6.5 ? 'Spoofed Dispersion' : 'Normal Dispersion'}
          </div>
        </div>
      </div>

      {/* Main Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Real-time Traffic Timeline */}
        <div className="lg:col-span-2 bg-[#0a0a12] border border-slate-800 rounded-lg p-5 flex flex-col shadow-sm">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 mb-3">
            <div>
              <h3 className="text-xs sm:text-sm font-bold uppercase tracking-widest text-slate-400 flex items-center gap-2">
                <Activity className="w-4 h-4 text-blue-500" />
                Network Ingress Anomaly Timeline
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Passive multi-protocol telemetry and packet flux across physical optical receiver.
              </p>
            </div>
            <div className="flex items-center gap-3 text-[10px] font-mono">
              <span className="flex items-center gap-1 text-blue-400">
                <span className="w-2 h-2 rounded-sm bg-blue-500" /> TCP
              </span>
              <span className="flex items-center gap-1 text-amber-400">
                <span className="w-2 h-2 rounded-sm bg-amber-500" /> UDP
              </span>
              <span className="flex items-center gap-1 text-slate-400">
                <span className="w-2 h-2 rounded-sm bg-slate-600" /> ICMP/Other
              </span>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeline} margin={{ top: 10, right: 10, left: -15, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorTcp" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#3b82f6" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorUdp" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorOther" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#64748b" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#64748b" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="time" stroke="#475569" tick={{ fontSize: 10, fontFamily: 'monospace' }} />
                <YAxis stroke="#475569" tick={{ fontSize: 10, fontFamily: 'monospace' }} tickFormatter={(val) => `${(val / 1000).toFixed(0)}k`} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0a0a12', borderColor: '#1e293b', borderRadius: '6px', fontSize: '12px' }}
                  labelStyle={{ color: '#94a3b8', fontFamily: 'monospace' }}
                />
                <Area type="monotone" dataKey="tcpPPS" stroke="#3b82f6" fillOpacity={1} fill="url(#colorTcp)" name="TCP Packets/sec" />
                <Area type="monotone" dataKey="udpPPS" stroke="#f59e0b" fillOpacity={1} fill="url(#colorUdp)" name="UDP Packets/sec" />
                <Area type="monotone" dataKey="otherPPS" stroke="#64748b" fillOpacity={1} fill="url(#colorOther)" name="Other/DNS Packets/sec" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocol Distribution Donut */}
        <div className="bg-[#11111d] border border-slate-800 rounded-lg p-5 flex flex-col justify-between shadow-sm">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-1 flex items-center gap-2">
              <Layers className="w-4 h-4 text-purple-400" />
              Protocol Distribution
            </h3>
            <p className="text-xs text-slate-500 mb-2">
              Hardware optical ingress breakdown.
            </p>
          </div>

          <div className="h-52 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={protocolData}
                  cx="50%"
                  cy="50%"
                  innerRadius={45}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {protocolData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0a0a12', borderColor: '#1e293b', borderRadius: '6px', fontSize: '12px' }}
                  formatter={(value: any) => [`${formatNumber(Number(value))} pps`, 'Rate']}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs font-mono-code pt-2 border-t border-slate-800/80">
            {protocolData.map((item) => (
              <div key={item.name} className="flex items-center justify-between text-slate-300">
                <span className="flex items-center gap-1.5 truncate">
                  <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: item.color }} />
                  <span className="text-[10px] truncate">{(item.name || '').split(' ')[0]}</span>
                </span>
                <span className="text-slate-400 text-[10px] font-mono">
                  {item.percentage.toFixed(1)}%
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom Row: Threat Severity + Statistical Entropy + Destination Concentration */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Threat Severity Breakdown */}
        <div className="bg-[#11111d] border border-slate-800 rounded-lg p-5">
          <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-1 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-red-500" />
            Threat Severity Distribution
          </h3>
          <p className="text-xs text-slate-500 mb-3">
            Active alerts partitioned by risk in passive enclave.
          </p>

          <div className="space-y-2.5">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-red-400 font-semibold flex items-center gap-1.5 text-[11px] uppercase tracking-wider">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-500" /> Critical
                </span>
                <span className="font-mono text-slate-300 text-xs">{severityCounts.Critical}</span>
              </div>
              <div className="h-1.5 bg-[#050508] rounded-full overflow-hidden">
                <div className="h-full bg-red-500" style={{ width: `${(severityCounts.Critical / alerts.length) * 100}%` }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-amber-400 font-semibold flex items-center gap-1.5 text-[11px] uppercase tracking-wider">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-500" /> High
                </span>
                <span className="font-mono text-slate-300 text-xs">{severityCounts.High}</span>
              </div>
              <div className="h-1.5 bg-[#050508] rounded-full overflow-hidden">
                <div className="h-full bg-amber-500" style={{ width: `${(severityCounts.High / alerts.length) * 100}%` }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-blue-400 font-semibold flex items-center gap-1.5 text-[11px] uppercase tracking-wider">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-500" /> Medium
                </span>
                <span className="font-mono text-slate-300 text-xs">{severityCounts.Medium}</span>
              </div>
              <div className="h-1.5 bg-[#050508] rounded-full overflow-hidden">
                <div className="h-full bg-blue-500" style={{ width: `${(severityCounts.Medium / alerts.length) * 100}%` }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-slate-400 font-semibold flex items-center gap-1.5 text-[11px] uppercase tracking-wider">
                  <span className="w-1.5 h-1.5 rounded-full bg-slate-500" /> Low / Info
                </span>
                <span className="font-mono text-slate-300 text-xs">{severityCounts.Low}</span>
              </div>
              <div className="h-1.5 bg-[#050508] rounded-full overflow-hidden">
                <div className="h-full bg-slate-500" style={{ width: `${(severityCounts.Low / alerts.length) * 100}%` }} />
              </div>
            </div>
          </div>
        </div>

        {/* Source IP Shannon Entropy Meter */}
        <div className="bg-[#11111d] border border-slate-800 rounded-lg p-5">
          <div className="flex items-center justify-between mb-1">
            <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-blue-400" />
              Source IP Shannon Entropy
            </h3>
            <span className="text-xs font-mono font-bold text-blue-400 bg-blue-600/10 px-2 py-0.5 rounded border border-blue-500/20">
              H(X) = {telemetry.sourceIPEntropy}
            </span>
          </div>
          <p className="text-xs text-slate-500 mb-3">
            Measures randomness of incoming source addresses. Spikes indicate spoofed botnets.
          </p>

          <div className="bg-[#050508] p-3 rounded border border-slate-800 mb-3">
            <div className="flex justify-between text-[10px] font-mono text-slate-500 mb-1">
              <span>0.0 (Uniform)</span>
              <span>4.0 (Normal)</span>
              <span>8.0 (Maximum Spoof)</span>
            </div>
            <div className="h-2 bg-slate-900 rounded-full overflow-hidden relative">
              <div
                className={`h-full transition-all duration-500 ${
                  telemetry.sourceIPEntropy > 6.5 ? 'bg-gradient-to-r from-amber-500 to-red-500' : 'bg-blue-500'
                }`}
                style={{ width: `${(telemetry.sourceIPEntropy / 8.0) * 100}%` }}
              />
            </div>
          </div>

          <div className="text-xs text-slate-300 space-y-1">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-slate-500">Baseline Range:</span>
              <span className="font-mono text-slate-300">3.20 - 4.30 bits</span>
            </div>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-slate-500">Assessment:</span>
              <span className={`font-mono font-bold ${telemetry.sourceIPEntropy > 6.5 ? 'text-amber-400' : 'text-green-400'}`}>
                {telemetry.sourceIPEntropy > 6.5 ? 'Anomalous Dispersion (Spoofing)' : 'Nominal Organic Dispersion'}
              </span>
            </div>
          </div>
        </div>

        {/* Destination Concentration Index */}
        <div className="bg-[#11111d] border border-slate-800 rounded-lg p-5">
          <div className="flex items-center justify-between mb-1">
            <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 flex items-center gap-2">
              <TrendingUp className="w-4 h-4 text-green-400" />
              Destination Concentration
            </h3>
            <span className="text-xs font-mono font-bold text-green-400 bg-green-500/10 px-2 py-0.5 rounded border border-green-500/20">
              HHI: {telemetry.destinationConcentration}
            </span>
          </div>
          <p className="text-xs text-slate-500 mb-3">
            Herfindahl Index of targeted VIPs. Heavy single-node focus reveals DDoS target.
          </p>

          <div className="bg-[#050508] p-3 rounded border border-slate-800 mb-3">
            <div className="flex justify-between text-[10px] font-mono text-slate-500 mb-1">
              <span>0.0 (Uniform)</span>
              <span>0.5 (Focused)</span>
              <span>1.0 (Single VIP)</span>
            </div>
            <div className="h-2 bg-slate-900 rounded-full overflow-hidden relative">
              <div
                className={`h-full transition-all duration-500 ${
                  telemetry.destinationConcentration > 0.65 ? 'bg-gradient-to-r from-amber-500 to-red-500' : 'bg-green-500'
                }`}
                style={{ width: `${telemetry.destinationConcentration * 100}%` }}
              />
            </div>
          </div>

          <div className="text-xs text-slate-300 space-y-1">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-slate-500">Primary VIP:</span>
              <span className="font-mono text-blue-400">192.168.10.45:443</span>
            </div>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-slate-500">Target Load:</span>
              <span className={`font-mono font-bold ${telemetry.destinationConcentration > 0.65 ? 'text-red-400' : 'text-slate-300'}`}>
                {telemetry.destinationConcentration > 0.65 ? 'VIP Exhaustion Imminent' : 'Evenly Distributed'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Security Alerts Table (Priority Incident Queue from Immersive UI) */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg overflow-hidden flex flex-col shadow-sm">
        <div className="px-5 py-3 border-b border-slate-800 flex justify-between items-center bg-white/5">
          <div>
            <h3 className="text-xs sm:text-sm font-bold uppercase tracking-widest text-slate-400 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              Priority Incident Queue (Passive AI Sensor Detections)
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Correlated threat alerts generated strictly from unidirectional passive packet flows.
            </p>
          </div>
          <button
            id="btn-view-all-alerts"
            onClick={() => onNavigateTab('alerts')}
            className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1 font-bold uppercase tracking-wider cursor-pointer"
          >
            <span>All Alerts ({alerts.length})</span>
            <ExternalLink className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-black/40 text-slate-500 uppercase font-mono text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Alert ID</th>
                <th className="py-2.5 px-4">Threat Type</th>
                <th className="py-2.5 px-4">Severity</th>
                <th className="py-2.5 px-4">AI Conf.</th>
                <th className="py-2.5 px-4">Source → Target</th>
                <th className="py-2.5 px-4">Detection Method</th>
                <th className="py-2.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 font-mono text-[11px]">
              {alerts.slice(0, 5).map((alert, idx) => (
                <tr key={`${alert.id}-${idx}`} className="hover:bg-white/5 transition-colors">
                  <td className="py-2.5 px-4 text-slate-300 font-semibold">{alert.id}</td>
                  <td className="py-2.5 px-4 text-slate-100 font-sans font-medium">{alert.threatType}</td>
                  <td className="py-2.5 px-4">
                    <span
                      className={`px-2 py-0.5 rounded-sm text-[9px] font-bold uppercase ${
                        alert.severity === 'Critical'
                          ? 'bg-red-500 text-white'
                          : alert.severity === 'High'
                          ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                          : 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                      }`}
                    >
                      {alert.severity}
                    </span>
                  </td>
                  <td className="py-2.5 px-4 text-blue-400 font-bold">{alert.confidenceScore}%</td>
                  <td className="py-2.5 px-4 text-slate-400 truncate max-w-xs font-sans">
                    <span className="text-slate-200">{(alert.source || 'Unknown').split(' ')[0]}</span> → {((alert.destination || (alert as any).target) || 'Protected VIP').split(' ')[0]}
                  </td>
                  <td className="py-2.5 px-4 text-slate-400 truncate max-w-xs font-sans">
                    {alert.detectionMethod}
                  </td>
                  <td className="py-2.5 px-4 text-right">
                    <button
                      onClick={() => onSelectAlert(alert)}
                      className="px-2.5 py-1 rounded bg-[#11111d] hover:bg-slate-800 border border-slate-700 text-blue-400 text-xs font-sans transition cursor-pointer"
                    >
                      Investigate
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
