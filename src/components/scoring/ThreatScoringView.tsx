/**
 * OneWaySentinel AI - AI Threat Scoring & Explainability Engine View (Module 6)
 *
 * Provides a unified, explainable 0 - 100 threat scoring dashboard for passive network analysis.
 *
 * STRICT PASSIVE CONSTRAINT:
 * Passive analysis only. Reverse egress: 0 bps. Production network access: NONE.
 */

import React, { useState, useMemo } from 'react';
import {
  Gauge,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Activity,
  CheckCircle2,
  Lock,
  Search,
  Filter,
  Eye,
  X,
  Sliders,
  Sparkles,
  Layers,
  ArrowRight,
  TrendingUp,
  Cpu,
  Radio,
  Zap,
  Info,
  ChevronRight,
  Clock,
  ExternalLink,
  Target
} from 'lucide-react';
import {
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar,
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid
} from 'recharts';
import { SecurityAlert, SimulationScenario, TelemetryMetrics } from '../../types';
import { FullAnalysisPipelineResult } from '../../detection/engine';
import { ExplainableSignalCard } from '../../detection/types';

interface ThreatScoringViewProps {
  pipeline?: FullAnalysisPipelineResult;
  alerts: SecurityAlert[];
  activeScenario: SimulationScenario;
  telemetry: TelemetryMetrics;
  onSelectAlert?: (alert: SecurityAlert) => void;
  onNavigateTab?: (tab: string) => void;
}

export const ThreatScoringView: React.FC<ThreatScoringViewProps> = ({
  pipeline,
  alerts,
  activeScenario,
  telemetry,
  onSelectAlert,
  onNavigateTab
}) => {
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [selectedThreatForInvestigation, setSelectedThreatForInvestigation] = useState<SecurityAlert | null>(null);

  // Extract Unified Threat Score from current pipeline or fallback calculation
  const threatScoreData = useMemo(() => {
    if (pipeline?.threatScore) {
      return pipeline.threatScore;
    }
    return {
      score: 12,
      severity: 'Low' as const,
      riskLevel: 'LOW' as const,
      confidence: 98,
      label: 'AI-Assisted Threat Scoring',
      subLabel: 'Explainable Behavioural Risk Engine',
      breakdown: {
        anomalyContribution: 2,
        ddosContribution: 0,
        temporalContribution: 2,
        entropyContribution: 2,
        concentrationContribution: 2,
        trafficIntensityContribution: 2,
        protocolContribution: 2
      },
      primaryThreat: 'Nominal Ingress Monitoring',
      allEvidence: ['Nominal ingress telemetry within historical bounds.'],
      evidenceChain: ['Ingress traffic within baseline variance.'],
      operatorExplanation: 'Traffic profile indicates routine enterprise flow without observed anomaly.',
      signalCards: [] as ExplainableSignalCard[],
      radarData: [
        { factor: 'Traffic Volume', score: 12, baseline: 15, fullMark: 100 },
        { factor: 'Protocol Anomaly', score: 10, baseline: 10, fullMark: 100 },
        { factor: 'Source Entropy', score: 15, baseline: 15, fullMark: 100 },
        { factor: 'Destination Concentration', score: 12, baseline: 12, fullMark: 100 },
        { factor: 'Temporal Regularity', score: 8, baseline: 8, fullMark: 100 },
        { factor: 'Connection Frequency', score: 10, baseline: 10, fullMark: 100 },
        { factor: 'Packet Behaviour', score: 12, baseline: 12, fullMark: 100 },
        { factor: 'Detection Confidence', score: 98, baseline: 90, fullMark: 100 }
      ],
      correlation: {
        title: 'NOMINAL BASELINE CORRELATION',
        correlatedSignalsCount: 4,
        correlationConfidence: 98,
        signalsSummary: [
          'Balanced Multi-Service Arrival Cadence',
          'Multi-Subnet Organic Source Entropy',
          'Distributed Destination VIP Ingress Mesh',
          'Standard L4 Handshake Completions'
        ],
        threatVector: 'Routine Passive Enterprise Ingress'
      },
      scoreTimeline: [
        { time: '12:00:00', score: 12 },
        { time: '12:00:10', score: 12 },
        { time: '12:00:20', score: 12 }
      ]
    };
  }, [pipeline]);

  // Global Incident Priority Sorting (Threat Score desc -> Severity desc -> Confidence desc -> Recency desc)
  const sortedAlerts = useMemo(() => {
    const severityRank: Record<string, number> = {
      Critical: 4,
      CRITICAL: 4,
      High: 3,
      HIGH: 3,
      Medium: 2,
      Moderate: 2,
      MODERATE: 2,
      Low: 1,
      LOW: 1
    };

    return [...alerts].sort((a, b) => {
      // 1. Threat Score
      const scoreA = a.threatScore ?? threatScoreData.score;
      const scoreB = b.threatScore ?? threatScoreData.score;
      if (scoreB !== scoreA) return scoreB - scoreA;

      // 2. Severity
      const sevA = severityRank[a.severity] || 1;
      const sevB = severityRank[b.severity] || 1;
      if (sevB !== sevA) return sevB - sevA;

      // 3. Confidence
      const confA = a.confidenceScore || 90;
      const confB = b.confidenceScore || 90;
      if (confB !== confA) return confB - confA;

      // 4. Recency
      return (b.timestamp || '').localeCompare(a.timestamp || '');
    });
  }, [alerts, threatScoreData.score]);

  // Filtered alerts for table
  const filteredAlerts = useMemo(() => {
    return sortedAlerts.filter((alert) => {
      const matchesSearch =
        searchTerm === '' ||
        (alert.id && alert.id.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (alert.threatType && alert.threatType.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (alert.source && alert.source.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (alert.destination && alert.destination.toLowerCase().includes(searchTerm.toLowerCase())) ||
        (alert.protocol && alert.protocol.toLowerCase().includes(searchTerm.toLowerCase()));

      const matchesSeverity =
        severityFilter === 'ALL' ||
        (severityFilter === 'CRITICAL' && alert.severity === 'Critical') ||
        (severityFilter === 'HIGH' && alert.severity === 'High') ||
        (severityFilter === 'MODERATE' && (alert.severity === 'Medium' || alert.severity === 'Low')) ||
        (severityFilter === 'LOW' && alert.severity === 'Low');

      return matchesSearch && matchesSeverity;
    });
  }, [sortedAlerts, searchTerm, severityFilter]);

  // Severity counts
  const severityCounts = useMemo(() => {
    return {
      Critical: alerts.filter((a) => a.severity === 'Critical').length,
      High: alerts.filter((a) => a.severity === 'High').length,
      Moderate: alerts.filter((a) => a.severity === 'Medium').length,
      Low: alerts.filter((a) => a.severity === 'Low').length
    };
  }, [alerts]);

  // Threat Score Color & Badge Helper
  const getScoreBadge = (score: number) => {
    if (score >= 75) {
      return {
        label: 'CRITICAL',
        color: 'text-rose-400',
        bgColor: 'bg-rose-500/10 border-rose-500/30',
        ringColor: 'stroke-rose-500',
        glow: 'shadow-glow-red'
      };
    }
    if (score >= 50) {
      return {
        label: 'HIGH',
        color: 'text-amber-400',
        bgColor: 'bg-amber-500/10 border-amber-500/30',
        ringColor: 'stroke-amber-500',
        glow: 'shadow-glow-amber'
      };
    }
    if (score >= 25) {
      return {
        label: 'MODERATE',
        color: 'text-yellow-400',
        bgColor: 'bg-yellow-500/10 border-yellow-500/30',
        ringColor: 'stroke-yellow-500',
        glow: ''
      };
    }
    return {
      label: 'LOW',
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-500/10 border-emerald-500/30',
      ringColor: 'stroke-emerald-500',
      glow: ''
    };
  };

  const badge = getScoreBadge(threatScoreData.score);

  return (
    <div id="threat-scoring-view" className="space-y-4 select-none pb-8">
      {/* 1. Header Banner with Passive Security Invariant */}
      <div className="bg-[#0a0a12] border border-slate-800/80 rounded-lg p-4 shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3.5">
          <div className="w-11 h-11 rounded-lg bg-[#050508] border border-slate-800 flex items-center justify-center text-purple-400 shrink-0">
            <Gauge className="w-6 h-6 text-purple-400 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[10px] uppercase font-mono font-bold tracking-widest text-slate-400">
                Module 6: Unified Decision Layer
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-purple-500/10 text-purple-400 border border-purple-500/20">
                AI-Assisted Threat Scoring
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                Explainable Behavioural Risk Engine
              </span>
            </div>
            <h2 className="text-base sm:text-lg font-bold text-slate-100 mt-0.5 tracking-tight flex items-center gap-2">
              <span>AI Threat Scoring & Explainability Engine</span>
              <span className="text-xs font-mono font-normal text-slate-500">
                ({activeScenario.name})
              </span>
            </h2>
          </div>
        </div>

        {/* Strict Passive Indicators */}
        <div className="flex items-center gap-2 flex-wrap bg-[#050508] px-3 py-1.5 rounded border border-slate-800/80">
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-400 font-semibold pr-3 border-r border-slate-800">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping" />
            <span>PASSIVE ANALYSIS ONLY</span>
          </div>
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-cyan-400 font-semibold pr-3 border-r border-slate-800">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span>REVERSE EGRESS: 0 BPS</span>
          </div>
          <div className="text-[11px] font-mono text-slate-400 font-medium">
            PROD NETWORK ACCESS: <span className="text-rose-400 font-bold">NONE</span>
          </div>
        </div>
      </div>

      {/* 2. One-Way Optical Data Diode Pipeline Topology Banner */}
      <div className="bg-[#0f0f18] border border-slate-800/70 rounded-lg p-3 text-xs overflow-x-auto">
        <div className="flex items-center justify-between min-w-[760px] gap-2 font-mono text-[11px]">
          <div className="flex items-center gap-1.5 text-slate-400 bg-black/40 px-2.5 py-1 rounded border border-slate-800">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />
            <span>PRODUCTION TAP</span>
          </div>
          <ArrowRight className="w-3.5 h-3.5 text-slate-600 shrink-0" />

          <div className="flex items-center gap-1.5 text-emerald-400 bg-emerald-950/30 px-2.5 py-1 rounded border border-emerald-800/50 font-bold">
            <Lock className="w-3.5 h-3.5 text-emerald-400" />
            <span>DATA DIODE (0 BPS TX)</span>
          </div>
          <ArrowRight className="w-3.5 h-3.5 text-slate-600 shrink-0" />

          <div className="flex items-center gap-1.5 text-cyan-400 bg-cyan-950/30 px-2.5 py-1 rounded border border-cyan-800/50">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span>FEATURE EXTRACTION</span>
          </div>
          <ArrowRight className="w-3.5 h-3.5 text-slate-600 shrink-0" />

          <div className="flex items-center gap-1.5 text-amber-400 bg-amber-950/30 px-2.5 py-1 rounded border border-amber-800/50">
            <Zap className="w-3.5 h-3.5 text-amber-400" />
            <span>PASSIVE DETECTION (DDoS / C2)</span>
          </div>
          <ArrowRight className="w-3.5 h-3.5 text-slate-600 shrink-0" />

          <div className="flex items-center gap-1.5 text-purple-300 bg-purple-950/40 px-2.5 py-1 rounded border border-purple-700/60 font-bold shadow-glow-purple">
            <Gauge className="w-3.5 h-3.5 text-purple-300" />
            <span>THREAT SCORING & EXPLAINABILITY</span>
          </div>
          <ArrowRight className="w-3.5 h-3.5 text-slate-600 shrink-0" />

          <div className="flex items-center gap-1.5 text-slate-300 bg-black/40 px-2.5 py-1 rounded border border-slate-800">
            <ShieldCheck className="w-3.5 h-3.5 text-slate-300" />
            <span>SOC DASHBOARD</span>
          </div>
        </div>
      </div>

      {/* 3. Primary Metrics Grid: Prominent Unified Threat Score & Key Indicators */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Unified Threat Score Card (Prominent 0 - 100 Gauge) */}
        <div className="lg:col-span-4 bg-[#0a0a12] border border-slate-800 rounded-lg p-5 flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 w-32 h-32 bg-purple-500/5 rounded-full blur-2xl pointer-events-none" />

          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] uppercase font-mono font-bold tracking-widest text-slate-400 flex items-center gap-1.5">
                <Gauge className="w-3.5 h-3.5 text-purple-400" />
                UNIFIED THREAT SCORE
              </span>
              <span className={`px-2.5 py-0.5 rounded text-[11px] font-bold font-mono uppercase tracking-wider border ${badge.bgColor} ${badge.color}`}>
                {badge.label}
              </span>
            </div>

            {/* Main Score Display */}
            <div className="flex items-baseline gap-2 mt-2">
              <span className={`text-5xl font-mono font-extrabold tracking-tight ${badge.color}`}>
                {threatScoreData.score}
              </span>
              <span className="text-xl font-mono text-slate-500 font-semibold">/ 100</span>
            </div>

            <div className="mt-3">
              <div className="flex justify-between text-[11px] font-mono mb-1">
                <span className="text-slate-400">Risk Threshold:</span>
                <span className="text-slate-200 font-bold uppercase">{badge.label} RISK LEVEL</span>
              </div>
              <div className="w-full h-2.5 bg-slate-900 rounded-full overflow-hidden flex">
                <div
                  className={`h-full transition-all duration-700 ${
                    threatScoreData.score >= 75
                      ? 'bg-rose-500'
                      : threatScoreData.score >= 50
                      ? 'bg-amber-500'
                      : threatScoreData.score >= 25
                      ? 'bg-yellow-500'
                      : 'bg-emerald-500'
                  }`}
                  style={{ width: `${Math.max(4, threatScoreData.score)}%` }}
                />
              </div>
              <div className="flex justify-between text-[9px] font-mono text-slate-500 mt-1">
                <span>0 LOW</span>
                <span>25 MODERATE</span>
                <span>50 HIGH</span>
                <span>75+ CRITICAL</span>
              </div>
            </div>
          </div>

          {/* Independent Confidence & Primary Threat */}
          <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Detection Confidence:</span>
              <span className="font-mono font-bold text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/50">
                {threatScoreData.confidence}%
              </span>
            </div>
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Dominant Vector:</span>
              <span className="font-mono text-slate-200 truncate max-w-[200px]" title={threatScoreData.primaryThreat}>
                {threatScoreData.primaryThreat}
              </span>
            </div>
            <div className="text-[11px] text-slate-400 bg-slate-900/60 p-2 rounded border border-slate-800/60 flex items-start gap-1.5 mt-2">
              <Info className="w-3.5 h-3.5 text-purple-400 shrink-0 mt-0.5" />
              <span>
                Engine: <strong className="text-slate-200">{threatScoreData.subLabel}</strong>. Transparent multi-vector synthesis without black-box drift.
              </span>
            </div>
          </div>
        </div>

        {/* Global Incident Queue Status Counters */}
        <div className="lg:col-span-4 bg-[#0a0a12] border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
          <div>
            <span className="text-[10px] uppercase font-mono font-bold tracking-widest text-slate-400 flex items-center gap-1.5 mb-3">
              <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
              GLOBAL INCIDENT INVENTORY
            </span>

            <div className="grid grid-cols-2 gap-2.5">
              <div className="bg-[#050508] p-2.5 rounded border border-rose-900/40">
                <div className="text-[10px] font-mono text-slate-400 uppercase">Critical (75-100)</div>
                <div className="text-2xl font-mono font-bold text-rose-400 mt-0.5">
                  {severityCounts.Critical}
                </div>
              </div>

              <div className="bg-[#050508] p-2.5 rounded border border-amber-900/40">
                <div className="text-[10px] font-mono text-slate-400 uppercase">High (50-74)</div>
                <div className="text-2xl font-mono font-bold text-amber-400 mt-0.5">
                  {severityCounts.High}
                </div>
              </div>

              <div className="bg-[#050508] p-2.5 rounded border border-yellow-900/40">
                <div className="text-[10px] font-mono text-slate-400 uppercase">Moderate (25-49)</div>
                <div className="text-2xl font-mono font-bold text-yellow-400 mt-0.5">
                  {severityCounts.Moderate}
                </div>
              </div>

              <div className="bg-[#050508] p-2.5 rounded border border-emerald-900/40">
                <div className="text-[10px] font-mono text-slate-400 uppercase">Low (0-24)</div>
                <div className="text-2xl font-mono font-bold text-emerald-400 mt-0.5">
                  {severityCounts.Low}
                </div>
              </div>
            </div>
          </div>

          {/* Active Flow Ingress Context */}
          <div className="mt-4 pt-3 border-t border-slate-800 text-xs text-slate-400 space-y-1 font-mono">
            <div className="flex justify-between">
              <span>Observed Flow Rate:</span>
              <span className="text-slate-200">{telemetry.packetsPerSecond.toLocaleString()} pps</span>
            </div>
            <div className="flex justify-between">
              <span>Source IP Shannon Entropy:</span>
              <span className="text-cyan-400">{telemetry.sourceIPEntropy.toFixed(2)}</span>
            </div>
            <div className="flex justify-between">
              <span>Target Concentration HHI:</span>
              <span className="text-purple-400">{telemetry.destinationConcentration.toFixed(2)}</span>
            </div>
          </div>
        </div>

        {/* Threat Score Timeline Track */}
        <div className="lg:col-span-4 bg-[#0a0a12] border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] uppercase font-mono font-bold tracking-widest text-slate-400 flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-cyan-400" />
              THREAT SCORE TIMELINE
            </span>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-800/40">
              Live Flow Sync
            </span>
          </div>

          <div className="h-28 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={threatScoreData.scoreTimeline || []}>
                <CartesianGrid strokeDasharray="2 2" stroke="#1e293b" />
                <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 9 }} />
                <YAxis domain={[0, 100]} stroke="#64748b" tick={{ fontSize: 9 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '11px' }}
                />
                <Line
                  type="monotone"
                  dataKey="score"
                  stroke={threatScoreData.score >= 75 ? '#f43f5e' : threatScoreData.score >= 50 ? '#f59e0b' : '#10b981'}
                  strokeWidth={2}
                  dot={{ r: 3, fill: '#38bdf8' }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>

          <div className="text-[11px] text-slate-400 pt-2 border-t border-slate-800/80 flex items-center justify-between">
            <span>Historical baseline correlation:</span>
            <span className="font-mono text-slate-200">Continuous 10s window</span>
          </div>
        </div>
      </div>

      {/* 4. Explainability Center: Risk Factor Radar & Multi-Signal Correlation */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Risk Factor Radar Chart (8 Factors) */}
        <div className="lg:col-span-6 bg-[#0a0a12] border border-slate-800 rounded-lg p-5">
          <div className="flex items-center justify-between mb-2">
            <div>
              <h3 className="text-xs sm:text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Target className="w-4 h-4 text-purple-400" />
                Risk Factor Dimensional Profile (8 Vectors)
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Normalized factor values driving the Unified Threat Score calculation.
              </p>
            </div>
            <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
              Polygon Area: Risk
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={threatScoreData.radarData}>
                <PolarGrid stroke="#334155" />
                <PolarAngleAxis dataKey="factor" stroke="#94a3b8" tick={{ fontSize: 10 }} />
                <PolarRadiusAxis angle={30} domain={[0, 100]} stroke="#475569" tick={{ fontSize: 9 }} />
                <Radar
                  name="Observed Profile"
                  dataKey="score"
                  stroke="#a855f7"
                  fill="#a855f7"
                  fillOpacity={0.4}
                />
                <Radar
                  name="Nominal Baseline"
                  dataKey="baseline"
                  stroke="#38bdf8"
                  fill="#38bdf8"
                  fillOpacity={0.1}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>

          {/* Factor Breakdown Legend */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[10px] font-mono mt-2 pt-2 border-t border-slate-800">
            {threatScoreData.radarData.map((item) => (
              <div key={item.factor} className="bg-[#050508] p-1.5 rounded border border-slate-800/80">
                <div className="text-slate-400 truncate">{item.factor}</div>
                <div className="flex justify-between items-center mt-0.5">
                  <span className="text-slate-100 font-bold">{item.score}/100</span>
                  <span className={`text-[9px] ${item.score > 50 ? 'text-rose-400' : 'text-slate-500'}`}>
                    Base: {item.baseline}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Multi-Signal Correlation & Operator Forensic Explanation */}
        <div className="lg:col-span-6 bg-[#0a0a12] border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-xs sm:text-sm font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-cyan-400" />
                Multi-Signal Threat Correlation
              </h3>
              <span className="text-[10px] font-mono font-bold text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/50">
                Confidence: {threatScoreData.correlation.correlationConfidence}%
              </span>
            </div>

            {/* Correlation Header Box */}
            <div className="bg-[#050508] p-3 rounded border border-slate-800 mb-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-purple-300">
                  {threatScoreData.correlation.title}
                </span>
                <span className="text-[10px] font-mono bg-purple-900/40 text-purple-300 px-2 py-0.5 rounded border border-purple-700/50">
                  {threatScoreData.correlation.correlatedSignalsCount} SIGNALS CORRELATED
                </span>
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Threat Vector: <strong className="text-slate-200">{threatScoreData.correlation.threatVector}</strong>
              </div>

              {/* Signals Checklist */}
              <div className="mt-2.5 space-y-1.5">
                {threatScoreData.correlation.signalsSummary.map((sig, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-xs text-slate-300">
                    <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    <span className="font-mono text-[11px]">{sig}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* "WHY THIS MATTERS" Operator Explanation */}
            <div className="bg-[#0e0e1a] p-3 rounded border border-slate-800/80">
              <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-amber-400 flex items-center gap-1.5 mb-1">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                OPERATOR FORENSIC EXPLANATION ("WHY THIS MATTERS")
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                {threatScoreData.operatorExplanation}
              </p>
            </div>
          </div>

          {/* Mathematical Weighting Transparency */}
          <div className="mt-3 pt-3 border-t border-slate-800 text-[10px] font-mono text-slate-500">
            Formula: Threat Score = Confidence (15%) + Anomaly (20%) + Traffic Intensity (20%) + Source/Dest Suspicion (15%) + Temporal Suspicion (15%) + Protocol Indicators (15%)
          </div>
        </div>
      </div>

      {/* 5. Individual Threat Analysis Table (Global Incident Priority) */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg overflow-hidden flex flex-col shadow-sm">
        {/* Table Header & Controls */}
        <div className="p-4 border-b border-slate-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 bg-white/5">
          <div>
            <h3 className="text-xs sm:text-sm font-bold uppercase tracking-widest text-slate-300 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-purple-400" />
              Individual Threat Analysis & Incident Priority Queue
            </h3>
            <p className="text-xs text-slate-500 mt-0.5">
              Ranked by Global Incident Priority: Threat Score → Severity → Confidence → Recency.
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap w-full md:w-auto">
            {/* Search Box */}
            <div className="relative flex-1 md:w-56">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                id="threat-table-search-input"
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search IP, type, ID..."
                className="w-full bg-[#050508] border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-purple-500"
              />
            </div>

            {/* Severity Filter Tabs */}
            <div className="flex items-center bg-[#050508] p-0.5 rounded border border-slate-800 text-[10px] font-mono">
              {(['ALL', 'CRITICAL', 'HIGH', 'MODERATE', 'LOW'] as const).map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2 py-1 rounded cursor-pointer transition-colors ${
                    severityFilter === sev
                      ? 'bg-purple-600 text-white font-bold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Table View */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-black/50 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Alert ID</th>
                <th className="py-2.5 px-4">Timestamp</th>
                <th className="py-2.5 px-4">Threat Type</th>
                <th className="py-2.5 px-4">Source → Target</th>
                <th className="py-2.5 px-4">Proto</th>
                <th className="py-2.5 px-4">Threat Score</th>
                <th className="py-2.5 px-4">Confidence</th>
                <th className="py-2.5 px-4">Severity</th>
                <th className="py-2.5 px-4">Detection Method</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-[11px]">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={11} className="py-8 text-center text-slate-500 font-sans">
                    No threat alerts match the selected search or severity criteria.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map((alert, idx) => {
                  const itemScore = alert.threatScore ?? threatScoreData.score;
                  const itemBadge = getScoreBadge(itemScore);
                  return (
                    <tr
                      key={`${alert.id}-${idx}`}
                      className="hover:bg-purple-950/10 transition-colors"
                    >
                      <td className="py-2.5 px-4 font-bold text-slate-300">
                        {alert.alertId || alert.id}
                      </td>
                      <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap">
                        {alert.timestamp ? alert.timestamp.substring(11, 19) : '12:00:00'}
                      </td>
                      <td className="py-2.5 px-4 font-sans font-medium text-slate-100 whitespace-nowrap">
                        {alert.threatType}
                      </td>
                      <td className="py-2.5 px-4 whitespace-nowrap">
                        <span className="text-cyan-400">{alert.source}</span>
                        <span className="text-slate-500 mx-1">→</span>
                        <span className="text-purple-400">{alert.destination}</span>
                      </td>
                      <td className="py-2.5 px-4 text-slate-300">
                        {alert.protocol}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className={`font-bold ${itemBadge.color}`}>
                          {itemScore}/100
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-cyan-400 font-bold">
                        {alert.confidenceScore || 94}%
                      </td>
                      <td className="py-2.5 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase ${
                            alert.severity === 'Critical'
                              ? 'bg-rose-500 text-white'
                              : alert.severity === 'High'
                              ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                              : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                          }`}
                        >
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-slate-400 font-sans text-[11px] truncate max-w-[180px]">
                        {alert.detectionMethod}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-slate-800 text-slate-300">
                          {alert.status || 'OPEN'}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-right">
                        <button
                          id={`btn-investigate-${alert.id}`}
                          onClick={() => {
                            setSelectedThreatForInvestigation(alert);
                            if (onSelectAlert) onSelectAlert(alert);
                          }}
                          className="px-2.5 py-1 rounded text-xs bg-purple-600/20 text-purple-300 hover:bg-purple-600 hover:text-white border border-purple-500/30 transition-all font-sans font-medium flex items-center gap-1 ml-auto cursor-pointer"
                        >
                          <span>Investigate</span>
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* 6. Explainable Threat Breakdown Slide-Over / Modal */}
      {selectedThreatForInvestigation && (
        <div
          id="threat-breakdown-modal"
          className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto"
        >
          <div className="bg-[#0c0c16] border border-purple-800/80 rounded-xl w-full max-w-4xl max-h-[90vh] overflow-y-auto shadow-2xl p-6 relative">
            {/* Modal Header */}
            <div className="flex items-start justify-between pb-4 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-purple-400 bg-purple-950/60 px-2 py-0.5 rounded border border-purple-700/50">
                    EXPLAINABLE THREAT BREAKDOWN
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    ID: {selectedThreatForInvestigation.alertId || selectedThreatForInvestigation.id}
                  </span>
                </div>
                <h2 className="text-xl font-bold text-slate-100 mt-1">
                  {selectedThreatForInvestigation.threatType}
                </h2>
                <div className="text-xs font-mono text-slate-400 mt-1">
                  Targeted Path: <span className="text-cyan-400">{selectedThreatForInvestigation.source}</span> → <span className="text-purple-400">{selectedThreatForInvestigation.destination}</span>
                </div>
              </div>

              <button
                id="btn-close-investigation-modal"
                onClick={() => setSelectedThreatForInvestigation(null)}
                className="w-8 h-8 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white flex items-center justify-center cursor-pointer transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Score & Confidence Overview Banner */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 my-4">
              <div className="bg-[#050508] p-3 rounded-lg border border-purple-900/50">
                <div className="text-[10px] font-mono text-slate-400 uppercase">Threat Score</div>
                <div className="text-3xl font-mono font-extrabold text-purple-400 mt-0.5">
                  {selectedThreatForInvestigation.threatScore ?? threatScoreData.score} <span className="text-sm font-normal text-slate-500">/ 100</span>
                </div>
                <div className="text-[10px] font-mono text-purple-300 mt-1">
                  Severity: {selectedThreatForInvestigation.severity.toUpperCase()}
                </div>
              </div>

              <div className="bg-[#050508] p-3 rounded-lg border border-cyan-900/50">
                <div className="text-[10px] font-mono text-slate-400 uppercase">Detection Confidence</div>
                <div className="text-3xl font-mono font-extrabold text-cyan-400 mt-0.5">
                  {selectedThreatForInvestigation.confidenceScore || 94}%
                </div>
                <div className="text-[10px] font-mono text-cyan-300 mt-1">
                  Engine Classification Fidelity
                </div>
              </div>

              <div className="bg-[#050508] p-3 rounded-lg border border-slate-800">
                <div className="text-[10px] font-mono text-slate-400 uppercase">Detection Protocol</div>
                <div className="text-xl font-mono font-bold text-slate-200 mt-1">
                  {selectedThreatForInvestigation.protocol}
                </div>
                <div className="text-[10px] font-mono text-slate-400 mt-1 truncate">
                  {selectedThreatForInvestigation.detectionMethod}
                </div>
              </div>
            </div>

            {/* Section: "WHY WAS THIS SCORED HIGH?" Individual Signal Cards */}
            <div className="mb-5">
              <div className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2 mb-3">
                <Sparkles className="w-4 h-4 text-purple-400" />
                <span>WHY WAS THIS SCORED {selectedThreatForInvestigation.severity.toUpperCase()}? (Signal Breakdown)</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {threatScoreData.signalCards.map((card) => (
                  <div
                    key={card.id}
                    className="bg-[#070712] border border-slate-800/80 rounded-lg p-3.5 space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-200">{card.name}</span>
                      <span
                        className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded uppercase ${
                          card.contribution === 'HIGH'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : card.contribution === 'MEDIUM'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {card.contribution} CONTRIBUTION
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-xs font-mono">
                      <span className="text-slate-400">Signal Score:</span>
                      <span className="text-purple-300 font-bold">{card.score}/100</span>
                    </div>

                    <div className="text-[11px] font-mono text-cyan-400 bg-black/40 p-1.5 rounded border border-slate-800/60">
                      {card.telemetryContext}
                    </div>

                    <p className="text-xs text-slate-400 leading-snug">
                      {card.forensicInterpretation}
                    </p>
                  </div>
                ))}
              </div>
            </div>

            {/* Section: Telemetry Evidence Chain */}
            <div className="bg-[#050508] p-4 rounded-lg border border-slate-800 mb-4">
              <div className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-2 mb-2">
                <CheckCircle2 className="w-4 h-4 text-cyan-400" />
                <span>FORENSIC TELEMETRY EVIDENCE CHAIN</span>
              </div>
              <ul className="space-y-1.5 text-xs text-slate-300 font-mono">
                {threatScoreData.evidenceChain.map((ev, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-cyan-400 font-bold">✓</span>
                    <span>{ev}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Out-of-band mitigation advisory reminder */}
            <div className="bg-purple-950/20 border border-purple-800/40 p-3.5 rounded-lg text-xs text-slate-300">
              <div className="font-bold text-purple-300 uppercase tracking-wide flex items-center gap-1.5 mb-1 font-mono text-[11px]">
                <Lock className="w-3.5 h-3.5 text-purple-400" />
                PASSIVE ENCLAVE OUT-OF-BAND MITIGATION ADVISORY
              </div>
              <p className="leading-relaxed">
                OneWaySentinel AI is decoupled from the production transmission plane (hardware diode invariant: 0 reverse packets).
                Mitigation execution must be carried out manually via out-of-band management console (e.g. switch port isolation or firewall blocklist update for destination {selectedThreatForInvestigation.destination}).
              </p>
            </div>

            {/* Modal Actions */}
            <div className="mt-5 pt-3 border-t border-slate-800 flex justify-end gap-2">
              <button
                onClick={() => setSelectedThreatForInvestigation(null)}
                className="px-4 py-2 rounded text-xs bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium transition-colors cursor-pointer"
              >
                Close Investigation
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
