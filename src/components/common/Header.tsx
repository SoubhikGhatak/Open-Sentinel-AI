import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Radio,
  Cpu,
  AlertTriangle,
  Play,
  Pause,
  Zap,
  Info
} from 'lucide-react';
import { TelemetryMetrics, SimulationScenario } from '../../types';

interface HeaderProps {
  telemetry: TelemetryMetrics;
  activeScenario: SimulationScenario;
  scenarios: SimulationScenario[];
  onSelectScenario: (scenarioId: string) => void;
  isStreaming: boolean;
  onToggleStreaming: () => void;
  onToggleDiodeBanner: () => void;
  isDiodeBannerOpen: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  telemetry,
  activeScenario,
  scenarios,
  onSelectScenario,
  isStreaming,
  onToggleStreaming,
  onToggleDiodeBanner,
  isDiodeBannerOpen,
}) => {
  return (
    <header id="soc-header" className="bg-[#0a0a12] border-b border-slate-800/60 sticky top-0 z-50 backdrop-blur select-none">
      {/* Top operational status stripe */}
      <div className="bg-[#050508] border-b border-slate-800/60 px-4 sm:px-6 py-1 text-xs flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-3 text-slate-400">
          <div className="flex items-center gap-2 px-2.5 py-0.5 bg-green-500/10 border border-green-500/20 rounded-full">
            <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse" />
            <span className="text-[10px] uppercase font-bold text-green-400 tracking-wider">Passive Monitoring Enclave: STRICTLY PASSIVE</span>
          </div>
          <span className="hidden md:inline text-slate-700">|</span>
          <span className="hidden md:flex items-center gap-1.5 text-blue-400 font-mono-code text-[11px]">
            <ShieldCheck className="w-3.5 h-3.5 text-blue-400" />
            <span>ONE-WAY INGRESS (RETURN PATH: BLOCKED)</span>
          </span>
          <span className="hidden lg:inline text-slate-700">|</span>
          <span className="hidden lg:flex items-center gap-1.5 text-emerald-400 font-mono-code text-[11px] bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
            EGRESS PACKETS: 0 (PRODUCTION NETWORK ACCESS: NONE)
          </span>
        </div>

        <div className="flex items-center gap-3 text-slate-400">
          <div className="flex items-center gap-2 px-2 py-0.5 rounded bg-amber-500/10 border border-amber-500/25">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-ping" />
            <span className="text-[10px] font-mono-code uppercase font-bold text-amber-400 tracking-wider">SIMULATION MODE</span>
            <span className="text-slate-600 hidden xl:inline">|</span>
            <span className="text-[10px] font-mono-code text-slate-400 hidden xl:inline">Data Source: Synthetic Passive Flow Generator</span>
          </div>
          <div className="hidden md:flex flex-col items-end">
            <span className="text-[9px] uppercase text-slate-500 font-medium tracking-wider">Optical Rx Power</span>
            <span className="text-[11px] font-mono-code text-slate-300">{telemetry.diodeOpticalRxPowerDbm} dBm</span>
          </div>
          <span className="text-[9px] bg-blue-600/10 text-blue-400 px-2 py-0.5 rounded border border-blue-500/20 font-mono-code font-bold uppercase tracking-wider">
            PASSIVE SOC ENCLAVE
          </span>
        </div>
      </div>

      {/* Main header row */}
      <div className="px-4 sm:px-6 py-2.5 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center gap-3.5">
          {/* Immersive UI 1W Logo Box */}
          <div className="w-8 h-8 bg-blue-600 rounded flex items-center justify-center font-bold text-white shadow-glow-blue shrink-0">
            1W
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-lg font-semibold tracking-tight text-white uppercase flex items-center gap-1.5">
                OneWaySentinel <span className="text-blue-500">AI</span>
              </h1>
              <div className="h-4 w-[1px] bg-slate-700 hidden sm:inline" />
              <span className="text-[9px] uppercase font-mono-code tracking-widest px-2 py-0.5 rounded bg-[#11111d] text-slate-400 border border-slate-800">
                SOC Core v2.4
              </span>
            </div>
            <p className="text-xs text-slate-400 flex items-center gap-2 mt-0.5">
              <span>Unidirectional AI Network Threat Detection & Intelligence</span>
              <button
                id="btn-toggle-diode-banner"
                onClick={onToggleDiodeBanner}
                className="text-blue-400 hover:text-blue-300 underline font-medium cursor-pointer inline-flex items-center gap-1 text-[11px] transition-colors"
                title="View One-Way Physical Architecture Diagram"
              >
                <Info className="w-3 h-3" />
                {isDiodeBannerOpen ? 'Hide Architecture' : 'View Architecture Flow'}
              </button>
            </p>
          </div>
        </div>

        {/* Action controls & scenario selector */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Attack Scenario Injector for Hackathon Evaluation */}
          <div className="flex items-center bg-[#11111d] border border-slate-800 rounded-lg px-2.5 py-1.5 gap-2 shadow-inner">
            <div className="flex items-center gap-1.5 text-xs text-amber-400 font-bold uppercase tracking-wider text-[10px]">
              <Zap className="w-3 h-3 text-amber-400 animate-pulse" />
              <span className="hidden sm:inline">Scenario:</span>
            </div>
            <select
              id="select-scenario"
              value={activeScenario.id}
              onChange={(e) => onSelectScenario(e.target.value)}
              className="bg-[#0a0a12] border border-slate-700 text-slate-100 text-xs rounded px-2 py-1 focus:outline-none focus:border-blue-500 font-mono-code cursor-pointer"
            >
              {scenarios.map((sc) => (
                <option key={sc.id} value={sc.id}>
                  {sc.category === 'Baseline' ? '🟢' : '🔴'} {sc.name}
                </option>
              ))}
            </select>
          </div>

          {/* Pause / Live stream control */}
          <button
            id="btn-toggle-streaming"
            onClick={onToggleStreaming}
            className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border font-mono-code font-bold uppercase tracking-wider transition cursor-pointer ${
              isStreaming
                ? 'bg-blue-600/10 text-blue-400 border-blue-500/30 hover:bg-blue-600/20'
                : 'bg-amber-500/10 text-amber-400 border-amber-500/30 hover:bg-amber-500/20'
            }`}
          >
            {isStreaming ? (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-ping" />
                <span>Live Feed</span>
                <Pause className="w-3 h-3 ml-1" />
              </>
            ) : (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                <span>Paused</span>
                <Play className="w-3 h-3 ml-1" />
              </>
            )}
          </button>
        </div>
      </div>
    </header>
  );
};
