import React from 'react';
import {
  ShieldAlert,
  ArrowRight,
  Lock,
  Cpu,
  Layers,
  Brain,
  Activity,
  LayoutDashboard,
  CheckCircle2,
  XCircle,
  AlertTriangle
} from 'lucide-react';

interface OneWayDiodeBannerProps {
  isOpen: boolean;
  onClose?: () => void;
}

export const OneWayDiodeBanner: React.FC<OneWayDiodeBannerProps> = ({ isOpen }) => {
  if (!isOpen) return null;

  const pipelineSteps = [
    {
      id: 'step-1',
      title: 'Production Network',
      subtitle: 'Critical Infrastructure / Ingress',
      icon: Activity,
      color: 'border-blue-500/50 bg-blue-950/20 text-blue-400',
      badge: 'Protected Zone'
    },
    {
      id: 'step-2',
      title: 'One-Way Data Diode',
      subtitle: 'Optical Hardware Isolator (1310nm)',
      icon: Lock,
      color: 'border-amber-500/60 bg-amber-950/30 text-amber-300',
      badge: 'PHYSICAL 1-WAY'
    },
    {
      id: 'step-3',
      title: 'Passive Enclave',
      subtitle: 'DPDK Zero-Copy Ring Buffer',
      icon: ShieldAlert,
      color: 'border-emerald-500/50 bg-emerald-950/20 text-emerald-400',
      badge: 'Zero Reverse Pkts'
    },
    {
      id: 'step-4',
      title: 'Feature Extraction',
      subtitle: 'Shannon Entropy, FFT, Sliding TCP',
      icon: Layers,
      color: 'border-cyan-500/50 bg-cyan-950/20 text-cyan-400',
      badge: 'Sub-millisecond'
    },
    {
      id: 'step-5',
      title: 'AI/ML Detection',
      subtitle: 'XGBoost & Isolation Forest Ensemble',
      icon: Brain,
      color: 'border-purple-500/50 bg-purple-950/20 text-purple-400',
      badge: 'Pluggable Python Engine'
    },
    {
      id: 'step-6',
      title: 'Threat Scoring',
      subtitle: 'Evidence Aggregator & Confidence Index',
      icon: Cpu,
      color: 'border-rose-500/50 bg-rose-950/20 text-rose-400',
      badge: 'Probabilistic Score'
    },
    {
      id: 'step-7',
      title: 'Security Dashboard',
      subtitle: 'Real-time SOC Telemetry & Triage',
      icon: LayoutDashboard,
      color: 'border-sky-500/50 bg-sky-950/20 text-sky-400',
      badge: 'Operator Console'
    }
  ];

  return (
    <div
      id="oneway-architecture-banner"
      className="bg-[#0a0a12] border-b border-slate-800/60 p-4 transition-all duration-300 shadow-xl select-none"
    >
      <div className="max-w-7xl mx-auto">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-2 mb-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
              <h2 className="text-xs sm:text-sm font-bold tracking-widest uppercase text-slate-200">
                Unidirectional Physical Architecture (Data Diode Invariant)
              </h2>
              <span className="text-[10px] bg-green-500/10 text-green-400 border border-green-500/20 px-2 py-0.5 rounded font-bold uppercase tracking-wider">
                HARDWARE ISOLATION VERIFIED
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              The monitoring enclave is strictly passive: optical TX lines are physically absent or terminated. No reverse probes, handshakes, or mitigation commands can reach the production network.
            </p>
          </div>

          <div className="flex items-center gap-2 bg-[#050508] px-3 py-1.5 rounded-lg border border-slate-800/80 text-xs">
            <span className="text-red-400 flex items-center gap-1 font-bold uppercase tracking-wider text-[10px]">
              <XCircle className="w-3.5 h-3.5 text-red-400" />
              Return Path: BLOCKED
            </span>
            <span className="text-slate-700">|</span>
            <span className="text-blue-400 flex items-center gap-1 font-mono-code font-bold text-[11px]">
              <CheckCircle2 className="w-3.5 h-3.5 text-blue-400" />
              Reverse Traffic: 0 Bps
            </span>
          </div>
        </div>

        {/* Pipeline Diagram Flow */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2 my-3">
          {pipelineSteps.map((step, idx) => {
            const Icon = step.icon;
            return (
              <div key={step.id} className="relative group">
                <div className="h-full p-2.5 rounded-lg border border-slate-800 bg-[#11111d] flex flex-col justify-between transition hover:border-blue-500/60">
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="p-1 rounded bg-[#0a0a12] border border-slate-800">
                        <Icon className="w-3.5 h-3.5 text-blue-400" />
                      </div>
                      <span className="text-[8px] font-mono-code px-1.5 py-0.5 rounded bg-[#0a0a12] border border-slate-800 uppercase font-bold tracking-wider text-slate-300">
                        {step.badge}
                      </span>
                    </div>
                    <div className="text-xs font-semibold text-slate-100 leading-tight">
                      {step.title}
                    </div>
                    <div className="text-[10px] text-slate-400 leading-snug mt-1">
                      {step.subtitle}
                    </div>
                  </div>
                  
                  <div className="mt-2 pt-1.5 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-400">
                    <span className="font-mono text-[9px] uppercase tracking-wider text-slate-500">Phase 0{idx + 1}</span>
                    <span className="font-mono-code text-blue-400 font-bold">→ 1-Way</span>
                  </div>
                </div>

                {idx < pipelineSteps.length - 1 && (
                  <div className="hidden lg:block absolute -right-2 top-1/2 -translate-y-1/2 z-10 text-blue-500">
                    <ArrowRight className="w-3.5 h-3.5 drop-shadow" />
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Technical Guarantee Footnote */}
        <div className="bg-[#050508] rounded-md p-2.5 border border-slate-800/60 flex flex-col sm:flex-row items-start sm:items-center justify-between text-xs gap-2">
          <div className="flex items-center gap-2 text-slate-300">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
            <span className="text-[11px] text-slate-300">
              <strong className="text-slate-100 uppercase tracking-wide">Zero-Mitigation Backchannel Mandate:</strong> Detected threats output human-auditable advisories and BGP Flowspec exports for out-of-band administrators. The enclave NEVER transmits mitigation packets directly back into monitored fabrics.
            </span>
          </div>
          <span className="text-[10px] font-mono-code uppercase font-bold tracking-widest text-blue-400 whitespace-nowrap">
            Security Guarantee: Air-Gap Egress Invariant
          </span>
        </div>
      </div>
    </div>
  );
};
