import React from 'react';
import {
  LayoutDashboard,
  Activity,
  Zap,
  Radio,
  Gauge,
  FileText,
  Search,
  Server,
  AlertOctagon,
  HardDrive
} from 'lucide-react';

export type ActiveTab =
  | 'dashboard'
  | 'traffic'
  | 'ingestion'
  | 'ddos'
  | 'c2'
  | 'scoring'
  | 'intel'
  | 'alerts'
  | 'forensics'
  | 'system';

interface NavigationProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: ActiveTab) => void;
  criticalAlertsCount: number;
  activeThreatsCount: number;
}

export const Navigation: React.FC<NavigationProps> = ({
  activeTab,
  onSelectTab,
  criticalAlertsCount,
  activeThreatsCount
}) => {
  const tabs = [
    {
      id: 'dashboard' as ActiveTab,
      label: '1. Dashboard',
      icon: LayoutDashboard,
      badge: null
    },
    {
      id: 'traffic' as ActiveTab,
      label: '2. Live Traffic',
      icon: Activity,
      badge: 'Live'
    },
    {
      id: 'ingestion' as ActiveTab,
      label: '3. Passive Ingestion',
      icon: HardDrive,
      badge: 'Feature Extr',
      badgeColor: 'bg-cyan-950 text-cyan-300 border-cyan-800'
    },
    {
      id: 'ddos' as ActiveTab,
      label: '4. DDoS Detection',
      icon: Zap,
      badge: activeThreatsCount > 1 ? `${activeThreatsCount} Threats` : null,
      badgeColor: 'bg-rose-950 text-rose-300 border-rose-800/80'
    },
    {
      id: 'c2' as ActiveTab,
      label: '5. C2 Beacon Detection',
      icon: Radio,
      badge: 'FFT Jitter'
    },
    {
      id: 'scoring' as ActiveTab,
      label: '6. Threat Scoring',
      icon: Gauge,
      badge: 'AI Explainable',
      badgeColor: 'bg-purple-950 text-purple-300 border-purple-800'
    },
    {
      id: 'intel' as ActiveTab,
      label: '7. Threat Intelligence',
      icon: FileText,
      badge: 'MITRE'
    },
    {
      id: 'alerts' as ActiveTab,
      label: '8. Alerts',
      icon: AlertOctagon,
      badge: criticalAlertsCount > 0 ? `${criticalAlertsCount} Critical` : null,
      badgeColor: 'bg-rose-600 text-white font-bold animate-pulse'
    },
    {
      id: 'forensics' as ActiveTab,
      label: '9. Forensics',
      icon: Search,
      badge: 'PCAP'
    },
    {
      id: 'system' as ActiveTab,
      label: '10. System Status',
      icon: Server,
      badge: 'Diode 100%'
    }
  ];

  return (
    <nav id="soc-navigation" className="bg-[#0a0a12] border-b border-slate-800/60 px-4 sm:px-6 select-none">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-4 py-1.5">
        <div className="flex items-center gap-1 overflow-x-auto scrollbar-none flex-1 py-0.5">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                id={`nav-tab-${tab.id}`}
                onClick={() => onSelectTab(tab.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-bold uppercase tracking-widest whitespace-nowrap transition-colors cursor-pointer ${
                  isActive
                    ? 'bg-blue-600/10 border-b-2 border-blue-500 text-blue-400'
                    : 'text-slate-500 hover:text-slate-300 hover:bg-white/5 border-b-2 border-transparent'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-blue-400' : 'text-slate-500'}`} />
                <span>{tab.label}</span>

                {tab.badge && (
                  <span
                    className={`text-[9px] px-1.5 py-0.5 rounded font-mono-code font-bold uppercase ${
                      tab.badgeColor || 'bg-[#11111d] text-slate-400 border border-slate-800'
                    }`}
                  >
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Immersive UI Architecture Flow Micro-Widget */}
        <div className="hidden xl:flex items-center gap-3 pl-3 border-l border-slate-800/60 text-[10px] font-mono shrink-0">
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 font-mono">PROD NET</span>
            <span className="text-blue-500 font-bold">→</span>
            <span className="text-white font-mono font-bold">SENTINEL</span>
          </div>
          <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div className="h-full bg-blue-500 w-[65%]" />
          </div>
          <div className="px-2 py-0.5 bg-red-900/10 border border-red-500/20 rounded text-center">
            <span className="text-[8px] text-red-400 font-bold uppercase tracking-wider">Return Path Blocked</span>
          </div>
        </div>
      </div>
    </nav>
  );
};
