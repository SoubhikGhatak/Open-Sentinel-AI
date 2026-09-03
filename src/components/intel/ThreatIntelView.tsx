import React, { useState } from 'react';
import {
  FileText,
  Search,
  Shield,
  Download,
  ExternalLink,
  Target,
  Database,
  Hash,
  Globe,
  CheckCircle2,
  Copy,
  Check,
  Cpu
} from 'lucide-react';
import { ThreatIntelligenceRecord } from '../../types';

interface ThreatIntelViewProps {
  intelRecords: ThreatIntelligenceRecord[];
}

export const ThreatIntelView: React.FC<ThreatIntelViewProps> = ({ intelRecords }) => {
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedIoc, setSelectedIoc] = useState<ThreatIntelligenceRecord>(intelRecords[0]);
  const [copiedStix, setCopiedStix] = useState<boolean>(false);

  const filteredRecords = intelRecords.filter((rec) => {
    const q = searchQuery.toLowerCase();
    return (
      rec.iocValue.toLowerCase().includes(q) ||
      rec.threatActor.toLowerCase().includes(q) ||
      rec.threatType.toLowerCase().includes(q) ||
      rec.iocType.toLowerCase().includes(q)
    );
  });

  const mitreTactics = [
    { id: 'T1498', name: 'Network Denial of Service', phase: 'Impact', detectedCount: 4, status: 'Active' },
    { id: 'T1498.001', name: 'Direct Network Flood (SYN/UDP)', phase: 'Impact', detectedCount: 2, status: 'Active' },
    { id: 'T1498.002', name: 'Reflection Amplification (NTP/DNS)', phase: 'Impact', detectedCount: 1, status: 'Active' },
    { id: 'T1071.001', name: 'Web Protocols C2 (Cobalt Strike)', phase: 'Command and Control', detectedCount: 3, status: 'Active' },
    { id: 'T1568.002', name: 'Domain Generation Algorithms (DGA)', phase: 'Command and Control', detectedCount: 1, status: 'Suspected' },
    { id: 'T1046', name: 'Network Service Discovery', phase: 'Discovery', detectedCount: 1, status: 'Historical' }
  ];

  const exportStix = () => {
    const stixBundle = {
      type: 'bundle',
      id: `bundle--${Math.random().toString(36).substring(2, 10)}`,
      spec_version: '2.1',
      objects: intelRecords.map((r) => ({
        type: 'indicator',
        id: `indicator--${r.id}`,
        created: '2026-09-03T00:00:00.000Z',
        name: `${r.threatType} indicator for ${r.threatActor}`,
        pattern: `[${r.iocType.toLowerCase()}-addr:value = '${r.iocValue}']`,
        valid_from: '2026-09-03T00:00:00.000Z',
        confidence: r.confidenceScore,
        labels: r.mitreTactics
      }))
    };
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(stixBundle, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', 'OneWaySentinel_STIX_2.1_Export.json');
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div id="threat-intel-view" className="space-y-4 select-none">
      {/* Header */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-xl">
        <div>
          <h2 className="text-sm font-bold text-slate-100 uppercase tracking-widest flex items-center gap-2">
            <FileText className="w-4 h-4 text-blue-500" />
            Threat Intelligence & MITRE ATT&CK Matrix Correlation
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Correlating passively extracted traffic features against global cyber threat feeds and known adversary infrastructures.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={exportStix}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded bg-[#11111d] hover:bg-slate-800 text-blue-400 border border-slate-700 font-mono font-bold uppercase tracking-wider transition cursor-pointer"
          >
            <Download className="w-3 h-3" />
            <span>Export STIX 2.1 JSON</span>
          </button>
        </div>
      </div>

      {/* MITRE ATT&CK Framework Mapping */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 shadow-sm">
        <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2 mb-1">
          <Target className="w-3.5 h-3.5 text-red-400" />
          Detected Adversary Tactics & Techniques (MITRE ATT&CK)
        </h3>
        <p className="text-xs text-slate-500 mb-3">
          Mapped based on passive protocol behavior observed via the unidirectional fiber tap.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5">
          {mitreTactics.map((tactic) => (
            <div key={tactic.id} className="bg-[#11111d] p-3 rounded border border-slate-800 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="font-mono font-bold text-blue-400 text-xs">{tactic.id}</span>
                  <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase tracking-wider ${
                    tactic.status === 'Active' ? 'bg-red-500 text-white' : 'bg-[#050508] text-slate-500 border border-slate-800'
                  }`}>
                    {tactic.status} ({tactic.detectedCount})
                  </span>
                </div>
                <div className="font-bold text-slate-200 text-xs">{tactic.name}</div>
              </div>
              <div className="mt-2 pt-2 border-t border-slate-800 text-[10px] text-slate-500 font-mono flex justify-between">
                <span>Phase: {tactic.phase}</span>
                <span className="text-blue-400 font-bold uppercase">Validated</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* IoC Database & Drilldown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* IoC Table */}
        <div className="lg:col-span-2 bg-[#0a0a12] border border-slate-800 rounded-lg p-4 shadow-sm space-y-3">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <Database className="w-3.5 h-3.5 text-blue-400" />
              Indicators of Compromise (IoC Feed)
            </h3>

            <div className="relative w-full sm:w-56">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search IoC, Actor, Type..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-[#050508] border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
              />
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-black/40 text-slate-500 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Type</th>
                  <th className="py-2.5 px-3">Indicator Value</th>
                  <th className="py-2.5 px-3">Associated Actor</th>
                  <th className="py-2.5 px-3">Threat</th>
                  <th className="py-2.5 px-3">Confidence</th>
                  <th className="py-2.5 px-3 text-right">View</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-[11px]">
                {filteredRecords.map((record) => (
                  <tr
                    key={record.id}
                    onClick={() => setSelectedIoc(record)}
                    className={`hover:bg-white/5 transition cursor-pointer ${
                      selectedIoc.id === record.id ? 'bg-blue-600/10 text-blue-300' : 'text-slate-300'
                    }`}
                  >
                    <td className="py-2.5 px-3">
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase bg-[#050508] text-slate-400 border border-slate-800">
                        {record.iocType}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-bold text-slate-100">{record.iocValue}</td>
                    <td className="py-2.5 px-3 text-slate-300">{record.threatActor}</td>
                    <td className="py-2.5 px-3 text-red-400">{record.threatType}</td>
                    <td className="py-2.5 px-3 font-bold text-green-400">{record.confidenceScore}%</td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedIoc(record);
                        }}
                        className="px-2 py-0.5 rounded bg-[#11111d] text-blue-400 hover:bg-slate-800 border border-slate-700 text-[10px] font-mono transition"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Selected IoC Profile */}
        <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
          <div>
            <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2 mb-2">
              <Shield className="w-3.5 h-3.5 text-blue-400" />
              Adversary Dossier & IoC Analysis
            </h3>

            {selectedIoc && (
              <div className="space-y-3 text-xs">
                <div className="bg-[#050508] p-3 rounded border border-slate-800 font-mono">
                  <span className="text-slate-500 text-[9px] uppercase tracking-wider block">INDICATOR VALUE ({selectedIoc.iocType})</span>
                  <span className="text-blue-400 font-bold text-xs break-all">{selectedIoc.iocValue}</span>
                </div>

                <div className="space-y-1">
                  <span className="text-slate-500 font-mono uppercase font-bold block text-[10px] tracking-wider">Attributed Threat Group:</span>
                  <div className="text-slate-200 font-bold bg-[#050508] p-2 rounded border border-slate-800 text-xs">
                    {selectedIoc.threatActor}
                  </div>
                </div>

                <div className="space-y-1">
                  <span className="text-slate-500 font-mono uppercase font-bold block text-[10px] tracking-wider">Threat Context & Behavior:</span>
                  <p className="text-slate-300 bg-[#050508] p-2.5 rounded border border-slate-800 leading-relaxed text-[11px]">
                    {selectedIoc.maliciousActivitySummary}
                  </p>
                </div>

                <div className="space-y-1">
                  <span className="text-slate-500 font-mono uppercase font-bold block text-[10px] tracking-wider">Associated MITRE Tactics:</span>
                  <div className="flex flex-wrap gap-1">
                    {selectedIoc.mitreTactics.map((t) => (
                      <span key={t} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[#11111d] text-blue-400 border border-slate-700 uppercase">
                        {t}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="space-y-1">
                  <span className="text-slate-500 font-mono uppercase font-bold block text-[10px] tracking-wider">Reputation Intelligence Source:</span>
                  <div className="text-slate-400 font-mono text-[10px] bg-[#050508] p-2 rounded border border-slate-800">
                    {selectedIoc.reputationSource}
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className="pt-3 border-t border-slate-800 text-[10px] font-mono text-slate-500 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
            <span>Synced with Enclave Passive Matcher</span>
          </div>
        </div>
      </div>
    </div>
  );
};
