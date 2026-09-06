import React, { useState } from 'react';
import {
  AlertOctagon,
  Filter,
  Search,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Shield,
  Download,
  X,
  FileCheck,
  ChevronRight,
  UserCheck
} from 'lucide-react';
import { SecurityAlert, Severity, ThreatType, AlertStatus } from '../../types';

interface AlertsViewProps {
  alerts: SecurityAlert[];
  onUpdateAlertStatus: (alertId: string, status: AlertStatus) => void;
  initialSelectedAlert?: SecurityAlert | null;
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  alerts,
  onUpdateAlertStatus,
  initialSelectedAlert
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [threatTypeFilter, setThreatTypeFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(
    initialSelectedAlert || alerts[0] || null
  );

  React.useEffect(() => {
    if (initialSelectedAlert) {
      const fresh = alerts.find((a) => a.id === initialSelectedAlert.id) || initialSelectedAlert;
      setSelectedAlert(fresh);
    } else if (selectedAlert) {
      const fresh = alerts.find((a) => a.id === selectedAlert.id);
      if (fresh) {
        setSelectedAlert(fresh);
      } else if (alerts.length > 0) {
        setSelectedAlert(alerts[0]);
      }
    } else if (alerts.length > 0) {
      setSelectedAlert(alerts[0]);
    }
  }, [initialSelectedAlert, alerts]);

  const filteredAlerts = alerts.filter((alert) => {
    if (severityFilter !== 'ALL' && alert.severity !== severityFilter) return false;
    if (threatTypeFilter !== 'ALL' && alert.threatType !== threatTypeFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        (alert.id || '').toLowerCase().includes(q) ||
        (alert.threatType || '').toLowerCase().includes(q) ||
        (alert.source || '').toLowerCase().includes(q) ||
        (alert.destination || (alert as any).target || '').toLowerCase().includes(q) ||
        (alert.detectionMethod || '').toLowerCase().includes(q)
      );
    }
    return true;
  });

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(alerts, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', 'OneWaySentinel_Alerts_Report.json');
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div id="alerts-view" className="space-y-4 select-none">
      {/* Header */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-xl">
        <div>
          <h2 className="text-sm font-bold text-slate-100 uppercase tracking-widest flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-red-500" />
            Security Incident Alerts & Triage Console
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Strict unidirectional evidence aggregation. Every alert features verified detection methods, confidence scores, and forensic indicators.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportJson}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded bg-[#11111d] hover:bg-slate-800 text-blue-400 border border-slate-700 font-mono font-bold uppercase tracking-wider transition cursor-pointer"
          >
            <Download className="w-3 h-3" />
            <span>Export Incident Log (JSON)</span>
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-2 font-mono">
          <div className="flex items-center gap-1 text-slate-500 mr-1 text-[10px] uppercase tracking-wider">
            <Filter className="w-3 h-3 text-slate-500" />
            <span>Severity:</span>
          </div>
          {['ALL', 'Critical', 'High', 'Medium', 'Low'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider transition cursor-pointer ${
                severityFilter === sev
                  ? 'bg-blue-600 text-white font-bold'
                  : 'bg-[#11111d] text-slate-400 border border-slate-800 hover:text-slate-200'
              }`}
            >
              {sev}
            </button>
          ))}

          <span className="text-slate-700 hidden sm:inline">|</span>

          <select
            value={threatTypeFilter}
            onChange={(e) => setThreatTypeFilter(e.target.value)}
            className="bg-[#050508] border border-slate-800 text-slate-300 text-xs rounded px-2.5 py-1 focus:outline-none focus:border-blue-500 cursor-pointer font-mono"
          >
            <option value="ALL">All Threat Types</option>
            <option value="SYN Flood">SYN Flood</option>
            <option value="UDP Flood">UDP Flood</option>
            <option value="UDP Reflection/Amplification">UDP Reflection/Amplification</option>
            <option value="Spoofed-Source Flood">Spoofed-Source Flood</option>
            <option value="Botnet C2 Beaconing">Botnet C2 Beaconing</option>
            <option value="General Traffic Anomaly">General Traffic Anomaly</option>
          </select>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search Alert, Target, Evidence..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#050508] border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
          />
        </div>
      </div>

      {/* Main Alerts Grid: Master Table + Detail Pane */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Alerts List */}
        <div className="lg:col-span-2 bg-[#0a0a12] border border-slate-800 rounded-lg overflow-hidden shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-black/40 text-slate-500 uppercase text-[10px] tracking-wider border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-3">Alert ID</th>
                  <th className="py-2.5 px-3">Threat Type</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Confidence</th>
                  <th className="py-2.5 px-3">Target</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-[11px]">
                {filteredAlerts.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-slate-500 font-mono">
                      No security alerts match the active filters.
                    </td>
                  </tr>
                ) : (
                  filteredAlerts.map((alert, idx) => (
                    <tr
                      key={`${alert.id}-${idx}`}
                      onClick={() => setSelectedAlert(alert)}
                      className={`transition cursor-pointer ${
                        selectedAlert?.id === alert.id
                          ? 'bg-blue-600/10 text-blue-300'
                          : 'hover:bg-white/5 text-slate-300'
                      }`}
                    >
                      <td className="py-3 px-3 font-semibold text-slate-200">{alert.id}</td>
                      <td className="py-3 px-3 font-bold text-slate-100">{alert.threatType}</td>
                      <td className="py-3 px-3">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider ${
                            alert.severity === 'Critical'
                              ? 'bg-red-500 text-white'
                              : alert.severity === 'High'
                              ? 'bg-amber-500/20 text-amber-300 border border-amber-800'
                              : 'bg-blue-500/20 text-blue-300 border border-blue-800'
                          }`}
                        >
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-green-400 font-bold">{alert.confidenceScore}%</td>
                      <td className="py-3 px-3 text-slate-400 truncate max-w-xs font-mono">
                        {((alert.destination || (alert as any).target) || 'Unknown VIP').split(' ')[0]}
                      </td>
                      <td className="py-3 px-3">
                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono uppercase tracking-wider ${
                          alert.status === 'New' ? 'bg-purple-950 text-purple-300 border border-purple-800' :
                          alert.status === 'Investigating' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                          alert.status === 'Verified' ? 'bg-red-950 text-red-300 border border-red-800' :
                          alert.status === 'Mitigated' ? 'bg-green-950 text-green-300 border border-green-800' :
                          'bg-slate-800 text-slate-400'
                        }`}>
                          {alert.status}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedAlert(alert);
                          }}
                          className="px-2 py-0.5 rounded bg-[#11111d] hover:bg-slate-800 border border-slate-700 text-blue-400 text-[10px] font-mono transition"
                        >
                          Details
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Complete Alert Forensic Dossier */}
        <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 flex flex-col justify-between shadow-lg">
          {selectedAlert ? (
            <div className="space-y-3.5">
              <div className="border-b border-slate-800 pb-3 flex items-start justify-between">
                <div>
                  <span className="text-[9px] font-mono text-slate-500 uppercase tracking-wider">INCIDENT DOSSIER</span>
                  <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                    <span>{selectedAlert.id}</span>
                    <span className="text-xs font-medium text-slate-400">({selectedAlert.threatType})</span>
                  </h3>
                </div>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase tracking-wider ${
                    selectedAlert.severity === 'Critical'
                      ? 'bg-red-500 text-white'
                      : 'bg-amber-500/20 text-amber-300 border border-amber-800'
                  }`}
                >
                  {selectedAlert.severity}
                </span>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs font-mono bg-[#050508] p-2.5 rounded border border-slate-800">
                <div>
                  <span className="text-slate-500 text-[9px] uppercase tracking-wider block">THREAT TYPE</span>
                  <span className="text-slate-100 font-bold">{selectedAlert.threatType}</span>
                </div>
                <div>
                  <span className="text-slate-500 text-[9px] uppercase tracking-wider block">AI CONFIDENCE SCORE</span>
                  <span className="text-green-400 font-bold text-xs">{selectedAlert.confidenceScore}%</span>
                </div>
                <div className="col-span-2">
                  <span className="text-slate-500 text-[9px] uppercase tracking-wider block">INGRESS TIMESTAMP</span>
                  <span className="text-slate-300 text-xs">{selectedAlert.timestamp}</span>
                </div>
              </div>

              <div className="space-y-1 text-xs">
                <span className="text-slate-500 font-mono text-[9px] uppercase tracking-wider block">SOURCE SOCKET / CLUSTER</span>
                <div className="bg-[#050508] p-2 rounded border border-slate-800 font-mono text-slate-200 text-xs">
                  {selectedAlert.source || 'Unknown'}
                </div>
              </div>

              <div className="space-y-1 text-xs">
                <span className="text-slate-500 font-mono text-[9px] uppercase tracking-wider block">PROTECTED DESTINATION TARGET</span>
                <div className="bg-[#050508] p-2 rounded border border-slate-800 font-mono text-blue-400 text-xs">
                  {selectedAlert.destination || (selectedAlert as any).target || 'Unknown VIP'}
                </div>
              </div>

              {/* Supporting Evidence */}
              <div className="space-y-1 text-xs">
                <span className="text-slate-400 font-mono font-bold uppercase text-[10px] tracking-wider flex items-center gap-1">
                  <FileCheck className="w-3.5 h-3.5 text-blue-400" />
                  Supporting Evidence:
                </span>
                <ul className="bg-[#050508] p-2.5 rounded border border-slate-800 space-y-1.5 text-slate-300 text-xs">
                  {(selectedAlert.supportingEvidence || (selectedAlert as any).evidence || []).map((ev: string, i: number) => (
                    <li key={i} className="flex items-start gap-2">
                      <span className="text-blue-400 font-bold mt-0.5">•</span>
                      <span className="text-xs text-slate-300">{ev}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Detection Method */}
              <div className="space-y-1 text-xs">
                <span className="text-slate-400 font-mono font-bold uppercase text-[10px] tracking-wider flex items-center gap-1">
                  <Shield className="w-3.5 h-3.5 text-purple-400" />
                  Detection Method:
                </span>
                <div className="bg-[#050508] p-2 rounded border border-slate-800 text-slate-300 font-mono text-[11px]">
                  {selectedAlert.detectionMethod}
                </div>
              </div>

              {/* Triage Status Actions */}
              <div className="pt-2 border-t border-slate-800 space-y-2">
                <span className="text-[9px] font-mono text-slate-500 uppercase tracking-wider block">SecOps Analyst Triage:</span>
                <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                  <button
                    onClick={() => onUpdateAlertStatus(selectedAlert.id, 'Investigating')}
                    className="px-2 py-1 rounded bg-[#11111d] hover:bg-slate-800 text-amber-300 border border-slate-700 text-[10px] uppercase tracking-wider transition cursor-pointer"
                  >
                    Investigating
                  </button>
                  <button
                    onClick={() => onUpdateAlertStatus(selectedAlert.id, 'Verified')}
                    className="px-2 py-1 rounded bg-[#11111d] hover:bg-slate-800 text-red-400 border border-slate-700 text-[10px] uppercase tracking-wider transition cursor-pointer"
                  >
                    Verify Threat
                  </button>
                  <button
                    onClick={() => onUpdateAlertStatus(selectedAlert.id, 'Mitigated')}
                    className="px-2 py-1 rounded bg-[#11111d] hover:bg-slate-800 text-green-400 border border-slate-700 text-[10px] uppercase tracking-wider transition cursor-pointer"
                  >
                    Mark Handled
                  </button>
                  <button
                    onClick={() => onUpdateAlertStatus(selectedAlert.id, 'False Positive')}
                    className="px-2 py-1 rounded bg-[#11111d] hover:bg-slate-800 text-slate-400 border border-slate-700 text-[10px] uppercase tracking-wider transition cursor-pointer"
                  >
                    False Positive
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="text-center py-12 text-slate-500 text-xs font-mono">
              Select an alert from the table to inspect forensic evidence.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
