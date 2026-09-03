/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/common/Header';
import { Navigation, ActiveTab } from './components/common/Navigation';
import { OneWayDiodeBanner } from './components/common/OneWayDiodeBanner';
import { DashboardView } from './components/dashboard/DashboardView';
import { LiveTrafficView } from './components/traffic/LiveTrafficView';
import { DDoSView } from './components/ddos/DDoSView';
import { C2BeaconView } from './components/c2/C2BeaconView';
import { ThreatIntelView } from './components/intel/ThreatIntelView';
import { AlertsView } from './components/alerts/AlertsView';
import { ForensicsView } from './components/forensics/ForensicsView';
import { SystemStatusView } from './components/system/SystemStatusView';
import {
  TelemetryMetrics,
  TrafficTimePoint,
  NetworkPacket,
  SecurityAlert,
  SimulationScenario,
  C2BeaconCandidate,
  ThreatIntelligenceRecord,
  AlertStatus
} from './types';
import {
  SIMULATION_SCENARIOS,
  INITIAL_ALERTS,
  INITIAL_C2_BEACONS,
  INITIAL_INTEL_RECORDS,
  generateInitialTimeline,
  generateSimulatedPacket
} from './services/networkSimulator';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [activeScenario, setActiveScenario] = useState<SimulationScenario>(SIMULATION_SCENARIOS[0]);
  const [isStreaming, setIsStreaming] = useState<boolean>(true);
  const [isDiodeBannerOpen, setIsDiodeBannerOpen] = useState<boolean>(true);

  // Core SOC State
  const [alerts, setAlerts] = useState<SecurityAlert[]>(INITIAL_ALERTS);
  const [selectedAlertForInvestigation, setSelectedAlertForInvestigation] = useState<SecurityAlert | null>(null);
  const [timeline, setTimeline] = useState<TrafficTimePoint[]>(generateInitialTimeline());
  const [packets, setPackets] = useState<NetworkPacket[]>(() => {
    const initPkts: NetworkPacket[] = [];
    for (let i = 0; i < 35; i++) {
      initPkts.push(generateSimulatedPacket(SIMULATION_SCENARIOS[0]));
    }
    return initPkts;
  });
  const [beacons, setBeacons] = useState<C2BeaconCandidate[]>(INITIAL_C2_BEACONS);
  const [intelRecords] = useState<ThreatIntelligenceRecord[]>(INITIAL_INTEL_RECORDS);

  const [telemetry, setTelemetry] = useState<TelemetryMetrics>({
    monitoringStatus: 'ACTIVE_ONE_WAY',
    totalPackets: 1849204000,
    totalBytes: 1420800000000,
    packetsPerSecond: 48500,
    bytesPerSecond: 263840000,
    activeThreatsCount: 1,
    criticalAlertsCount: INITIAL_ALERTS.filter(a => a.severity === 'Critical').length,
    averageAiConfidence: 96.4,
    sourceIPEntropy: 3.72,
    destinationConcentration: 0.32,
    diodeReversePacketsTransmitted: 0, // Hardwired physical invariant
    diodeOpticalRxPowerDbm: -14.2,
    diodeTxHardwareDisabled: true,
    pipelineLatencyMs: 0.84,
    mlInferenceLatencyMs: 2.15
  });

  // Scenario switch handler
  const handleSelectScenario = async (scenarioId: string) => {
    const found = SIMULATION_SCENARIOS.find((s) => s.id === scenarioId);
    if (!found) return;

    setActiveScenario(found);

    // Call server endpoint if available
    try {
      await fetch('/api/simulate/scenario', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenarioId })
      });
    } catch {
      // Offline fallback already updated activeScenario locally
    }

    // Prepend a realistic alert if an attack scenario was triggered
    if (found.activeThreat) {
      const newAlert: SecurityAlert = {
        id: `ALT-2026-${Math.floor(1000 + Math.random() * 9000)}`,
        threatType: found.activeThreat,
        severity: 'Critical',
        confidenceScore: Math.floor(92 + Math.random() * 7),
        timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
        source: found.id === 'syn-flood' ? '198.51.100.0/24 (Volumetric Botnet)' :
                found.id === 'udp-amplification' ? 'Public NTP Amplifiers (Port 123)' :
                found.id === 'spoofed-source' ? 'Forged Bogon Subnets (100.64.0.0/10)' :
                found.id === 'c2-beacon' ? '10.0.4.118 (Workstation-Finance-02)' : '10.0.2.45 (Internal Dev)',
        destination: found.targetService,
        protocol: found.id === 'syn-flood' ? 'TCP' :
                  found.id === 'udp-amplification' ? 'NTP' :
                  found.id === 'spoofed-source' ? 'UDP' :
                  found.id === 'c2-beacon' ? 'TLS' : 'TCP',
        supportingEvidence: [
          `Active scenario trigger: ${found.name}`,
          `Traffic multiplier escalated to ${found.trafficMultiplier}x baseline`,
          'Passive feature extraction pipeline detected statistical anomaly threshold breach',
          'Zero mitigation back-channel opened (Enclave isolation intact)'
        ],
        detectionMethod: 'Passive Feature Extraction & Ensemble Classifier',
        status: 'New',
        packetRate: Math.floor(250000 * found.trafficMultiplier),
        bandwidthRate: `${(found.trafficMultiplier * 3.4).toFixed(1)} Gbps`,
        mitreTechnique: 'T1498 - Denial of Service'
      };
      setAlerts((prev) => [newAlert, ...prev]);
    }
  };

  // Alert status update handler
  const handleUpdateAlertStatus = async (alertId: string, newStatus: AlertStatus) => {
    setAlerts((prev) =>
      prev.map((a) => (a.id === alertId ? { ...a, status: newStatus } : a))
    );
    try {
      await fetch(`/api/alerts/${alertId}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      });
    } catch {
      // Local state already updated
    }
  };

  // Cross-tab alert investigation
  const handleInvestigateAlert = (alert: SecurityAlert) => {
    setSelectedAlertForInvestigation(alert);
    setActiveTab('alerts');
  };

  // Real-time background simulation & polling loop
  useEffect(() => {
    if (!isStreaming) return;

    const interval = setInterval(() => {
      // Generate realistic packet flow
      const newPacket = generateSimulatedPacket(activeScenario);
      setPackets((prev) => [newPacket, ...prev.slice(0, 50)]);

      // Update timeline
      const now = new Date();
      const timeStr = now.toTimeString().substring(0, 8);
      const mult = activeScenario.trafficMultiplier;
      const basePPS = Math.floor((42000 + Math.random() * 8000) * mult);

      let entropy = 3.65 + Math.random() * 0.4;
      let concentration = 0.32;

      if (activeScenario.id === 'spoofed-source') {
        entropy = 7.75 + Math.random() * 0.2;
        concentration = 0.74;
      } else if (activeScenario.id === 'syn-flood') {
        entropy = 6.85 + Math.random() * 0.3;
        concentration = 0.88;
      } else if (activeScenario.id === 'udp-amplification') {
        entropy = 5.62;
        concentration = 0.91;
      }

      const tcpRatio = activeScenario.id === 'syn-flood' ? 0.88 : 0.62;
      const udpRatio = activeScenario.id === 'udp-amplification' || activeScenario.id === 'spoofed-source' ? 0.76 : 0.24;

      setTimeline((prev) => {
        const next = [
          ...prev,
          {
            time: timeStr,
            totalPPS: basePPS,
            tcpPPS: Math.floor(basePPS * tcpRatio),
            udpPPS: Math.floor(basePPS * udpRatio),
            icmpPPS: Math.floor(basePPS * 0.03),
            otherPPS: Math.floor(basePPS * 0.08),
            mbps: Number(((basePPS * 720 * 8) / 1000000).toFixed(1)),
            entropy: Number(entropy.toFixed(2))
          }
        ];
        return next.slice(-25);
      });

      // Update telemetry
      const pps = Math.floor(48500 * mult + Math.random() * 2500);
      const bps = pps * 680 * 8;
      setTelemetry((prev) => ({
        ...prev,
        packetsPerSecond: pps,
        bytesPerSecond: bps,
        totalPackets: prev.totalPackets + pps * 2,
        totalBytes: prev.totalBytes + bps / 4,
        sourceIPEntropy: Number(entropy.toFixed(2)),
        destinationConcentration: Number(concentration.toFixed(2)),
        activeThreatsCount: activeScenario.activeThreat ? 4 : 1,
        criticalAlertsCount: alerts.filter((a) => a.severity === 'Critical' && a.status !== 'Mitigated').length,
        averageAiConfidence: activeScenario.activeThreat ? 95.2 : 98.4,
        diodeReversePacketsTransmitted: 0 // Hardwired physical invariant
      }));
    }, 2000);

    return () => clearInterval(interval);
  }, [isStreaming, activeScenario, alerts]);

  return (
    <div className="min-h-screen bg-[#050508] text-slate-200 flex flex-col font-sans">
      {/* 1. Master SOC Header */}
      <Header
        telemetry={telemetry}
        activeScenario={activeScenario}
        scenarios={SIMULATION_SCENARIOS}
        onSelectScenario={handleSelectScenario}
        isStreaming={isStreaming}
        onToggleStreaming={() => setIsStreaming((prev) => !prev)}
        onToggleDiodeBanner={() => setIsDiodeBannerOpen((prev) => !prev)}
        isDiodeBannerOpen={isDiodeBannerOpen}
      />

      {/* 2. Unidirectional Data Diode Architecture Banner */}
      <OneWayDiodeBanner isOpen={isDiodeBannerOpen} />

      {/* 3. Navigation Bar (8 SOC Sections) */}
      <Navigation
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        criticalAlertsCount={telemetry.criticalAlertsCount}
        activeThreatsCount={telemetry.activeThreatsCount}
      />

      {/* 4. Active Section Content View */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 space-y-4">
        {activeTab === 'dashboard' && (
          <DashboardView
            telemetry={telemetry}
            timeline={timeline}
            alerts={alerts}
            activeScenario={activeScenario}
            onNavigateTab={setActiveTab}
            onSelectAlert={handleInvestigateAlert}
          />
        )}

        {activeTab === 'traffic' && (
          <LiveTrafficView
            packets={packets}
            isStreaming={isStreaming}
            onToggleStreaming={() => setIsStreaming((prev) => !prev)}
            activeScenario={activeScenario}
          />
        )}

        {activeTab === 'ddos' && (
          <DDoSView activeScenario={activeScenario} />
        )}

        {activeTab === 'c2' && (
          <C2BeaconView beacons={beacons} activeScenario={activeScenario} />
        )}

        {activeTab === 'intel' && (
          <ThreatIntelView intelRecords={intelRecords} />
        )}

        {activeTab === 'alerts' && (
          <AlertsView
            alerts={alerts}
            onUpdateAlertStatus={handleUpdateAlertStatus}
            initialSelectedAlert={selectedAlertForInvestigation}
          />
        )}

        {activeTab === 'forensics' && (
          <ForensicsView />
        )}

        {activeTab === 'system' && (
          <SystemStatusView telemetry={telemetry} />
        )}
      </main>

      {/* SOC Global Footer (Immersive UI specification) */}
      <footer className="h-9 bg-[#0a0a12] border-t border-slate-800/60 px-4 sm:px-6 flex items-center justify-between text-[10px] font-mono text-slate-500 uppercase tracking-widest select-none">
        <div className="flex items-center gap-2.5">
          <div className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse" />
          <span className="font-bold text-slate-300">ONEWAYSENTINEL AI</span>
          <span className="hidden md:inline text-slate-700">|</span>
          <span className="hidden md:inline text-slate-400">PASSIVE MONITORING ENCLAVE ACTIVE</span>
          <span className="hidden lg:inline text-slate-700">|</span>
          <span className="hidden lg:inline text-blue-400">REVERSE EGRESS: 0 BPS (INVARIANT)</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-slate-400">SIH-2026 PROTOTYPE // INTERNAL USE ONLY</span>
        </div>
      </footer>
    </div>
  );
}
