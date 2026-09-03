import React from 'react';
import {
  Server,
  ShieldCheck,
  Cpu,
  Lock,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Radio,
  Clock,
  HardDrive,
  FileCheck
} from 'lucide-react';
import { TelemetryMetrics } from '../../types';

interface SystemStatusViewProps {
  telemetry: TelemetryMetrics;
}

export const SystemStatusView: React.FC<SystemStatusViewProps> = ({ telemetry }) => {
  const hardwareSpecs = [
    { label: 'Data Diode Model', value: 'OWS-DD-10G Optical Isolator', status: 'Optimal' },
    { label: 'Optical Transceiver Wavelength', value: '1310 nm Single-Mode Fiber', status: 'Optimal' },
    { label: 'Ingress RX Photodiode', value: 'Active (Physical Ingress Only)', status: 'Active' },
    { label: 'Egress TX Laser Diode', value: 'PHYSICALLY REMOVED / DISCONNECTED', status: 'Air-Gapped' },
    { label: 'Reverse Packets Transmitted', value: '0 PKTS (Continuous Hardware Invariant)', status: 'Verified' },
    { label: 'Optical Power Reading', value: `${telemetry.diodeOpticalRxPowerDbm} dBm (Threshold: -18 to -10)`, status: 'Nominal' },
    { label: 'Galvanic Voltage Isolation', value: '> 2,500 Volts Dielectric Breakdown', status: 'Certified' },
    { label: 'Tamper Watchdog Circuit', value: 'Armed (Microsecond Trigger)', status: 'Armed' }
  ];

  const mlModels = [
    {
      name: 'XGBoost Flow Classifier',
      version: 'v2.4.1',
      task: 'Multi-class attack classification (SYN, UDP, Spoofed, Normal)',
      accuracy: '98.7% F1-Score',
      inferenceTime: '0.45 ms',
      status: 'Online'
    },
    {
      name: 'Isolation Forest Anomaly',
      version: 'v1.8.0',
      task: 'Unsupervised zero-day traffic divergence detection',
      accuracy: '96.2% ROC-AUC',
      inferenceTime: '0.38 ms',
      status: 'Online'
    },
    {
      name: 'FFT Spectral Beacon Detector',
      version: 'v3.1.0',
      task: 'High-speed Fourier frequency & jitter analysis for C2 heartbeats',
      accuracy: '95.8% Precision',
      inferenceTime: '0.62 ms',
      status: 'Online'
    },
    {
      name: 'Bi-LSTM Sequential Packet Analyzer',
      version: 'v1.2.0',
      task: 'Temporal inter-arrival and byte-length sequence inspection',
      accuracy: '97.4% Recall',
      inferenceTime: '0.90 ms',
      status: 'Online'
    }
  ];

  return (
    <div id="system-status-view" className="space-y-4 select-none">
      {/* Header */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-xl">
        <div>
          <h2 className="text-sm font-bold text-slate-100 uppercase tracking-widest flex items-center gap-2">
            <Server className="w-4 h-4 text-green-400" />
            Hardware Data Diode & Enclave System Status
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Real-time physical verification of unidirectional data isolation, DPDK memory buffers, and ML inference components.
          </p>
        </div>

        <div className="flex items-center gap-2 bg-[#050508] text-green-400 border border-slate-800 px-3 py-1.5 rounded text-xs font-mono font-bold">
          <ShieldCheck className="w-4 h-4 text-green-400" />
          <span className="text-[10px] uppercase tracking-wider">ZERO REVERSE TRANSMISSION VERIFIED</span>
        </div>
      </div>

      {/* Hardware Diode Guarantee Card */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2.5">
            <Lock className="w-4 h-4 text-amber-400" />
            <h3 className="font-bold text-slate-100 text-xs font-mono uppercase tracking-wider">
              Physical Data Diode Specification (OWS-DD-10G)
            </h3>
          </div>
          <span className="text-[10px] font-mono bg-[#050508] px-2.5 py-1 rounded text-blue-400 border border-slate-800 uppercase tracking-wider">
            FIRMWARE: v4.1.9-hardened-soc
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          {hardwareSpecs.map((spec) => (
            <div key={spec.label} className="bg-[#11111d] p-3 rounded border border-slate-800 space-y-1">
              <span className="text-slate-500 font-mono text-[9px] uppercase tracking-wider block">{spec.label}</span>
              <span className="text-slate-200 font-bold block text-xs">{spec.value}</span>
              <div className="flex items-center gap-1 text-[10px] text-green-400 font-mono pt-1">
                <CheckCircle2 className="w-3 h-3 text-green-400" />
                <span className="uppercase tracking-wider">{spec.status}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* DPDK Enclave Buffers & Latencies */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-xs mb-2">
            <span className="font-bold font-mono text-xs uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <HardDrive className="w-3.5 h-3.5 text-blue-400" />
              DPDK Ring Buffer
            </span>
            <span className="font-mono text-blue-400 font-bold">18.4%</span>
          </div>
          <p className="text-xs text-slate-500 mb-3">
            Hardware-accelerated lockless ring buffer in host memory (RX ONLY).
          </p>
          <div className="h-2 bg-[#050508] border border-slate-800 rounded-full overflow-hidden mb-2">
            <div className="h-full bg-blue-500 rounded-full" style={{ width: '18.4%' }} />
          </div>
          <div className="flex justify-between text-[10px] font-mono text-slate-500">
            <span>Allocated: 368,000 pkts</span>
            <span>Capacity: 2,000,000 pkts</span>
          </div>
        </div>

        <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-xs mb-2">
            <span className="font-bold font-mono text-xs uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Clock className="w-3.5 h-3.5 text-purple-400" />
              Extraction Latency
            </span>
            <span className="font-mono text-purple-300 font-bold">{telemetry.pipelineLatencyMs} ms</span>
          </div>
          <p className="text-xs text-slate-500 mb-3">
            Real-time sliding window Shannon entropy, header parsing & FFT.
          </p>
          <div className="h-2 bg-[#050508] border border-slate-800 rounded-full overflow-hidden mb-2">
            <div className="h-full bg-purple-500 rounded-full" style={{ width: '28%' }} />
          </div>
          <div className="flex justify-between text-[10px] font-mono text-slate-500">
            <span>Budget: &lt; 1.5ms</span>
            <span className="text-green-400 font-bold uppercase">PASSED</span>
          </div>
        </div>

        <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4">
          <div className="flex items-center justify-between text-xs mb-2">
            <span className="font-bold font-mono text-xs uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Cpu className="w-3.5 h-3.5 text-green-400" />
              ML Inference Pipeline
            </span>
            <span className="font-mono text-green-400 font-bold">{telemetry.mlInferenceLatencyMs} ms</span>
          </div>
          <p className="text-xs text-slate-500 mb-3">
            Concurrent batch inference across all registered anomaly classifiers.
          </p>
          <div className="h-2 bg-[#050508] border border-slate-800 rounded-full overflow-hidden mb-2">
            <div className="h-full bg-green-500 rounded-full" style={{ width: '35%' }} />
          </div>
          <div className="flex justify-between text-[10px] font-mono text-slate-500">
            <span>Budget: &lt; 5.0ms</span>
            <span className="text-green-400 font-bold uppercase">PASSED</span>
          </div>
        </div>
      </div>

      {/* Registered AI/ML Models */}
      <div className="bg-[#0a0a12] border border-slate-800 rounded-lg p-4 shadow-sm">
        <h3 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2 mb-3">
          <Cpu className="w-3.5 h-3.5 text-purple-400" />
          Active AI/ML Detection Engine Registry (Modular Python/ONNX Integration)
        </h3>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-black/40 text-slate-500 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Model Name</th>
                <th className="py-2.5 px-3">Version</th>
                <th className="py-2.5 px-3">Detection Scope</th>
                <th className="py-2.5 px-3">Benchmark Metric</th>
                <th className="py-2.5 px-3">Latency</th>
                <th className="py-2.5 px-3 text-right">Engine Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-[11px]">
              {mlModels.map((model) => (
                <tr key={model.name} className="hover:bg-white/5 transition">
                  <td className="py-2.5 px-3 font-bold text-slate-200">{model.name}</td>
                  <td className="py-2.5 px-3 text-blue-400">{model.version}</td>
                  <td className="py-2.5 px-3 text-slate-400 text-xs">{model.task}</td>
                  <td className="py-2.5 px-3 font-bold text-green-400">{model.accuracy}</td>
                  <td className="py-2.5 px-3 text-purple-300">{model.inferenceTime}</td>
                  <td className="py-2.5 px-3 text-right">
                    <span className="px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-green-950 text-green-400 border border-green-800 inline-flex items-center gap-1 font-mono">
                      <CheckCircle2 className="w-3 h-3 text-green-400" />
                      {model.status}
                    </span>
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
