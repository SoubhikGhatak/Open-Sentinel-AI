import React, { useState, useRef, useMemo } from 'react';
import {
  Upload,
  FileCode,
  FileSpreadsheet,
  FileText,
  Activity,
  Layers,
  ShieldCheck,
  ShieldAlert,
  Sliders,
  RefreshCw,
  Search,
  Download,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Info,
  Radio,
  Clock,
  BarChart3,
  HardDrive
} from 'lucide-react';
import {
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';
import {
  FeatureVector,
  PassiveObservation,
  SlidingWindowConfig,
  PassiveDatasetSummary,
  IngestionValidationSummary
} from '../../detection/ingestion/types';
import {
  processUploadedFile,
  processPassiveObservations,
  ProcessedIngestionPayload
} from '../../detection/ingestion/validator';
import {
  SAMPLE_DATASET_DEFINITIONS,
  getSamplePassiveDataset,
  observationsToCsv,
  observationsToJson
} from '../../detection/ingestion/sampleDatasets';
import { evaluateFeatureVector } from '../../detection/ingestion/passiveEvaluator';
import { extractWindowFeatures } from '../../detection/ingestion/timeWindowAnalyzer';

interface PassiveIngestionViewProps {
  onTransferToPipeline?: (observations: PassiveObservation[], sourceName: string) => void;
}

export const PassiveIngestionView: React.FC<PassiveIngestionViewProps> = ({
  onTransferToPipeline
}) => {
  // Window Configuration (Default: 10s window, 5s step)
  const [windowConfig, setWindowConfig] = useState<SlidingWindowConfig>({
    windowDurationSeconds: 10,
    stepSeconds: 5
  });

  // Current Active Dataset & Mode
  const [dataSourceMode, setDataSourceMode] = useState<'SIMULATION' | 'PASSIVE_FILE'>(
    'PASSIVE_FILE'
  );
  const [selectedDatasetId, setSelectedDatasetId] = useState<string>('sample-syn-flood');
  const [currentFilename, setCurrentFilename] = useState<string>('syn_flood_capture.pcap');

  // Observations & Extraction Results
  const [rawObservations, setRawObservations] = useState<PassiveObservation[]>(() => {
    return getSamplePassiveDataset('sample-syn-flood').observations;
  });

  const [validationSummary, setValidationSummary] = useState<IngestionValidationSummary>({
    success: true,
    sourceType: 'PCAP',
    filename: 'syn_flood_capture.pcap',
    validRecords: 42,
    invalidRecords: 0,
    totalRecordsProcessed: 42,
    parseErrors: [],
    timeRange: {
      start: new Date(Date.now() - 60000).toISOString().substring(11, 19),
      end: new Date().toISOString().substring(11, 19),
      durationSeconds: 46.2
    }
  });

  const [featureData, setFeatureData] = useState<{
    featureVectors: FeatureVector[];
    summary: PassiveDatasetSummary;
  }>(() => {
    const initObs = getSamplePassiveDataset('sample-syn-flood').observations;
    return extractWindowFeatures(initObs, { windowDurationSeconds: 10, stepSeconds: 5 });
  });

  // UI state
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [selectedVectorId, setSelectedVectorId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const [showConfigPanel, setShowConfigPanel] = useState<boolean>(false);
  const [showErrorsDrawer, setShowErrorsDrawer] = useState<boolean>(false);
  const [transferNotice, setTransferNotice] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Re-run window extraction when config changes or user clicks Recompute
  const handleRecomputeWindows = () => {
    setIsProcessing(true);
    setTimeout(() => {
      const result = extractWindowFeatures(rawObservations, windowConfig);
      setFeatureData(result);
      setIsProcessing(false);
    }, 150);
  };

  // Load a built-in sample dataset
  const handleLoadSample = (sampleId: string) => {
    setIsProcessing(true);
    setSelectedDatasetId(sampleId);
    const sample = getSamplePassiveDataset(sampleId);
    setDataSourceMode('PASSIVE_FILE');
    setCurrentFilename(`${sampleId}.dat`);
    setRawObservations(sample.observations);

    const result = extractWindowFeatures(sample.observations, windowConfig);
    setFeatureData(result);

    setValidationSummary({
      success: true,
      sourceType: sample.meta.format,
      filename: `${sampleId}.${sample.meta.format.toLowerCase()}`,
      validRecords: sample.observations.length,
      invalidRecords: 0,
      totalRecordsProcessed: sample.observations.length,
      parseErrors: [],
      timeRange: {
        start: result.summary.timeRangeStart.substring(11, 19),
        end: result.summary.timeRangeEnd.substring(11, 19),
        durationSeconds: 45
      }
    });

    setSelectedVectorId(null);
    setIsProcessing(false);
  };

  // Handle uploaded file
  const handleFileUpload = async (file: File) => {
    setIsProcessing(true);
    try {
      const payload: ProcessedIngestionPayload = await processUploadedFile(file, windowConfig);
      setValidationSummary(payload.validation);

      if (payload.validation.success && payload.observations.length > 0) {
        setRawObservations(payload.observations);
        setFeatureData({
          featureVectors: payload.featureVectors,
          summary: payload.summary
        });
        setDataSourceMode('PASSIVE_FILE');
        setCurrentFilename(file.name);
        setSelectedDatasetId('custom-upload');
        setSelectedVectorId(null);
      } else {
        setShowErrorsDrawer(true);
      }
    } catch (err: any) {
      setValidationSummary({
        success: false,
        sourceType: 'PCAP',
        filename: file.name,
        validRecords: 0,
        invalidRecords: 1,
        totalRecordsProcessed: 1,
        parseErrors: [err?.message || 'Failed to read or parse the uploaded file.']
      });
      setShowErrorsDrawer(true);
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  // Export feature vectors as JSON or CSV
  const handleExportFeatures = (format: 'JSON' | 'CSV') => {
    let content = '';
    let mimeType = 'text/plain';
    let filename = `OneWaySentinel_Features_${Date.now()}.${format.toLowerCase()}`;

    if (format === 'JSON') {
      content = JSON.stringify(
        {
          metadata: {
            app: 'OneWaySentinel AI',
            mode: dataSourceMode,
            sourceFile: currentFilename,
            windowConfig,
            generatedAt: new Date().toISOString()
          },
          summary: featureData.summary,
          featureVectors: featureData.featureVectors
        },
        null,
        2
      );
      mimeType = 'application/json';
    } else {
      const headers = [
        'windowIndex',
        'timestamp',
        'sourceIp',
        'destinationIp',
        'protocol',
        'packetCount',
        'byteCount',
        'packetsPerSecond',
        'bytesPerSecond',
        'synPacketCount',
        'ackPacketCount',
        'synToAckRatio',
        'uniqueSourceIpCount',
        'sourceIpEntropy',
        'destinationConcentrationHHI',
        'trafficGrowthRate',
        'interArrivalTimeMean',
        'periodicityScore',
        'jitterPercentage'
      ];
      const rows = featureData.featureVectors.map((f) =>
        [
          f.windowIndex,
          f.timestamp,
          f.sourceIp,
          f.destinationIp,
          f.protocol,
          f.packetCount,
          f.byteCount,
          f.packetsPerSecond,
          f.bytesPerSecond,
          f.synPacketCount,
          f.ackPacketCount,
          f.synToAckRatio,
          f.uniqueSourceIpCount,
          f.sourceIpEntropy,
          f.destinationConcentration,
          f.trafficGrowthRate,
          f.interArrivalTimeMean,
          f.periodicityScore,
          f.jitterPercentage
        ].join(',')
      );
      content = [headers.join(','), ...rows].join('\n');
      mimeType = 'text/csv';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  // Transfer to pipeline
  const handleTransfer = () => {
    if (onTransferToPipeline && rawObservations.length > 0) {
      onTransferToPipeline(rawObservations, currentFilename);
      setTransferNotice(`Successfully dispatched ${rawObservations.length} passive flow records to master Detection Engine! Check Live Traffic, DDoS Detection, or Alerts.`);
      setTimeout(() => setTransferNotice(null), 7000);
    }
  };

  // Filter feature vectors
  const filteredVectors = useMemo(() => {
    return featureData.featureVectors.filter((v) => {
      const matchesSearch =
        searchQuery === '' ||
        v.sourceSummary.toLowerCase().includes(searchQuery.toLowerCase()) ||
        v.destinationSummary.toLowerCase().includes(searchQuery.toLowerCase()) ||
        v.protocol.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (v.detectedThreatIndicator && v.detectedThreatIndicator.toLowerCase().includes(searchQuery.toLowerCase()));

      const matchesProto = protocolFilter === 'ALL' || v.protocol.toUpperCase() === protocolFilter.toUpperCase();
      return matchesSearch && matchesProto;
    });
  }, [featureData.featureVectors, searchQuery, protocolFilter]);

  // Selected Vector Details
  const activeSelectedVector = useMemo(() => {
    if (!selectedVectorId) return null;
    return featureData.featureVectors.find((v) => v.id === selectedVectorId) || null;
  }, [selectedVectorId, featureData.featureVectors]);

  const activeDetectionResult = useMemo(() => {
    if (!activeSelectedVector) return null;
    return evaluateFeatureVector(activeSelectedVector);
  }, [activeSelectedVector]);

  // Timeline chart data across windows
  const windowTimelineData = useMemo(() => {
    return featureData.featureVectors.map((f) => ({
      name: `W${f.windowIndex}`,
      time: f.timestamp,
      pps: f.packetsPerSecond,
      bpsKb: Math.round(f.bytesPerSecond / 1024),
      syn: f.synPacketCount,
      entropy: f.sourceIpEntropy,
      periodicity: Number((f.periodicityScore * 10).toFixed(1))
    }));
  }, [featureData.featureVectors]);

  return (
    <div className="space-y-6">
      {/* Top Banner: One-Way Diode Architecture Guarantee & Data Source Indicator */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 backdrop-blur shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-emerald-500/5 rounded-full filter blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className="p-3 bg-emerald-950/60 border border-emerald-500/30 rounded-xl text-emerald-400 mt-1">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-3 flex-wrap">
                <h1 className="text-xl font-bold text-white tracking-wide">
                  PASSIVE DATA INGESTION & FEATURE EXTRACTION
                </h1>
                {/* Data Source Indicator */}
                <div
                  className={`px-3 py-1 rounded-full text-xs font-mono font-bold tracking-wider flex items-center gap-2 border ${
                    dataSourceMode === 'PASSIVE_FILE'
                      ? 'bg-emerald-950/80 border-emerald-500/40 text-emerald-300'
                      : 'bg-amber-950/80 border-amber-500/40 text-amber-300'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                  DATA SOURCE: {dataSourceMode === 'PASSIVE_FILE' ? 'PASSIVE FILE ANALYSIS' : 'SIMULATION MODE'}
                </div>
                <span className="text-xs bg-slate-800 text-slate-300 px-2.5 py-0.5 rounded font-mono">
                  {currentFilename}
                </span>
              </div>
              <p className="text-sm text-slate-400 mt-1 max-w-4xl leading-relaxed">
                <span className="text-emerald-400 font-semibold">Strictly Passive Optical Monitor:</span> TX physical fiber disabled.
                Zero active scans, zero probes, zero TCP handshakes, and zero reverse packets to monitored endpoints.
                Ingests PCAP binary metadata, CSV flow logs, or JSON/JSONL streams and computes mathematical features across sliding time-windows.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 self-end lg:self-center flex-wrap">
            <button
              onClick={() => setShowConfigPanel(!showConfigPanel)}
              className="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium border border-slate-700 flex items-center gap-2 transition"
              title="Configure window length and step"
            >
              <Sliders className="w-3.5 h-3.5 text-cyan-400" />
              <span>Window: {windowConfig.windowDurationSeconds}s / {windowConfig.stepSeconds}s</span>
              {showConfigPanel ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            </button>

            {onTransferToPipeline && (
              <button
                onClick={handleTransfer}
                disabled={rawObservations.length === 0}
                className="px-3.5 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-lg text-xs font-semibold shadow-lg shadow-cyan-600/20 flex items-center gap-2 transition"
              >
                <Activity className="w-3.5 h-3.5" />
                <span>Dispatch to Detection Engine</span>
              </button>
            )}
          </div>
        </div>

        {/* Sliding Window Configuration Slider Panel */}
        {showConfigPanel && (
          <div className="mt-4 pt-4 border-t border-slate-800/80 grid grid-cols-1 md:grid-cols-3 gap-4 bg-slate-950/60 p-4 rounded-lg">
            <div>
              <label className="text-xs font-medium text-slate-300 flex justify-between">
                <span>Sliding Window Duration</span>
                <span className="text-cyan-400 font-mono">{windowConfig.windowDurationSeconds} seconds</span>
              </label>
              <input
                type="range"
                min="2"
                max="60"
                step="1"
                value={windowConfig.windowDurationSeconds}
                onChange={(e) =>
                  setWindowConfig((prev) => ({
                    ...prev,
                    windowDurationSeconds: Number(e.target.value)
                  }))
                }
                className="w-full mt-2 accent-cyan-500 bg-slate-800 rounded-lg cursor-pointer"
              />
              <div className="flex justify-between text-[10px] text-slate-400 mt-1 font-mono">
                <span>2s (Instant)</span>
                <span>10s (Default)</span>
                <span>60s (Macro)</span>
              </div>
            </div>

            <div>
              <label className="text-xs font-medium text-slate-300 flex justify-between">
                <span>Sliding Step Size</span>
                <span className="text-cyan-400 font-mono">{windowConfig.stepSeconds} seconds</span>
              </label>
              <input
                type="range"
                min="1"
                max="30"
                step="1"
                value={windowConfig.stepSeconds}
                onChange={(e) =>
                  setWindowConfig((prev) => ({
                    ...prev,
                    stepSeconds: Number(e.target.value)
                  }))
                }
                className="w-full mt-2 accent-cyan-500 bg-slate-800 rounded-lg cursor-pointer"
              />
              <div className="flex justify-between text-[10px] text-slate-400 mt-1 font-mono">
                <span>1s (Continuous)</span>
                <span>5s (Default)</span>
                <span>30s (Sparse)</span>
              </div>
            </div>

            <div className="flex flex-col justify-between">
              <span className="text-xs text-slate-400">
                Preset: 10s window / 5s step guarantees sufficient temporal samples for discrete FFT periodicity detection.
              </span>
              <button
                onClick={handleRecomputeWindows}
                className="mt-2 w-full py-2 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded font-mono text-xs font-bold border border-slate-700 flex items-center justify-center gap-2 transition"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isProcessing ? 'animate-spin' : ''}`} />
                <span>Recompute Window Features</span>
              </button>
            </div>
          </div>
        )}

        {/* Transfer Confirmation Notice */}
        {transferNotice && (
          <div className="mt-4 p-3 bg-cyan-950/70 border border-cyan-500/40 rounded-lg flex items-center justify-between text-xs text-cyan-300">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
              <span>{transferNotice}</span>
            </div>
            <button
              onClick={() => setTransferNotice(null)}
              className="text-slate-400 hover:text-white text-xs font-mono"
            >
              Dismiss
            </button>
          </div>
        )}
      </div>

      {/* Ingestion Dropzone & Built-in Sample Datasets */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Dropzone & Upload Box */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`lg:col-span-5 border-2 border-dashed rounded-xl p-6 flex flex-col items-center justify-center text-center cursor-pointer transition relative group ${
            isDragging
              ? 'border-cyan-400 bg-cyan-950/20'
              : 'border-slate-800 hover:border-slate-700 bg-slate-900/60'
          }`}
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={(e) => {
              if (e.target.files && e.target.files.length > 0) {
                handleFileUpload(e.target.files[0]);
              }
            }}
            accept=".pcap,.cap,.csv,.txt,.json,.jsonl"
            className="hidden"
          />
          <div className="p-4 bg-slate-800/80 rounded-2xl text-cyan-400 group-hover:scale-110 group-hover:text-cyan-300 transition duration-200">
            <Upload className="w-8 h-8" />
          </div>
          <h3 className="text-white font-semibold text-sm mt-3">
            Drop Real Passive Telemetry File Here
          </h3>
          <p className="text-xs text-slate-400 mt-1 max-w-sm">
            Upload <span className="text-slate-200 font-mono font-semibold">.pcap</span> binary captures,{' '}
            <span className="text-slate-200 font-mono font-semibold">.csv</span> NetFlow/IPFIX logs, or{' '}
            <span className="text-slate-200 font-mono font-semibold">.json / .jsonl</span> flow exports.
          </p>
          <div className="flex items-center gap-3 mt-4 text-[11px] font-mono text-slate-400">
            <span className="flex items-center gap-1">
              <FileCode className="w-3.5 h-3.5 text-blue-400" /> PCAP
            </span>
            <span>•</span>
            <span className="flex items-center gap-1">
              <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" /> CSV
            </span>
            <span>•</span>
            <span className="flex items-center gap-1">
              <FileText className="w-3.5 h-3.5 text-amber-400" /> JSON / JSONL
            </span>
          </div>
        </div>

        {/* Built-in Sample Passive Datasets */}
        <div className="lg:col-span-7 bg-slate-900/60 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-bold text-white uppercase tracking-wider">
                Load Verified Sample Datasets
              </h2>
            </div>
            <span className="text-[11px] text-slate-400 font-mono">
              6 Built-in Scenarios (Passive Records)
            </span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 gap-2.5 mt-3">
            {SAMPLE_DATASET_DEFINITIONS.map((sample) => {
              const isSelected = selectedDatasetId === sample.id;
              return (
                <button
                  key={sample.id}
                  onClick={() => handleLoadSample(sample.id)}
                  className={`p-2.5 text-left rounded-lg border transition flex flex-col justify-between ${
                    isSelected
                      ? 'bg-cyan-950/60 border-cyan-500/60 text-white shadow-md'
                      : 'bg-slate-950/40 border-slate-800 hover:border-slate-700 text-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between w-full">
                    <span
                      className={`text-[10px] font-bold px-1.5 py-0.5 rounded font-mono ${
                        sample.category === 'Baseline'
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          : sample.category === 'DDoS'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : 'bg-purple-950 text-purple-300 border border-purple-800'
                      }`}
                    >
                      {sample.category}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">
                      {sample.format}
                    </span>
                  </div>
                  <div className="text-xs font-semibold mt-2 line-clamp-1 text-slate-100">
                    {sample.name}
                  </div>
                  <div className="text-[10px] text-slate-400 mt-1 line-clamp-2">
                    {sample.expectedThreat}
                  </div>
                </button>
              );
            })}
          </div>

          {/* Ingestion Validation Status */}
          <div className="mt-3 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              {validationSummary.success ? (
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
              )}
              <span className="text-slate-300">
                Parsed: <strong className="text-emerald-400">{validationSummary.validRecords}</strong> valid records
                {validationSummary.invalidRecords > 0 && (
                  <span className="text-rose-400 ml-1">
                    ({validationSummary.invalidRecords} invalid/skipped)
                  </span>
                )}
              </span>
            </div>

            {validationSummary.parseErrors.length > 0 && (
              <button
                onClick={() => setShowErrorsDrawer(!showErrorsDrawer)}
                className="text-amber-400 hover:text-amber-300 underline text-xs"
              >
                View Parser Diagnostics ({validationSummary.parseErrors.length})
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Parser Errors Drawer */}
      {showErrorsDrawer && validationSummary.parseErrors.length > 0 && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/60 rounded-xl text-xs text-rose-300 font-mono">
          <div className="flex items-center justify-between font-bold pb-2 border-b border-rose-900/60">
            <span>Parser Warning & Error Logs</span>
            <button onClick={() => setShowErrorsDrawer(false)} className="text-slate-400 hover:text-white">
              Close
            </button>
          </div>
          <ul className="mt-2 space-y-1 list-disc list-inside">
            {validationSummary.parseErrors.map((err, idx) => (
              <li key={idx} className="text-rose-200">
                {err}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Primary KPI Metrics Summary Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-slate-900/70 border border-slate-800 p-3.5 rounded-xl">
          <div className="text-[11px] text-slate-400 uppercase font-mono">Total Flows</div>
          <div className="text-xl font-bold text-white font-mono mt-1">
            {featureData.summary.totalFlows.toLocaleString()}
          </div>
          <div className="text-[10px] text-slate-400 mt-1 font-mono">
            {featureData.summary.timeRangeStart.substring(11, 19)} - {featureData.summary.timeRangeEnd.substring(11, 19)}
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 p-3.5 rounded-xl">
          <div className="text-[11px] text-slate-400 uppercase font-mono">Total Packets</div>
          <div className="text-xl font-bold text-cyan-300 font-mono mt-1">
            {featureData.summary.totalPackets.toLocaleString()}
          </div>
          <div className="text-[10px] text-slate-400 mt-1 font-mono">
            Avg {featureData.summary.averagePacketRate.toLocaleString()} PPS
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 p-3.5 rounded-xl">
          <div className="text-[11px] text-slate-400 uppercase font-mono">Total Ingress Volume</div>
          <div className="text-xl font-bold text-indigo-300 font-mono mt-1">
            {featureData.summary.totalBytes > 1048576
              ? `${(featureData.summary.totalBytes / 1048576).toFixed(1)} MB`
              : `${(featureData.summary.totalBytes / 1024).toFixed(1)} KB`}
          </div>
          <div className="text-[10px] text-slate-400 mt-1 font-mono">
            Avg {Math.round(featureData.summary.averageByteRate / 1024)} KB/s
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 p-3.5 rounded-xl">
          <div className="text-[11px] text-slate-400 uppercase font-mono">Unique IP Hosts</div>
          <div className="text-xl font-bold text-emerald-300 font-mono mt-1">
            {featureData.summary.uniqueSourceIps} <span className="text-xs text-slate-400 font-normal">src</span> /{' '}
            {featureData.summary.uniqueDestinationIps} <span className="text-xs text-slate-400 font-normal">dst</span>
          </div>
          <div className="text-[10px] text-slate-400 mt-1 font-mono">
            Shannon H(X): {featureData.summary.averageEntropy}
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 p-3.5 rounded-xl">
          <div className="text-[11px] text-slate-400 uppercase font-mono">Analysis Window</div>
          <div className="text-xl font-bold text-amber-300 font-mono mt-1">
            {windowConfig.windowDurationSeconds}s <span className="text-xs text-slate-400 font-normal">/ {windowConfig.stepSeconds}s step</span>
          </div>
          <div className="text-[10px] text-slate-400 mt-1 font-mono">
            {featureData.featureVectors.length} Extracted Windows
          </div>
        </div>

        <div className="bg-slate-900/70 border border-slate-800 p-3.5 rounded-xl">
          <div className="text-[11px] text-slate-400 uppercase font-mono">Protocols Ingested</div>
          <div className="flex flex-wrap gap-1 mt-1.5">
            {Object.entries(featureData.summary.protocolPercentages).map(([proto, pct]) => (
              <span
                key={proto}
                className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700"
              >
                {proto}: {pct}%
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Visualizer Chart: Windowed Metric Trends */}
      {windowTimelineData.length > 0 && (
        <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
            <div>
              <h2 className="text-sm font-bold text-white flex items-center gap-2">
                <BarChart3 className="w-4 h-4 text-cyan-400" />
                <span>SLIDING TIME-WINDOW FEATURE TELEMETRY</span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5 font-mono">
                Ingress Rate (PPS), Shannon Entropy H(X), and Spectral Periodicity (x10) across consecutive {windowConfig.windowDurationSeconds}s windows
              </p>
            </div>
            <div className="flex items-center gap-3 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-cyan-400">
                <span className="w-2.5 h-2.5 rounded bg-cyan-400" /> PPS Rate
              </span>
              <span className="flex items-center gap-1.5 text-rose-400">
                <span className="w-2.5 h-2.5 rounded bg-rose-400" /> Shannon Entropy
              </span>
              <span className="flex items-center gap-1.5 text-purple-400">
                <span className="w-2.5 h-2.5 rounded bg-purple-400" /> Periodicity Score (x10)
              </span>
            </div>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={windowTimelineData} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis yAxisId="left" stroke="#64748b" fontSize={11} tickLine={false} />
                <YAxis yAxisId="right" orientation="right" stroke="#64748b" fontSize={11} tickLine={false} domain={[0, 10]} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px',
                    color: '#f8fafc'
                  }}
                />
                <Line
                  yAxisId="left"
                  type="monotone"
                  dataKey="pps"
                  name="Packets / Sec"
                  stroke="#22d3ee"
                  strokeWidth={2}
                  dot={{ r: 3, fill: '#22d3ee' }}
                />
                <Line
                  yAxisId="right"
                  type="monotone"
                  dataKey="entropy"
                  name="Entropy H(X)"
                  stroke="#fb7185"
                  strokeWidth={2}
                  dot={{ r: 3, fill: '#fb7185' }}
                />
                <Line
                  yAxisId="right"
                  type="monotone"
                  dataKey="periodicity"
                  name="Periodicity (x10)"
                  stroke="#c084fc"
                  strokeWidth={2}
                  dot={{ r: 3, fill: '#c084fc' }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Extracted Feature Vectors Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="p-4 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-slate-800 rounded-lg text-cyan-400">
              <Layers className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white tracking-wide">
                EXTRACTED SLIDING FEATURE RECORDS
              </h2>
              <p className="text-xs text-slate-400">
                Computed across {windowConfig.windowDurationSeconds}s windows with {windowConfig.stepSeconds}s step intervals
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* Search filter */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter IP, proto, threat..."
                className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-44 font-mono"
              />
            </div>

            {/* Protocol filter */}
            <select
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value)}
              className="py-1.5 px-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">All Protos</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="TLS">TLS</option>
              <option value="DNS">DNS</option>
              <option value="NTP">NTP</option>
            </select>

            {/* Export buttons */}
            <button
              onClick={() => handleExportFeatures('CSV')}
              className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-mono flex items-center gap-1.5 transition"
            >
              <Download className="w-3.5 h-3.5 text-emerald-400" /> CSV
            </button>
            <button
              onClick={() => handleExportFeatures('JSON')}
              className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-mono flex items-center gap-1.5 transition"
            >
              <Download className="w-3.5 h-3.5 text-amber-400" /> JSON
            </button>
          </div>
        </div>

        {/* Feature Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs font-mono">
            <thead>
              <tr className="bg-slate-950 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider">
                <th className="py-2.5 px-3">Win #</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Source</th>
                <th className="py-2.5 px-3">Destination</th>
                <th className="py-2.5 px-2">Proto</th>
                <th className="py-2.5 px-2 text-right">Packets</th>
                <th className="py-2.5 px-2 text-right">Bytes</th>
                <th className="py-2.5 px-2 text-right">PPS</th>
                <th className="py-2.5 px-2 text-right">BPS</th>
                <th className="py-2.5 px-2 text-right">SYN:ACK</th>
                <th className="py-2.5 px-2 text-right">Entropy</th>
                <th className="py-2.5 px-2 text-right">IAT (ms)</th>
                <th className="py-2.5 px-2 text-right">Periodicity</th>
                <th className="py-2.5 px-3 text-center">Threat Class</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filteredVectors.length === 0 ? (
                <tr>
                  <td colSpan={14} className="py-8 text-center text-slate-500">
                    No feature vectors matching query. Upload a capture or adjust search filter.
                  </td>
                </tr>
              ) : (
                filteredVectors.map((v) => {
                  const isSelected = selectedVectorId === v.id;
                  return (
                    <tr
                      key={v.id}
                      onClick={() => setSelectedVectorId(isSelected ? null : v.id)}
                      className={`cursor-pointer transition hover:bg-slate-800/40 ${
                        isSelected ? 'bg-cyan-950/40 border-l-4 border-cyan-400' : ''
                      }`}
                    >
                      <td className="py-2.5 px-3 font-bold text-slate-400">
                        W{v.windowIndex}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">{v.timestamp}</td>
                      <td className="py-2.5 px-3 text-slate-200 truncate max-w-[140px]" title={v.sourceSummary}>
                        {v.sourceSummary}
                      </td>
                      <td className="py-2.5 px-3 text-slate-200 truncate max-w-[140px]" title={v.destinationSummary}>
                        {v.destinationSummary}
                      </td>
                      <td className="py-2.5 px-2">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            v.protocol === 'TCP'
                              ? 'bg-blue-950 text-blue-300 border border-blue-800'
                              : v.protocol === 'UDP'
                              ? 'bg-amber-950 text-amber-300 border border-amber-800'
                              : v.protocol === 'TLS'
                              ? 'bg-purple-950 text-purple-300 border border-purple-800'
                              : 'bg-slate-800 text-slate-300 border border-slate-700'
                          }`}
                        >
                          {v.protocol}
                        </span>
                      </td>
                      <td className="py-2.5 px-2 text-right font-semibold text-cyan-300">
                        {v.packetCount.toLocaleString()}
                      </td>
                      <td className="py-2.5 px-2 text-right text-slate-400">
                        {v.byteCount > 1048576
                          ? `${(v.byteCount / 1048576).toFixed(1)}M`
                          : `${(v.byteCount / 1024).toFixed(0)}K`}
                      </td>
                      <td className="py-2.5 px-2 text-right text-cyan-200 font-bold">
                        {v.packetsPerSecond.toLocaleString()}
                      </td>
                      <td className="py-2.5 px-2 text-right text-slate-400">
                        {Math.round(v.bytesPerSecond / 1024)} KB/s
                      </td>
                      <td
                        className={`py-2.5 px-2 text-right font-bold ${
                          v.synToAckRatio > 15
                            ? 'text-rose-400 font-bold'
                            : v.synToAckRatio > 5
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {v.synToAckRatio}:1
                      </td>
                      <td
                        className={`py-2.5 px-2 text-right ${
                          v.sourceIpEntropy > 6.5
                            ? 'text-rose-400 font-bold'
                            : v.sourceIpEntropy < 1.0
                            ? 'text-cyan-400'
                            : 'text-slate-300'
                        }`}
                      >
                        {v.sourceIpEntropy.toFixed(2)}
                      </td>
                      <td className="py-2.5 px-2 text-right text-slate-300">
                        {v.interArrivalTimeMean.toFixed(1)}
                      </td>
                      <td
                        className={`py-2.5 px-2 text-right font-semibold ${
                          v.periodicityScore >= 0.75
                            ? 'text-purple-400 font-bold'
                            : v.periodicityScore >= 0.5
                            ? 'text-amber-300'
                            : 'text-slate-400'
                        }`}
                      >
                        {v.periodicityScore.toFixed(3)}
                      </td>
                      <td className="py-2.5 px-3 text-center">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            v.detectedThreatIndicator === 'SYN Flood'
                              ? 'bg-rose-950/80 text-rose-300 border border-rose-800'
                              : v.detectedThreatIndicator === 'UDP Flood' || v.detectedThreatIndicator === 'UDP Reflection/Amplification'
                              ? 'bg-orange-950/80 text-orange-300 border border-orange-800'
                              : v.detectedThreatIndicator === 'Spoofed-Source Flood'
                              ? 'bg-red-950/80 text-red-300 border border-red-800'
                              : v.detectedThreatIndicator === 'Botnet C2 Beaconing'
                              ? 'bg-purple-950/80 text-purple-300 border border-purple-800'
                              : v.detectedThreatIndicator === 'Anomaly'
                              ? 'bg-amber-950/80 text-amber-300 border border-amber-800'
                              : 'bg-emerald-950/50 text-emerald-400 border border-emerald-900/60'
                          }`}
                        >
                          {v.detectedThreatIndicator || 'Normal'}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Deep Feature Inspector & Evidence Card (When a row is clicked) */}
      {activeSelectedVector && activeDetectionResult && (
        <div className="bg-slate-900 border border-cyan-500/40 rounded-xl p-5 shadow-2xl space-y-4 animate-in fade-in duration-200">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-cyan-950 border border-cyan-500/30 rounded-lg text-cyan-400">
                <Info className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <span>FEATURE RECORD INSPECTOR: WINDOW #{activeSelectedVector.windowIndex}</span>
                  <span className="text-xs font-mono font-normal text-slate-400">
                    ({activeSelectedVector.timestamp} • Duration: {activeSelectedVector.windowDurationSec}s)
                  </span>
                </h3>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Path: {activeSelectedVector.sourceSummary} → {activeSelectedVector.destinationSummary}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <div
                className={`px-3 py-1 rounded-full text-xs font-bold font-mono border ${
                  activeDetectionResult.severity === 'Critical'
                    ? 'bg-rose-950 text-rose-300 border-rose-800'
                    : activeDetectionResult.severity === 'High'
                    ? 'bg-orange-950 text-orange-300 border-orange-800'
                    : activeDetectionResult.severity === 'Medium'
                    ? 'bg-amber-950 text-amber-300 border-amber-800'
                    : 'bg-emerald-950 text-emerald-400 border-emerald-800'
                }`}
              >
                {activeDetectionResult.threatType} • {activeDetectionResult.confidence}% Confidence
              </div>
              <button
                onClick={() => setSelectedVectorId(null)}
                className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs"
              >
                Close
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* 1. Basic Features */}
            <div className="bg-slate-950/60 p-4 rounded-lg border border-slate-800 space-y-2">
              <div className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                <HardDrive className="w-3.5 h-3.5" /> Basic Flow Features
              </div>
              <div className="text-xs font-mono space-y-1.5 pt-1 text-slate-300">
                <div className="flex justify-between">
                  <span className="text-slate-400">Packet Count:</span>
                  <span className="font-bold text-white">{activeSelectedVector.packetCount.toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Byte Count:</span>
                  <span>{activeSelectedVector.byteCount.toLocaleString()} B</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Rate (PPS / BPS):</span>
                  <span className="text-cyan-300 font-semibold">{activeSelectedVector.packetsPerSecond.toLocaleString()} / {(activeSelectedVector.bytesPerSecond / 1024).toFixed(0)} KB/s</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Packet Size (Min/Avg/Max):</span>
                  <span>{activeSelectedVector.minPacketSize} / {activeSelectedVector.averagePacketSize} / {activeSelectedVector.maxPacketSize} B</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Protocol & Ports:</span>
                  <span>{activeSelectedVector.protocol} ({activeSelectedVector.sourcePort} → {activeSelectedVector.destinationPort})</span>
                </div>
              </div>
            </div>

            {/* 2. DDoS Features */}
            <div className="bg-slate-950/60 p-4 rounded-lg border border-slate-800 space-y-2">
              <div className="text-xs font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5" /> DDoS Statistical Features
              </div>
              <div className="text-xs font-mono space-y-1.5 pt-1 text-slate-300">
                <div className="flex justify-between">
                  <span className="text-slate-400">SYN / ACK Counts:</span>
                  <span className="font-semibold text-rose-300">{activeSelectedVector.synPacketCount} SYN / {activeSelectedVector.ackPacketCount} ACK</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">SYN to ACK Ratio:</span>
                  <span className="font-bold text-rose-400">{activeSelectedVector.synToAckRatio}:1</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Source Shannon Entropy:</span>
                  <span className="font-bold text-white">{activeSelectedVector.sourceIpEntropy.toFixed(3)} / 8.0</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Target VIP Concentration:</span>
                  <span>HHI {activeSelectedVector.destinationConcentration.toFixed(3)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Traffic Growth Rate:</span>
                  <span>{activeSelectedVector.trafficGrowthRate > 0 ? `+${activeSelectedVector.trafficGrowthRate}%` : `${activeSelectedVector.trafficGrowthRate}%`}</span>
                </div>
              </div>
            </div>

            {/* 3. C2 Features */}
            <div className="bg-slate-950/60 p-4 rounded-lg border border-slate-800 space-y-2">
              <div className="text-xs font-bold text-purple-400 uppercase tracking-wider flex items-center gap-1.5">
                <Radio className="w-3.5 h-3.5" /> C2 Beacon Features
              </div>
              <div className="text-xs font-mono space-y-1.5 pt-1 text-slate-300">
                <div className="flex justify-between">
                  <span className="text-slate-400">Periodicity Score:</span>
                  <span className="font-bold text-purple-300">{activeSelectedVector.periodicityScore.toFixed(3)} / 1.000</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Mean IAT & Jitter:</span>
                  <span>{activeSelectedVector.interArrivalTimeMean.toFixed(1)}ms (±{activeSelectedVector.jitterPercentage}%)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Coefficient of Variation:</span>
                  <span>CV = {activeSelectedVector.coefficientOfVariation.toFixed(3)}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Payload Uniformity:</span>
                  <span>{(activeSelectedVector.packetSizeConsistency * 100).toFixed(1)}%</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Target Repetitions:</span>
                  <span>{activeSelectedVector.destinationRepetitionCount} contacts</span>
                </div>
              </div>
            </div>
          </div>

          {/* Forensic Evidence & Recommendation */}
          <div className="bg-slate-950/80 p-3.5 rounded-lg border border-slate-800 text-xs font-mono">
            <div className="text-slate-400 font-bold uppercase text-[11px] mb-1.5">
              Deterministic Detection Method: <span className="text-slate-200">{activeDetectionResult.detectionMethod}</span>
            </div>
            <ul className="space-y-1 list-disc list-inside text-slate-300">
              {activeDetectionResult.evidence.map((ev, i) => (
                <li key={i}>{ev}</li>
              ))}
            </ul>
            <div className="mt-2.5 pt-2 border-t border-slate-800/80 text-emerald-400 text-[11px]">
              <strong>Enclave Advisory:</strong> {activeDetectionResult.recommendedAction}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
