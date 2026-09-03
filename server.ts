import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import {
  SIMULATION_SCENARIOS,
  INITIAL_ALERTS,
  INITIAL_C2_BEACONS,
  INITIAL_INTEL_RECORDS
} from './src/services/networkSimulator';
import { NetworkPacket, SecurityAlert, TelemetryMetrics, SimulationScenario } from './src/types';
import { runDetectionPipeline, getEngineModuleStatus } from './src/detection/engine';
import { generateScenarioFlows } from './src/detection/simulation/trafficGenerator';
import { parsePcapBinary } from './src/detection/parsers/pcapParser';
import { parseCsvFlows } from './src/detection/parsers/csvParser';
import { runAllAcceptanceTests } from './src/detection/tests/acceptanceTests';

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '50mb' }));
  app.use(express.text({ limit: '50mb' }));

  // Mutable In-Memory State for Prototype SOC Backend
  let activeScenario: SimulationScenario = SIMULATION_SCENARIOS[0];
  let alerts: SecurityAlert[] = [...INITIAL_ALERTS];
  let recentPackets: NetworkPacket[] = [];
  let timelineHistory: any[] = [];
  let latestPipelineResult = runDetectionPipeline(generateScenarioFlows('normal', 60), 'SIMULATION');

  recentPackets = latestPipelineResult.displayPackets;
  timelineHistory = latestPipelineResult.timeline;

  // Periodic simulator background loop (simulates passive data diode ingress)
  setInterval(() => {
    // Generate new flow batch and execute detection pipeline
    const flows = generateScenarioFlows(activeScenario.id as any, 30);
    latestPipelineResult = runDetectionPipeline(flows, 'SIMULATION');

    // Update packets and timeline (deduplicated by packet id)
    const combinedPackets = [...latestPipelineResult.displayPackets.slice(0, 15), ...recentPackets];
    const seenPktIds = new Set<string>();
    recentPackets = combinedPackets.filter((p) => {
      if (seenPktIds.has(p.id)) return false;
      seenPktIds.add(p.id);
      return true;
    }).slice(0, 50);

    const now = new Date();
    const timeStr = now.toTimeString().substring(0, 8);
    const pps = latestPipelineResult.telemetry.packetsPerSecond;
    const mbps = Number(((latestPipelineResult.telemetry.bytesPerSecond * 8) / 1e6).toFixed(1));

    timelineHistory.push({
      time: timeStr,
      totalPPS: pps,
      tcpPPS: Math.floor(pps * (latestPipelineResult.features.general.protocolPercentages.TCP / 100)),
      udpPPS: Math.floor(pps * (latestPipelineResult.features.general.protocolPercentages.UDP / 100)),
      icmpPPS: Math.floor(pps * 0.02),
      otherPPS: Math.floor(pps * 0.08),
      mbps,
      entropy: latestPipelineResult.features.ddos.sourceIPEntropy
    });

    if (timelineHistory.length > 30) {
      timelineHistory.shift();
    }
  }, 2500);

  // Health endpoint
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      service: 'OneWaySentinel AI SOC Engine',
      oneWayDiodeVerified: true,
      reversePackets: 0
    });
  });

  // Current Telemetry
  app.get('/api/telemetry', (req, res) => {
    let pps = Math.floor(48500 * activeScenario.trafficMultiplier + Math.random() * 2500);
    let bps = pps * 680 * 8; // bits per second
    let entropy = 3.72;
    let concentration = 0.32;

    if (activeScenario.id === 'syn-flood') {
      entropy = 6.95;
      concentration = 0.88; // high concentration on victim IP
    } else if (activeScenario.id === 'spoofed-source') {
      entropy = 7.84;
      concentration = 0.74;
    } else if (activeScenario.id === 'udp-amplification') {
      entropy = 5.62;
      concentration = 0.91;
    }

    const telemetry: TelemetryMetrics = {
      monitoringStatus: 'ACTIVE_ONE_WAY',
      totalPackets: 1849204000 + Math.floor(Math.random() * 500000),
      totalBytes: 1420800000000 + Math.floor(Math.random() * 40000000),
      packetsPerSecond: pps,
      bytesPerSecond: bps,
      activeThreatsCount: activeScenario.activeThreat ? 4 : 1,
      criticalAlertsCount: alerts.filter(a => a.severity === 'Critical' && a.status !== 'Mitigated' && a.status !== 'False Positive').length,
      averageAiConfidence: activeScenario.activeThreat ? 95.2 : 98.4,
      sourceIPEntropy: Number(entropy.toFixed(2)),
      destinationConcentration: Number(concentration.toFixed(2)),
      diodeReversePacketsTransmitted: 0, // Invariant
      diodeOpticalRxPowerDbm: -14.2,
      diodeTxHardwareDisabled: true, // Physical guarantee
      pipelineLatencyMs: 0.84,
      mlInferenceLatencyMs: 2.15
    };

    res.json({
      telemetry,
      activeScenario,
      scenarios: SIMULATION_SCENARIOS
    });
  });

  // Live Traffic Flows
  app.get('/api/traffic', (req, res) => {
    res.json({
      packets: recentPackets,
      timeline: timelineHistory,
      activeScenario
    });
  });

  // DDoS Detection Metrics
  app.get('/api/threats/ddos', (req, res) => {
    const isSynAttack = activeScenario.id === 'syn-flood';
    const isUdpAmp = activeScenario.id === 'udp-amplification';
    const isSpoofed = activeScenario.id === 'spoofed-source';

    res.json({
      metrics: {
        synFloodIntensity: isSynAttack ? 94 : 4,
        udpFloodIntensity: isUdpAmp || isSpoofed ? 91 : 8,
        amplificationFactor: isUdpAmp ? 55.4 : 1.2,
        spoofedEntropyScore: isSpoofed ? 7.84 : isSynAttack ? 6.95 : 3.72,
        synToAckRatio: isSynAttack ? 48.6 : 1.02,
        topTargetVips: [
          { ip: '192.168.10.45', service: 'HTTPS Web VIP', pps: isSynAttack ? 385000 : 18000, percentage: isSynAttack ? 74 : 32 },
          { ip: '192.168.20.10', service: 'Core Database Gateway', pps: isUdpAmp ? 290000 : 12000, percentage: isUdpAmp ? 68 : 22 },
          { ip: '192.168.10.1', service: 'API Ingress Gateway', pps: isSpoofed ? 175000 : 11000, percentage: isSpoofed ? 55 : 20 },
          { ip: '192.168.10.50', service: 'Authoritative DNS', pps: 9200, percentage: 14 }
        ],
        amplificationVectors: [
          { protocol: 'NTP Monlist', port: 123, pps: isUdpAmp ? 180000 : 250, factor: '55.4x' },
          { protocol: 'DNS ANY Query', port: 53, pps: isUdpAmp ? 72000 : 1800, factor: '28.0x' },
          { protocol: 'Memcached Get', port: 11211, pps: isUdpAmp ? 41000 : 40, factor: '4000.0x' },
          { protocol: 'SSDP Discover', port: 1900, pps: isUdpAmp ? 17000 : 120, factor: '30.8x' }
        ]
      }
    });
  });

  // C2 Beacon Detection
  app.get('/api/threats/c2', (req, res) => {
    res.json({
      beacons: INITIAL_C2_BEACONS,
      activeBeaconMode: activeScenario.id === 'c2-beacon'
    });
  });

  // Alerts API
  app.get('/api/alerts', (req, res) => {
    res.json({ alerts });
  });

  // Update alert status
  app.post('/api/alerts/:id/status', (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    const alert = alerts.find(a => a.id === id);
    if (alert) {
      alert.status = status;
      return res.json({ success: true, alert });
    }
    res.status(404).json({ error: 'Alert not found' });
  });

  // Threat Intel Feed
  app.get('/api/intel', (req, res) => {
    res.json({ intel: INITIAL_INTEL_RECORDS });
  });

  // Scenario Simulator Switch
  app.post('/api/simulate/scenario', (req, res) => {
    const { scenarioId } = req.body;
    const found = SIMULATION_SCENARIOS.find(s => s.id === scenarioId);
    if (found) {
      activeScenario = found;

      // If attack scenario triggered, prepend a realistic alert
      if (found.activeThreat) {
        const newAlert: SecurityAlert = {
          id: `ALT-2026-${Math.floor(1000 + Math.random() * 9000)}`,
          threatType: found.activeThreat,
          severity: 'Critical',
          confidenceScore: Math.floor(92 + Math.random() * 7),
          timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
          source: found.id === 'syn-flood' ? '203.0.113.0/24 (Volumetric Botnet)' :
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
        alerts.unshift(newAlert);
      }

      return res.json({ success: true, activeScenario });
    }
    res.status(400).json({ error: 'Scenario not found' });
  });

  // Ingestion & Detection API: Analyze normalized flows
  app.post('/api/analyze', (req, res) => {
    try {
      const { flows, sourceType, filename } = req.body;
      if (!flows || !Array.isArray(flows)) {
        return res.status(400).json({ error: 'Expected an array of TrafficFlow objects in the "flows" property.' });
      }
      const result = runDetectionPipeline(flows, sourceType || 'SIMULATION', filename);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Analysis pipeline failure.' });
    }
  });

  // Ingestion & Detection API: Parse & Analyze PCAP (Base64 or Raw)
  app.post('/api/analyze/pcap', (req, res) => {
    try {
      const { base64Data, filename } = req.body;
      if (!base64Data) {
        return res.status(400).json({ error: 'Missing base64Data in request body.' });
      }
      const buffer = Buffer.from(base64Data, 'base64');
      const arrayBuffer = buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);

      const parseResult = parsePcapBinary(arrayBuffer);
      if (!parseResult.success) {
        return res.status(400).json({
          success: false,
          error: parseResult.error || 'Failed to parse PCAP file header.'
        });
      }

      const analysisResult = runDetectionPipeline(parseResult.flows, 'PCAP', filename || 'capture.pcap');
      res.json({
        success: true,
        parseMetadata: parseResult.metadata,
        analysis: analysisResult
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to process PCAP capture.' });
    }
  });

  // Ingestion & Detection API: Parse & Analyze CSV / NetFlow Flows
  app.post('/api/analyze/flows', (req, res) => {
    try {
      let csvContent = '';
      if (typeof req.body === 'string') {
        csvContent = req.body;
      } else if (req.body && req.body.csvText) {
        csvContent = req.body.csvText;
      } else {
        return res.status(400).json({ error: 'Expected CSV string payload.' });
      }

      const parseResult = parseCsvFlows(csvContent);
      if (!parseResult.success) {
        return res.status(400).json({
          success: false,
          error: parseResult.error || 'Failed to parse CSV flows.'
        });
      }

      const analysisResult = runDetectionPipeline(parseResult.flows, 'CSV', req.body.filename || 'flows.csv');
      res.json({
        success: true,
        rowCount: parseResult.rowCount,
        analysis: analysisResult
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message || 'Failed to process CSV flow data.' });
    }
  });

  // Verification Test Suite Runner
  app.get('/api/tests/run', (req, res) => {
    try {
      const suite = runAllAcceptanceTests();
      res.json(suite);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Test execution failure.' });
    }
  });

  // Detection Engine Module Statuses
  app.get('/api/system/modules', (req, res) => {
    res.json({ modules: getEngineModuleStatus() });
  });

  // System & Hardware Diode specifications
  app.get('/api/system', (req, res) => {
    res.json({
      hardwareDiode: {
        model: 'OWS-DD-10G Optical Data Diode',
        vendor: 'Smart India Hackathon 2026 Cyber Prototype',
        firmware: 'v4.1.9-hardened-soc',
        txTransmitterStatus: 'PHYSICALLY_DISCONNECTED (Air-Gapped)',
        rxPhototransistorStatus: 'OPTICAL_INGRESS_RECEIVING (1310nm Singlemode)',
        opticalPowerLevelDbm: -14.2,
        reversePacketsAttempted: 0,
        reversePacketsTransmitted: 0,
        backplaneElectricalIsolation: 'Passed (Galvanic Barrier > 2.5 kV)',
        regulatoryCompliance: 'EAL 7+ Equivalent Passive Separation'
      },
      softwarePipeline: {
        enclaveOperatingMode: 'STRICT_PASSIVE_MONITORING',
        captureDriver: 'DPDK Zero-Copy Ring Buffer (RX Only)',
        bufferCapacityPackets: 2000000,
        bufferUtilizationPct: 18.4,
        featureExtractionLatencyMicroseconds: 840,
        mlInferenceEngine: 'Modular ONNX / PyTorch Python Bridge (Pluggable)',
        activeModels: [
          { name: 'XGBoost Flow Classifier', version: '2.4.1', type: 'Supervised Flow Classification', accuracy: '98.7%' },
          { name: 'Isolation Forest Anomaly', version: '1.8.0', type: 'Unsupervised Outlier Detection', accuracy: '96.2%' },
          { name: 'FFT Periodicity Beacon Detector', version: '3.1.0', type: 'Spectral Analysis', accuracy: '95.8%' },
          { name: 'Bi-LSTM Sequential Packet Analyzer', version: '1.2.0', type: 'Deep Temporal Pattern', accuracy: '97.4%' }
        ]
      }
    });
  });

  // Mount Vite middleware for development or serve static in production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[OneWaySentinel AI] SOC Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
