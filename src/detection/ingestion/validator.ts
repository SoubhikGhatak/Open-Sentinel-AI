/**
 * OneWaySentinel AI - Unified Ingestion Validator & Orchestrator
 * Strictly passive validation and feature extraction dispatch.
 */

import {
  PassiveObservation,
  FeatureVector,
  SlidingWindowConfig,
  PassiveDatasetSummary,
  IngestionValidationSummary,
  IngestionSourceFormat
} from './types';
import { parsePcapPassive, PcapIngestionResult } from './pcapParser';
import { parseCsvPassive, CsvIngestionResult } from './csvParser';
import { parseJsonPassive, JsonIngestionResult } from './jsonParser';
import { extractWindowFeatures } from './timeWindowAnalyzer';

export interface ProcessedIngestionPayload {
  validation: IngestionValidationSummary;
  observations: PassiveObservation[];
  featureVectors: FeatureVector[];
  summary: PassiveDatasetSummary;
}

/**
 * Validates and processes any uploaded file payload (PCAP ArrayBuffer, CSV text, JSON text).
 * Handles malformed records gracefully without throwing unhandled exceptions.
 */
export async function processUploadedFile(
  file: File,
  windowConfig: SlidingWindowConfig = { windowDurationSeconds: 10, stepSeconds: 5 }
): Promise<ProcessedIngestionPayload> {
  const filename = file.name;
  const ext = filename.split('.').pop()?.toLowerCase() || '';

  if (ext === 'pcap' || ext === 'cap') {
    const buffer = await file.arrayBuffer();
    return processPcapBuffer(buffer, filename, windowConfig);
  } else if (ext === 'csv' || ext === 'txt') {
    const text = await file.text();
    return processCsvString(text, filename, windowConfig);
  } else if (ext === 'json' || ext === 'jsonl') {
    const text = await file.text();
    return processJsonString(text, filename, windowConfig);
  } else {
    // Attempt text or binary sniffing
    try {
      const buffer = await file.arrayBuffer();
      if (buffer.byteLength >= 4) {
        const view = new DataView(buffer);
        const magic = view.getUint32(0, false);
        if (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1 || magic === 0xa1b23c4d || magic === 0x4d3cb2a1) {
          return processPcapBuffer(buffer, filename, windowConfig);
        }
      }
      const text = await file.text();
      if (text.trim().startsWith('{') || text.trim().startsWith('[')) {
        return processJsonString(text, filename, windowConfig);
      }
      return processCsvString(text, filename, windowConfig);
    } catch (e: any) {
      return createErrorPayload(
        'UNKNOWN' as IngestionSourceFormat,
        filename,
        `Unsupported file format: .${ext}. Please provide standard .pcap, .csv, or .json/.jsonl network flow logs.`
      );
    }
  }
}

export function processPcapBuffer(
  buffer: ArrayBuffer,
  filename: string = 'uploaded.pcap',
  windowConfig: SlidingWindowConfig = { windowDurationSeconds: 10, stepSeconds: 5 }
): ProcessedIngestionPayload {
  const result: PcapIngestionResult = parsePcapPassive(buffer);

  if (!result.success || result.observations.length === 0) {
    return createErrorPayload('PCAP', filename, result.error || 'No valid packets discovered in PCAP.');
  }

  const { featureVectors, summary } = extractWindowFeatures(result.observations, windowConfig);

  const validation: IngestionValidationSummary = {
    success: true,
    sourceType: 'PCAP',
    filename,
    validRecords: result.validPackets,
    invalidRecords: result.invalidPackets,
    totalRecordsProcessed: result.validPackets + result.invalidPackets,
    parseErrors: result.error ? [result.error] : [],
    timeRange: {
      start: summary.timeRangeStart,
      end: summary.timeRangeEnd,
      durationSeconds: result.durationSeconds
    }
  };

  return {
    validation,
    observations: result.observations,
    featureVectors,
    summary
  };
}

export function processCsvString(
  csvText: string,
  filename: string = 'flows.csv',
  windowConfig: SlidingWindowConfig = { windowDurationSeconds: 10, stepSeconds: 5 }
): ProcessedIngestionPayload {
  const result: CsvIngestionResult = parseCsvPassive(csvText);

  if (!result.success || result.observations.length === 0) {
    return createErrorPayload('CSV', filename, result.error || 'Failed to parse CSV flows.', result.parseErrors);
  }

  const { featureVectors, summary } = extractWindowFeatures(result.observations, windowConfig);

  const validation: IngestionValidationSummary = {
    success: true,
    sourceType: 'CSV',
    filename,
    validRecords: result.validRecords,
    invalidRecords: result.invalidRecords,
    totalRecordsProcessed: result.validRecords + result.invalidRecords,
    parseErrors: result.parseErrors,
    timeRange: {
      start: summary.timeRangeStart,
      end: summary.timeRangeEnd,
      durationSeconds: result.durationSeconds
    }
  };

  return {
    validation,
    observations: result.observations,
    featureVectors,
    summary
  };
}

export function processJsonString(
  jsonText: string,
  filename: string = 'flows.json',
  windowConfig: SlidingWindowConfig = { windowDurationSeconds: 10, stepSeconds: 5 }
): ProcessedIngestionPayload {
  const result: JsonIngestionResult = parseJsonPassive(jsonText);

  if (!result.success || result.observations.length === 0) {
    return createErrorPayload('JSON', filename, result.error || 'Failed to parse JSON flows.', result.parseErrors);
  }

  const { featureVectors, summary } = extractWindowFeatures(result.observations, windowConfig);

  const validation: IngestionValidationSummary = {
    success: true,
    sourceType: 'JSON',
    filename,
    validRecords: result.validRecords,
    invalidRecords: result.invalidRecords,
    totalRecordsProcessed: result.validRecords + result.invalidRecords,
    parseErrors: result.parseErrors,
    timeRange: {
      start: summary.timeRangeStart,
      end: summary.timeRangeEnd,
      durationSeconds: result.durationSeconds
    }
  };

  return {
    validation,
    observations: result.observations,
    featureVectors,
    summary
  };
}

export function processPassiveObservations(
  observations: PassiveObservation[],
  sourceType: IngestionSourceFormat = 'SIMULATION',
  filename: string = 'observations.dat',
  windowConfig: SlidingWindowConfig = { windowDurationSeconds: 10, stepSeconds: 5 }
): ProcessedIngestionPayload {
  if (!observations || observations.length === 0) {
    return createErrorPayload(sourceType, filename, 'No passive observations provided.');
  }

  const { featureVectors, summary } = extractWindowFeatures(observations, windowConfig);

  const validation: IngestionValidationSummary = {
    success: true,
    sourceType,
    filename,
    validRecords: observations.length,
    invalidRecords: 0,
    totalRecordsProcessed: observations.length,
    parseErrors: [],
    timeRange: {
      start: summary.timeRangeStart,
      end: summary.timeRangeEnd,
      durationSeconds: Math.max(1, (new Date(summary.timeRangeEnd).getTime() - new Date(summary.timeRangeStart).getTime()) / 1000)
    }
  };

  return {
    validation,
    observations,
    featureVectors,
    summary
  };
}

function createErrorPayload(
  sourceType: IngestionSourceFormat,
  filename: string,
  errorMessage: string,
  parseErrors: string[] = []
): ProcessedIngestionPayload {
  return {
    validation: {
      success: false,
      sourceType,
      filename,
      validRecords: 0,
      invalidRecords: 0,
      totalRecordsProcessed: 0,
      parseErrors: [errorMessage, ...parseErrors]
    },
    observations: [],
    featureVectors: [],
    summary: {
      totalFlows: 0,
      totalPackets: 0,
      totalBytes: 0,
      analysisWindow: '10s window / 5s step',
      protocolsObserved: {},
      protocolPercentages: {},
      uniqueSourceIps: 0,
      uniqueDestinationIps: 0,
      averagePacketRate: 0,
      averageByteRate: 0,
      averageEntropy: 0,
      peakPeriodicityScore: 0,
      timeRangeStart: 'N/A',
      timeRangeEnd: 'N/A'
    }
  };
}
