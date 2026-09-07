/**
 * OneWaySentinel AI - Client & Server Engine Service Bridge
 * Coordinates ingestion, feature extraction, detection, forensic analysis, and acceptance testing.
 */

import {
  runDetectionPipeline,
  FullAnalysisPipelineResult,
  getEngineModuleStatus
} from '../detection/engine';
import { parsePcapBinary, PcapParseResult } from '../detection/parsers/pcapParser';
import { parseCsvFlows, CsvParseResult } from '../detection/parsers/csvParser';
import { generateScenarioFlows, SimulationScenarioId } from '../detection/simulation/trafficGenerator';
import { runAllAcceptanceTests, TestSuiteSummary } from '../detection/tests/acceptanceTests';
import { TrafficFlow, ModuleStatus } from '../detection/types';
import { PassiveObservation, FeatureVector, SlidingWindowConfig, PassiveDatasetSummary } from '../detection/ingestion/types';
import { extractWindowFeatures } from '../detection/ingestion/timeWindowAnalyzer';
import { processUploadedFile, ProcessedIngestionPayload } from '../detection/ingestion/validator';

export class DetectionEngineService {
  /**
   * Directly parses an uploaded binary ArrayBuffer (.pcap) and executes the full detection pipeline.
   * If parsing fails or file is invalid, returns explicit descriptive error without fabrication.
   */
  public static analyzePcapFile(
    arrayBuffer: ArrayBuffer,
    filename: string = 'uploaded_capture.pcap'
  ): { success: boolean; result?: FullAnalysisPipelineResult; error?: string } {
    const parseResult: PcapParseResult = parsePcapBinary(arrayBuffer);

    if (!parseResult.success) {
      return {
        success: false,
        error: parseResult.error || 'Failed to parse PCAP file header.'
      };
    }

    if (parseResult.flows.length === 0) {
      return {
        success: false,
        error: 'PCAP parsed successfully but contains 0 IPv4/L4 packets matching monitoring filters.'
      };
    }

    const pipelineResult = runDetectionPipeline(parseResult.flows, 'PCAP', filename);
    return {
      success: true,
      result: pipelineResult
    };
  }

  /**
   * Directly parses a CSV flow text string (NetFlow/IPFIX) and executes the detection pipeline.
   */
  public static analyzeCsvText(
    csvText: string,
    filename: string = 'flows.csv'
  ): { success: boolean; result?: FullAnalysisPipelineResult; error?: string } {
    const parseResult: CsvParseResult = parseCsvFlows(csvText);

    if (!parseResult.success) {
      return {
        success: false,
        error: parseResult.error || 'Failed to parse CSV flow data.'
      };
    }

    const pipelineResult = runDetectionPipeline(parseResult.flows, 'CSV', filename);
    return {
      success: true,
      result: pipelineResult
    };
  }

  /**
   * Runs simulation scenario generation through the full real detection pipeline.
   */
  public static simulateScenario(
    scenarioId: SimulationScenarioId,
    count: number = 70
  ): FullAnalysisPipelineResult {
    const flows = generateScenarioFlows(scenarioId, count);
    return runDetectionPipeline(flows, 'SIMULATION');
  }

  /**
   * Directly analyzes an array of pre-parsed normalized TrafficFlow items.
   */
  public static analyzeFlows(
    flows: TrafficFlow[],
    sourceType: 'PCAP' | 'CSV' | 'SIMULATION' = 'SIMULATION',
    filename?: string
  ): FullAnalysisPipelineResult {
    return runDetectionPipeline(flows, sourceType, filename);
  }

  /**
   * Runs the 8 required acceptance test verification cases.
   */
  public static runTests(): TestSuiteSummary {
    return runAllAcceptanceTests();
  }

  /**
   * Extracts structured feature records across configurable sliding windows.
   */
  public static extractPassiveFeatures(
    observations: PassiveObservation[],
    config: SlidingWindowConfig = { windowDurationSeconds: 10, stepSeconds: 5 }
  ): { featureVectors: FeatureVector[]; summary: PassiveDatasetSummary } {
    return extractWindowFeatures(observations, config);
  }

  /**
   * Validates and processes an uploaded passive file.
   */
  public static async processUploadedPassiveFile(
    file: File,
    config: SlidingWindowConfig = { windowDurationSeconds: 10, stepSeconds: 5 }
  ): Promise<ProcessedIngestionPayload> {
    return processUploadedFile(file, config);
  }

  /**
   * Retrieves live status of all passive detection modules.
   */
  public static getModules(): ModuleStatus[] {
    return getEngineModuleStatus();
  }
}
