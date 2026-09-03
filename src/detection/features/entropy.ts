/**
 * Shannon Entropy Module
 * H(X) = -Σ p(x) * log2(p(x))
 * Applied to Source IP and Port dispersion analysis.
 */

import { ENGINE_CONFIG } from '../config';

export interface EntropyResult {
  entropy: number; // 0.0 - 8.0
  baseline: number;
  deviation: number;
  interpretation: 'LOW_ENTROPY' | 'NORMAL_ENTROPY' | 'HIGH_ENTROPY';
  interpretationText: string;
  itemCount: number;
  uniqueCount: number;
}

/**
 * Reusable Shannon Entropy calculation.
 * Can take an array of values (strings or numbers) or a frequency map.
 */
export function calculateShannonEntropy(values: (string | number)[]): number {
  if (!values || values.length === 0) return 0;

  const frequencies: Map<string | number, number> = new Map();
  for (const v of values) {
    frequencies.set(v, (frequencies.get(v) || 0) + 1);
  }

  const total = values.length;
  let entropy = 0;

  for (const count of frequencies.values()) {
    if (count > 0) {
      const p = count / total;
      entropy -= p * Math.log2(p);
    }
  }

  return Number(entropy.toFixed(3));
}

/**
 * Evaluates Shannon Entropy against baseline and produces standard SOC interpretation.
 */
export function evaluateSourceIpEntropy(sourceIps: string[], baselineEntropy: number = ENGINE_CONFIG.baseline.baselineEntropy): EntropyResult {
  const currentEntropy = calculateShannonEntropy(sourceIps);
  const deviation = Number((currentEntropy - baselineEntropy).toFixed(2));
  const uniqueCount = new Set(sourceIps).size;

  let interpretation: 'LOW_ENTROPY' | 'NORMAL_ENTROPY' | 'HIGH_ENTROPY' = 'NORMAL_ENTROPY';
  let interpretationText = 'Normal organic source IP distribution.';

  if (currentEntropy < ENGINE_CONFIG.entropy.lowThreshold) {
    interpretation = 'LOW_ENTROPY';
    interpretationText = 'Highly concentrated source distribution (single host or small ingress cluster).';
  } else if (currentEntropy > ENGINE_CONFIG.entropy.highThreshold) {
    interpretation = 'HIGH_ENTROPY';
    interpretationText = 'High entropy dispersion detected. Strong indicator of randomized / spoofed source IP flood.';
  }

  return {
    entropy: currentEntropy,
    baseline: baselineEntropy,
    deviation,
    interpretation,
    interpretationText,
    itemCount: sourceIps.length,
    uniqueCount
  };
}
