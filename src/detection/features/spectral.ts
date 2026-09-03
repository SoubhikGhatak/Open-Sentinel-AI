/**
 * Spectral & Temporal Analysis Module
 * Inter-arrival time (IAT) statistical moments and Discrete Fourier Transform (DFT/FFT) periodicity detection.
 * Strictly adheres to rule: If sample count < minSamples, explicitly report "Insufficient temporal samples".
 */

import { ENGINE_CONFIG } from '../config';

export interface SpectralAnalysisResult {
  meanIntervalMs: number;
  stdDevIntervalMs: number;
  coefficientOfVariation: number; // CV = sigma / mu
  jitterPercentage: number; // (sigma / mu) * 100
  periodicityScore: number; // 0.0 - 1.0
  hasSufficientSamples: boolean;
  sampleCount: number;
  dominantFrequencyHz?: number;
  dominantPeriodSeconds?: number;
  peakSpectralPower?: number; // 0.0 - 1.0
  statusMessage: string;
}

/**
 * Calculates temporal statistical moments and discrete spectral power for an arrival time series.
 * @param intervalsMs Array of inter-arrival times in milliseconds
 */
export function analyzeTemporalPeriodicity(intervalsMs: number[]): SpectralAnalysisResult {
  const sampleCount = intervalsMs.length;

  if (sampleCount === 0) {
    return {
      meanIntervalMs: 0,
      stdDevIntervalMs: 0,
      coefficientOfVariation: 0,
      jitterPercentage: 0,
      periodicityScore: 0,
      hasSufficientSamples: false,
      sampleCount: 0,
      statusMessage: 'Insufficient temporal samples: 0 intervals observed.'
    };
  }

  // 1. Mean
  const sum = intervalsMs.reduce((acc, val) => acc + val, 0);
  const mean = sum / sampleCount;

  // 2. Variance & Standard Deviation
  let variance = 0;
  for (const val of intervalsMs) {
    variance += Math.pow(val - mean, 2);
  }
  variance = variance / sampleCount;
  const stdDev = Math.sqrt(variance);

  // 3. Coefficient of Variation (CV) & Jitter
  const cv = mean > 0 ? stdDev / mean : 0;
  const jitterPct = Number((cv * 100).toFixed(2));

  // 4. Check for sufficient temporal samples
  if (sampleCount < ENGINE_CONFIG.c2.minSamplesForFFT) {
    return {
      meanIntervalMs: Number(mean.toFixed(2)),
      stdDevIntervalMs: Number(stdDev.toFixed(2)),
      coefficientOfVariation: Number(cv.toFixed(3)),
      jitterPercentage: jitterPct,
      periodicityScore: Number(Math.max(0, 1 - cv).toFixed(2)),
      hasSufficientSamples: false,
      sampleCount,
      statusMessage: `Insufficient temporal samples: Only ${sampleCount} intervals observed (minimum ${ENGINE_CONFIG.c2.minSamplesForFFT} required for spectral FFT).`
    };
  }

  // 5. Discrete Fourier Transform (DFT) Power Spectrum
  // Normalize intervals around zero-mean
  const N = sampleCount;
  const normalized = intervalsMs.map((v) => v - mean);

  let maxPower = 0;
  let dominantK = 0;

  // Inspect frequencies from k = 1 to N/2
  const maxK = Math.floor(N / 2);
  for (let k = 1; k <= maxK; k++) {
    let re = 0;
    let im = 0;
    for (let n = 0; n < N; n++) {
      const angle = (2 * Math.PI * k * n) / N;
      re += normalized[n] * Math.cos(angle);
      im -= normalized[n] * Math.sin(angle);
    }
    const power = (re * re + im * im) / (N * N);
    if (power > maxPower) {
      maxPower = power;
      dominantK = k;
    }
  }

  // Calculate peak spectral power ratio vs total variance
  const peakSpectralPower = variance > 0 ? Math.min(1.0, Number((maxPower / variance).toFixed(3))) : 0;

  // Periodicity score incorporates low jitter + high spectral peak
  // Low jitter (CV < 0.15) gives high base periodicity
  const jitterFactor = Math.max(0, 1 - cv / 0.5);
  const periodicityScore = Number((0.6 * jitterFactor + 0.4 * peakSpectralPower).toFixed(2));

  // Dominant frequency in Hz (based on mean sampling interval)
  const samplingRateHz = mean > 0 ? 1000 / mean : 1;
  const dominantFrequencyHz = dominantK > 0 ? Number(((dominantK * samplingRateHz) / N).toFixed(4)) : undefined;
  const dominantPeriodSeconds = dominantFrequencyHz && dominantFrequencyHz > 0 ? Number((1 / dominantFrequencyHz).toFixed(2)) : undefined;

  return {
    meanIntervalMs: Number(mean.toFixed(2)),
    stdDevIntervalMs: Number(stdDev.toFixed(2)),
    coefficientOfVariation: Number(cv.toFixed(3)),
    jitterPercentage: jitterPct,
    periodicityScore,
    hasSufficientSamples: true,
    sampleCount,
    dominantFrequencyHz,
    dominantPeriodSeconds,
    peakSpectralPower,
    statusMessage: `Spectral FFT completed across ${sampleCount} temporal samples. Dominant frequency: ${dominantFrequencyHz || 0} Hz.`
  };
}
