/**
 * Destination Concentration Module
 * Evaluates traffic concentration using Herfindahl-Hirschman Index (HHI):
 * HHI = Σ s_i^2 where s_i is the proportion of traffic directed to destination i.
 */

import { ENGINE_CONFIG } from '../config';

export interface DestinationConcentrationResult {
  hhi: number; // 0.0 - 1.0 (normalized)
  primaryTarget: string;
  trafficShare: number; // percentage (0 - 100)
  interpretation: 'DISTRIBUTED' | 'MODERATE' | 'VERY_HIGH';
  interpretationText: string;
  topTargets: { destination: string; count: number; sharePercentage: number }[];
}

/**
 * Calculates normalized HHI across destination targets.
 */
export function calculateDestinationConcentration(
  destinations: string[],
  weights?: number[]
): DestinationConcentrationResult {
  if (!destinations || destinations.length === 0) {
    return {
      hhi: 0,
      primaryTarget: 'None',
      trafficShare: 0,
      interpretation: 'DISTRIBUTED',
      interpretationText: 'No destination traffic observed.',
      topTargets: []
    };
  }

  const counts: Map<string, number> = new Map();
  let totalVolume = 0;

  for (let i = 0; i < destinations.length; i++) {
    const dest = destinations[i];
    const weight = weights && weights[i] ? weights[i] : 1;
    counts.set(dest, (counts.get(dest) || 0) + weight);
    totalVolume += weight;
  }

  if (totalVolume === 0) totalVolume = 1;

  let sumSquaredShares = 0;
  const targetList: { destination: string; count: number; sharePercentage: number }[] = [];

  for (const [dest, count] of counts.entries()) {
    const share = count / totalVolume;
    sumSquaredShares += share * share;
    targetList.push({
      destination: dest,
      count,
      sharePercentage: Number((share * 100).toFixed(1))
    });
  }

  // Sort targets by traffic share descending
  targetList.sort((a, b) => b.count - a.count);

  const primary = targetList[0] || { destination: 'Unknown', count: 0, sharePercentage: 0 };
  const hhi = Number(sumSquaredShares.toFixed(3));

  let interpretation: 'DISTRIBUTED' | 'MODERATE' | 'VERY_HIGH' = 'DISTRIBUTED';
  let interpretationText = 'Low HHI: Healthy distributed traffic across multiple destination VIPs.';

  if (hhi >= ENGINE_CONFIG.concentration.targetedFloodThreshold) {
    interpretation = 'VERY_HIGH';
    interpretationText = `Very high HHI (${hhi}): Critical traffic concentration targeting ${primary.destination} (${primary.sharePercentage}% share) - possible targeted volumetric flood.`;
  } else if (hhi >= ENGINE_CONFIG.concentration.distributedThreshold) {
    interpretation = 'MODERATE';
    interpretationText = `Moderate HHI (${hhi}): Noticeable concentration on ${primary.destination} (${primary.sharePercentage}% share).`;
  }

  return {
    hhi,
    primaryTarget: primary.destination,
    trafficShare: primary.sharePercentage,
    interpretation,
    interpretationText,
    topTargets: targetList.slice(0, 5)
  };
}
