export interface UniformityAnalysis {
  chiSq: number;
  expectedPerLeaf: number;
  degreesOfFreedom: number;
  criticalValue: number;
  consistent: boolean | null;
  verdict: string;
}

// Pearson chi-square 95th percentiles for df 1..30. The live lab uses df=15;
// the table keeps this helper honest if the teaching parameters are reduced.
const CHI_SQUARE_05 = [
  0,
  3.841, 5.991, 7.815, 9.488, 11.070, 12.592, 14.067, 15.507,
  16.919, 18.307, 19.675, 21.026, 22.362, 23.685, 24.996, 26.296,
  27.587, 28.869, 30.144, 31.410, 32.671, 33.924, 35.172, 36.415,
  37.652, 38.885, 40.113, 41.337, 42.557, 43.773,
];

/** Analyze one complete path sample without claiming more than it supports. */
export function analyzePathUniformity(
  pathCounts: ReadonlyMap<number, number>,
  numLeaves: number,
  total: number,
): UniformityAnalysis {
  if (!Number.isSafeInteger(numLeaves) || numLeaves < 2 || numLeaves > 31) {
    throw new RangeError('numLeaves must be an integer in [2, 31].');
  }
  if (!Number.isSafeInteger(total) || total < 0) {
    throw new RangeError('total must be a non-negative integer.');
  }

  let observedTotal = 0;
  for (const [leaf, count] of pathCounts) {
    if (!Number.isSafeInteger(leaf) || leaf < 0 || leaf >= numLeaves) {
      throw new RangeError(`Observed leaf ${leaf} is outside [0, ${numLeaves - 1}].`);
    }
    if (!Number.isSafeInteger(count) || count < 0) {
      throw new RangeError(`Observed count for leaf ${leaf} must be a non-negative integer.`);
    }
    observedTotal += count;
  }
  if (observedTotal !== total) {
    throw new RangeError(`Path counts sum to ${observedTotal}, not declared total ${total}.`);
  }

  const expectedPerLeaf = total / numLeaves;
  let chiSq = 0;
  for (let leaf = 0; leaf < numLeaves; leaf++) {
    const observed = pathCounts.get(leaf) ?? 0;
    if (expectedPerLeaf > 0) {
      chiSq += (observed - expectedPerLeaf) ** 2 / expectedPerLeaf;
    }
  }
  const degreesOfFreedom = numLeaves - 1;
  const criticalValue = CHI_SQUARE_05[degreesOfFreedom];
  if (criticalValue === undefined) throw new RangeError('No chi-square threshold for this sample.');
  const enoughData = expectedPerLeaf >= 5;
  const consistent = enoughData ? chiSq <= criticalValue : null;
  const verdict = !enoughData
    ? `Inconclusive: need ≥5 expected/leaf — run ${Math.ceil(5 * numLeaves)}+ accesses total.`
    : consistent
      ? 'This run is consistent with uniform paths (fail to reject H₀ at α=0.05).'
      : 'This run deviates from uniform at α=0.05 (expected for about 5% of uniform samples).';
  return {
    chiSq,
    expectedPerLeaf,
    degreesOfFreedom,
    criticalValue,
    consistent,
    verdict,
  };
}
