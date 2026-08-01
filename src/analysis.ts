export interface UniformityAnalysis {
  chiSq: number;
  expectedPerLeaf: number;
  consistent: boolean | null;
  verdict: string;
}

/** Analyze observed paths without claiming more than this run demonstrates. */
export function analyzePathUniformity(
  pathCounts: ReadonlyMap<number, number>,
  numLeaves: number,
  total: number,
): UniformityAnalysis {
  const expectedPerLeaf = total / numLeaves;
  let chiSq = 0;
  for (let i = 0; i < numLeaves; i++) {
    const observed = pathCounts.get(i) ?? 0;
    chiSq += expectedPerLeaf === 0 ? 0 : (observed - expectedPerLeaf) ** 2 / expectedPerLeaf;
  }
  const enoughData = expectedPerLeaf >= 5;
  const consistent = enoughData ? chiSq <= 24.996 : null;
  const verdict = !enoughData
    ? `Inconclusive: need ≥5 expected/leaf — run ${Math.ceil(5 * numLeaves)}+ accesses total.`
    : consistent
      ? 'This run is consistent with uniform paths (fail to reject H₀ at α=0.05).'
      : 'This run deviates from uniform at α=0.05 (expected for about 5% of uniform samples).';
  return { chiSq, expectedPerLeaf, consistent, verdict };
}
