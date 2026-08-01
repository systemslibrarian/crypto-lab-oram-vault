import { describe, expect, it } from 'vitest';
import { analyzePathUniformity } from '../src/analysis.ts';

describe('path-uniformity verdicts', () => {
  it('reports the initial 20-access sample as inconclusive', () => {
    const result = analyzePathUniformity(new Map([[0, 20]]), 16, 20);
    expect(result.consistent).toBeNull();
    expect(result.verdict).toMatch(/^Inconclusive/);
  });

  it('reports a balanced valid sample as consistent', () => {
    const counts = new Map(Array.from({ length: 16 }, (_, leaf) => [leaf, 5]));
    const result = analyzePathUniformity(counts, 16, 80);
    expect(result.consistent).toBe(true);
  });

  it('reports a concentrated valid sample as deviating', () => {
    const result = analyzePathUniformity(new Map([[0, 80]]), 16, 80);
    expect(result.consistent).toBe(false);
  });
});
