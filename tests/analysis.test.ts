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
    expect(result.degreesOfFreedom).toBe(15);
    expect(result.criticalValue).toBe(24.996);
  });

  it('reports a concentrated valid sample as deviating', () => {
    const result = analyzePathUniformity(new Map([[0, 80]]), 16, 80);
    expect(result.consistent).toBe(false);
  });

  it('uses the threshold for the requested leaf count', () => {
    const result = analyzePathUniformity(new Map([[0, 5], [1, 5], [2, 5], [3, 5]]), 4, 20);
    expect(result.degreesOfFreedom).toBe(3);
    expect(result.criticalValue).toBe(7.815);
    expect(result.consistent).toBe(true);
  });

  it('rejects incomplete or out-of-range samples', () => {
    expect(() => analyzePathUniformity(new Map([[0, 3]]), 16, 4)).toThrow(/sum/i);
    expect(() => analyzePathUniformity(new Map([[16, 1]]), 16, 1)).toThrow(/outside/i);
    expect(() => analyzePathUniformity(new Map([[0, -1]]), 16, -1)).toThrow(/total/i);
  });
});
