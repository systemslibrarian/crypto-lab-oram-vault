// @vitest-environment happy-dom
import { describe, expect, it } from 'vitest';
import { renderStashContents } from '../src/ui/stash.js';

describe('plaintext rendering boundary', () => {
  it('renders stored text literally instead of interpreting markup', () => {
    const container = document.createElement('div');
    const stash = new Map([[7, new Uint8Array([1])]]);
    renderStashContents(container, stash, () => '<img src=x>');
    expect(container.textContent).toBe('B7: <img src=x>');
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('.stash-block')).not.toBeNull();
  });
});
