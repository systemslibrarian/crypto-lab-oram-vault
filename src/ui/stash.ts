/** Render client plaintext as text nodes so stored values cannot become markup. */
export function renderStashContents(
  container: HTMLElement,
  stash: ReadonlyMap<number, Uint8Array>,
  formatData: (data: Uint8Array) => string,
): void {
  container.replaceChildren();
  if (stash.size === 0) {
    const empty = document.createElement('span');
    empty.style.color = 'var(--text2)';
    empty.style.fontSize = '0.8rem';
    empty.textContent = '(empty)';
    container.append(empty);
    return;
  }
  for (const [blockId, data] of stash) {
    const item = document.createElement('div');
    item.className = 'stash-block';
    item.textContent = `B${blockId}: ${formatData(data).substring(0, 12)}`;
    container.append(item);
  }
}
