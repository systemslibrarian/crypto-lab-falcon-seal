// Guided tour: a lightweight stepper that walks a newcomer through the demo in
// signing order — lattice, keygen, hash→challenge, rejection sampling, verify,
// tamper, side-channel, toy trapdoor, real WASM — highlighting the live panel
// and (where useful) pressing the buttons for them.

export type TourStep = {
  target: string; // CSS selector of the element to highlight
  title: string;
  body: string;
  action?: () => void | Promise<void>; // runs on entering the step
};

const HIGHLIGHT_CLASS = 'tour-highlight';

let activeCleanup: (() => void) | null = null;

export function isTourActive(): boolean {
  return activeCleanup !== null;
}

export function endTour(): void {
  activeCleanup?.();
}

export function startTour(steps: TourStep[]): void {
  endTour();
  if (steps.length === 0) return;

  let index = -1;
  let highlighted: Element | null = null;

  const card = document.createElement('div');
  card.className = 'tour-card';
  card.setAttribute('role', 'dialog');
  card.setAttribute('aria-label', 'Guided tour');
  document.body.appendChild(card);

  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const cleanup = () => {
    highlighted?.classList.remove(HIGHLIGHT_CLASS);
    card.remove();
    document.removeEventListener('keydown', onKeydown);
    activeCleanup = null;
  };
  activeCleanup = cleanup;

  const onKeydown = (event: KeyboardEvent) => {
    if (event.key === 'Escape') cleanup();
  };
  document.addEventListener('keydown', onKeydown);

  const show = async (nextIndex: number) => {
    if (nextIndex < 0 || nextIndex >= steps.length) {
      cleanup();
      return;
    }
    index = nextIndex;
    const step = steps[index];

    highlighted?.classList.remove(HIGHLIGHT_CLASS);
    highlighted = document.querySelector(step.target);
    highlighted?.classList.add(HIGHLIGHT_CLASS);
    highlighted?.scrollIntoView({ behavior: prefersReducedMotion ? 'auto' : 'smooth', block: 'center' });

    card.innerHTML = `
      <div class="tour-progress">Step ${index + 1} of ${steps.length}</div>
      <h3 class="tour-title" tabindex="-1">${step.title}</h3>
      <p class="tour-body">${step.body}</p>
      <div class="tour-actions">
        <button type="button" class="btn alt" data-tour="back" ${index === 0 ? 'disabled' : ''}>← Back</button>
        <button type="button" class="btn" data-tour="next">${index === steps.length - 1 ? 'Finish' : 'Next →'}</button>
        <button type="button" class="btn alt" data-tour="exit" aria-label="Exit tour">Exit</button>
      </div>
    `;
    card.querySelector<HTMLButtonElement>('[data-tour="back"]')?.addEventListener('click', () => void show(index - 1));
    card.querySelector<HTMLButtonElement>('[data-tour="next"]')?.addEventListener('click', () => void show(index + 1));
    card.querySelector<HTMLButtonElement>('[data-tour="exit"]')?.addEventListener('click', cleanup);
    card.querySelector<HTMLElement>('.tour-title')?.focus();

    try {
      await step.action?.();
    } catch {
      // A failed demo action shouldn't strand the tour; the narration still stands.
    }
  };

  void show(0);
}
