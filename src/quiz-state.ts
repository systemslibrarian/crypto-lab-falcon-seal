// Quiz progress persistence. Stores which option was chosen per question so the
// score survives reloads and learners can come back to review what they missed.

export type QuizRecord = { chosenIdx: number; correct: boolean };

const STORAGE_KEY = 'falcon-seal-quiz-v1';

export function loadQuizState(): Record<string, QuizRecord> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as Record<string, QuizRecord>;
    return typeof parsed === 'object' && parsed !== null ? parsed : {};
  } catch {
    return {};
  }
}

export function saveQuizAnswer(id: string, record: QuizRecord): void {
  try {
    const state = loadQuizState();
    state[id] = record;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch {
    // Private-mode storage failures just mean no persistence — the quiz still works.
  }
}

export function resetQuizState(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
}
