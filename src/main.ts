import '../styles/main.css';
import { renderApp } from './ui';

function setupThemeToggle(): void {
  const root = document.documentElement;
  const button = document.querySelector<HTMLButtonElement>('#theme-toggle');
  if (!button) {
    return;
  }

  const syncButton = (theme: 'dark' | 'light') => {
    button.textContent = theme === 'dark' ? '🌙' : '☀️';
    button.setAttribute('aria-label', theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
    button.setAttribute('aria-pressed', theme === 'dark' ? 'true' : 'false');
  };

  let theme: 'dark' | 'light' = root.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  root.setAttribute('data-theme', theme);
  syncButton(theme);

  button.addEventListener('click', () => {
    theme = theme === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    syncButton(theme);
  });
}

const app = document.querySelector<HTMLElement>('#app');
if (!app) {
  throw new Error('App root not found');
}

renderApp(app);
setupThemeToggle();
