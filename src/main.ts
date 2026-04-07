import '../styles/main.css';
import { renderApp } from './ui';

if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
  document.documentElement.dataset.theme = 'dark';
}

const app = document.querySelector<HTMLElement>('#app');
if (!app) {
  throw new Error('App root not found');
}

renderApp(app);
