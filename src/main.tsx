import { createRoot } from 'react-dom/client';
import { registerSW } from 'virtual:pwa-register';
import App from './App.tsx';
import './index.css';

// Registra el Service Worker local para operación 100% sin conexión
registerSW({ immediate: true });

createRoot(document.getElementById('root')!).render(<App />);
