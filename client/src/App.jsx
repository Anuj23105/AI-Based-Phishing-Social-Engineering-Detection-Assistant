import { useCallback, useEffect, useState } from 'react';

import api from './api.js';
import AnalyzerView from './components/AnalyzerView.jsx';
import AwarenessView from './components/AwarenessView.jsx';
import DashboardView from './components/DashboardView.jsx';

const VIEWS = [
  { id: 'analyse', label: 'Analyse' },
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'learn', label: 'Awareness' }
];

/**
 * Live status of the three tiers. Showing which layers are actually up avoids
 * the worst failure mode of a layered system: silently running degraded and
 * reporting confident results anyway.
 */
function StatusStrip({ health }) {
  if (!health) {
    return (
      <div className="status-strip">
        <span className="chip"><span className="dot off" />connecting…</span>
      </div>
    );
  }

  const ml = health.layers?.ml;
  const ai = health.layers?.ai;
  const intel = health.layers?.intel;

  return (
    <div className="status-strip" role="status" aria-label="System status">
      <span className="chip">
        <span className="dot on" />
        <strong>Rule engine</strong> ready
      </span>
      <span className="chip" title={ml?.reachable ? `${ml.baseUrl}` : ml?.reason}>
        <span className={`dot ${ml?.reachable ? 'on' : 'off'}`} />
        <strong>ML models</strong> {ml?.reachable ? 'loaded' : 'offline'}
      </span>
      <span className="chip" title={ai?.reason || `${ai?.provider} / ${ai?.model}`}>
        <span className={`dot ${ai?.configured ? 'on' : 'off'}`} />
        <strong>LLM</strong> {ai?.configured ? ai.provider : 'not configured'}
      </span>
      <span className="chip" title={intel?.reason || 'Safe Browsing enabled'}>
        <span className={`dot ${intel?.safeBrowsing ? 'on' : 'warn'}`} />
        <strong>Threat intel</strong> {intel?.safeBrowsing ? 'Safe Browsing' : 'community only'}
      </span>
    </div>
  );
}

export default function App() {
  const [view, setView] = useState('analyse');
  const [health, setHealth] = useState(null);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const poll = async () => {
      try {
        const data = await api.health();
        if (!cancelled) setHealth(data);
      } catch {
        if (!cancelled) setHealth({ layers: {} });
      }
    };
    poll();
    const timer = setInterval(poll, 20_000);
    return () => { cancelled = true; clearInterval(timer); };
  }, []);

  const onAnalysed = useCallback(() => setRefreshKey((key) => key + 1), []);

  return (
    <div className="app">
      <header className="masthead">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">{'\u{1F6E1}'}</span>
          <div>
            <h1>PhishGuard AI</h1>
            <p>Explainable phishing &amp; social-engineering detection</p>
          </div>
        </div>
        <StatusStrip health={health} />
      </header>

      <nav className="tabs" role="tablist" aria-label="Sections">
        {VIEWS.map((item) => (
          <button
            key={item.id}
            type="button"
            role="tab"
            className="tab"
            aria-selected={view === item.id}
            onClick={() => setView(item.id)}
          >
            {item.label}
          </button>
        ))}
      </nav>

      <main>
        {view === 'analyse' && <AnalyzerView onAnalysed={onAnalysed} />}
        {view === 'dashboard' && <DashboardView refreshKey={refreshKey} />}
        {view === 'learn' && <AwarenessView />}
      </main>

      <footer className="footer">
        <span>
          Rule engine v{health?.engineVersion || '1.0.0'} · every verdict is explainable and every
          point is traceable
        </span>
        <span>
          Advisory only: verify anything involving money or credentials through an official channel.
        </span>
      </footer>
    </div>
  );
}
