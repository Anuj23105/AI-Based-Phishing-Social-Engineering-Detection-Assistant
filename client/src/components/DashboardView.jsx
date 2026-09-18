/**
 * Dashboard: aggregate figures, recent checks, and the model card.
 *
 * The model card deliberately shows both the in-distribution and the gold-set
 * numbers. Quoting only the ~1.000 held-out split would be misleading, and the
 * gap between the two is the interesting part.
 */

import { useEffect, useState } from 'react';

import api from '../api.js';

function Stat({ value, label, tone }) {
  return (
    <div className={`stat ${tone || ''}`}>
      <div className="n">{value}</div>
      <div className="l">{label}</div>
    </div>
  );
}

function Bars({ items, labels }) {
  if (!items?.length) return <p className="empty">Nothing recorded yet.</p>;
  const max = Math.max(...items.map((i) => i.count));
  return (
    <div className="bars">
      {items.map((item) => (
        <div className="bar-row" key={item.id || item.domain}>
          <span>{labels?.[item.id] || item.id || item.domain}</span>
          <span className="bar-track">
            <span className="bar-fill" style={{ width: `${(item.count / max) * 100}%` }} />
          </span>
          <span className="bar-num">{item.count}</span>
        </div>
      ))}
    </div>
  );
}

function MetricRow({ label, metrics }) {
  if (!metrics) return null;
  return (
    <div className="bar-row" style={{ gridTemplateColumns: 'minmax(140px, 220px) minmax(0, 1fr)' }}>
      <span>{label}</span>
      <span className="v" style={{ fontFamily: 'var(--mono)', fontSize: '0.79rem', color: 'var(--text-dim)' }}>
        accuracy {(metrics.accuracy * 100).toFixed(1)}% · precision {(metrics.precision * 100).toFixed(1)}% ·
        recall {(metrics.recall * 100).toFixed(1)}% · FPR {(metrics.false_positive_rate * 100).toFixed(1)}%
        {metrics.samples ? ` · n=${metrics.samples}` : ''}
      </span>
    </div>
  );
}

export default function DashboardView({ refreshKey }) {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [reports, setReports] = useState([]);
  const [modelInfo, setModelInfo] = useState(null);
  const [modelError, setModelError] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [statsData, historyData, reportsData] = await Promise.all([
          api.stats(),
          api.history(15),
          api.reports(8)
        ]);
        if (cancelled) return;
        setStats(statsData);
        setHistory(historyData.items || []);
        setReports(reportsData.items || []);
        setError(null);
      } catch (err) {
        if (!cancelled) setError(err.message);
      }
      try {
        const info = await api.modelInfo();
        if (!cancelled) { setModelInfo(info); setModelError(null); }
      } catch (err) {
        if (!cancelled) setModelError(err.message);
      }
    })();
    return () => { cancelled = true; };
  }, [refreshKey]);

  if (error) {
    return <div className="notice error" role="alert"><strong>Could not load the dashboard.</strong> {error}</div>;
  }
  if (!stats) return <div className="panel"><p className="empty">Loading…</p></div>;

  return (
    <div>
      <div className="grid four" style={{ marginBottom: 16 }}>
        <Stat value={stats.totalAnalyses} label="Items analysed" />
        <Stat value={stats.byLevel.high || 0} label="High risk" tone="high" />
        <Stat value={stats.byLevel.medium || 0} label="Medium risk" tone="medium" />
        <Stat value={stats.byLevel.low || 0} label="Low risk" tone="low" />
      </div>

      <div className="grid two">
        <section className="panel">
          <div className="panel-head">
            <h3>Most common tactics seen</h3>
            <span className="panel-sub">across this instance</span>
          </div>
          <Bars items={stats.topTactics} labels={stats.tacticLabels} />
        </section>

        <section className="panel">
          <div className="panel-head">
            <h3>Domains seen most</h3>
            <span className="panel-sub">from analysed links</span>
          </div>
          <Bars items={stats.topDomains} />
        </section>
      </div>

      <section className="panel">
        <div className="panel-head">
          <h3>Model card</h3>
          <span className="panel-sub">
            {modelInfo ? 'live from the ML service' : 'ML service unavailable'}
          </span>
        </div>

        {modelError && (
          <div className="notice info">
            <strong>The ML service is not reachable, so no model metrics are available.</strong>
            <br />{modelError}
          </div>
        )}

        {modelInfo && (
          <>
            <div className="bars" style={{ marginBottom: 14 }}>
              <MetricRow
                label="Message model — gold set"
                metrics={modelInfo.gold_set_metrics?.message}
              />
              <MetricRow
                label="Message model — held-out split"
                metrics={modelInfo.message_model?.metrics}
              />
              <MetricRow
                label="URL model — gold set"
                metrics={modelInfo.gold_set_metrics?.url}
              />
              <MetricRow
                label="URL model — held-out split"
                metrics={modelInfo.url_model?.metrics}
              />
            </div>

            <div className="kv">
              <div>
                <span className="k">Message model</span>
                <span className="v">{modelInfo.message_model?.model || 'not trained'}</span>
              </div>
              <div>
                <span className="k">URL model</span>
                <span className="v">{modelInfo.url_model?.model || 'not trained'}</span>
              </div>
              <div>
                <span className="k">Decision threshold</span>
                <span className="v">
                  {modelInfo.thresholds?.message} ({modelInfo.thresholds?.source})
                </span>
              </div>
              <div>
                <span className="k">Training rows</span>
                <span className="v">
                  {modelInfo.message_model?.rows ?? '?'} messages, {modelInfo.url_model?.rows ?? '?'} URLs
                </span>
              </div>
              <div>
                <span className="k">Trained at</span>
                <span className="v">{modelInfo.message_model?.trained_at || 'unknown'}</span>
              </div>
            </div>

            <p className="panel-sub" style={{ marginTop: 12 }}>
              {modelInfo.gold_set_metrics?.note}
            </p>
          </>
        )}
      </section>

      <div className="grid two">
        <section className="panel">
          <div className="panel-head">
            <h3>Recent checks</h3>
            <span className="panel-sub">previews only, never full content</span>
          </div>
          {history.length === 0 ? (
            <p className="empty">No analyses yet.</p>
          ) : (
            <ul className="history">
              {history.map((item) => (
                <li key={item.id}>
                  <span className={`sc ${item.level}`}>{item.score}</span>
                  <span className="pv" title={item.preview}>
                    {item.preview || item.url || '(no preview)'}
                  </span>
                  <span className="tm">{new Date(item.analyzedAt).toLocaleTimeString()}</span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="panel">
          <div className="panel-head">
            <h3>Community reports</h3>
            <span className="panel-sub">feeds the threat-intel stage</span>
          </div>
          {reports.length === 0 ? (
            <p className="empty">
              No reports yet. Reporting a phishing message adds its domain to the local
              intelligence used by later checks.
            </p>
          ) : (
            <ul className="history">
              {reports.map((item) => (
                <li key={item.id} style={{ gridTemplateColumns: 'minmax(0, 1fr) auto' }}>
                  <span className="pv" title={item.url || item.preview}>
                    {item.domains?.join(', ') || item.preview || item.url}
                  </span>
                  <span className="tm">{new Date(item.reportedAt).toLocaleDateString()}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>

      <p className="panel-sub" style={{ marginTop: 14 }}>
        Average score {stats.averageScore}/100 · average analysis time {stats.averageDurationMs} ms ·
        storage driver: {stats.driver}
      </p>
    </div>
  );
}
