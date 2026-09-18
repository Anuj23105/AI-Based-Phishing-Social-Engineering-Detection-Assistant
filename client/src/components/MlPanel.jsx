/**
 * Machine-learning panel.
 *
 * Shows the probability, the decision threshold it was compared against, and the
 * exact token / feature contributions that produced it. Because both served
 * models are linear, these contributions are the real arithmetic behind the
 * number — not a post-hoc approximation.
 *
 * When the ML service is down this panel explains that plainly instead of
 * disappearing, so a demo never silently loses a tier.
 */

function ProbabilityBar({ probability, threshold }) {
  const pct = Math.round(probability * 100);
  const colour = probability >= 0.6 ? 'var(--high)' : probability >= (threshold ?? 0.34) ? 'var(--medium)' : 'var(--low)';
  return (
    <>
      <div
        className="prob-bar"
        role="img"
        aria-label={`Phishing probability ${pct} percent`}
      >
        <span style={{ width: `${Math.max(2, pct)}%`, background: colour }} />
      </div>
      <div className="prob-scale">
        <span>0% legitimate</span>
        {threshold != null && <span>threshold {Math.round(threshold * 100)}%</span>}
        <span>100% phishing</span>
      </div>
    </>
  );
}

function Indicators({ items = [], emptyLabel }) {
  if (!items.length) return <p className="panel-sub">{emptyLabel}</p>;
  return (
    <ul className="indicators">
      {items.map((item, index) => (
        <li key={`${item.token || item.feature || index}`}>
          <span>
            {item.description}
            {item.value != null && (
              <span style={{ color: 'var(--text-faint)' }}> (value {item.value})</span>
            )}
          </span>
          <span className={`contrib ${item.contribution > 0 ? 'up' : 'down'}`}>
            {item.contribution > 0 ? '+' : ''}{item.contribution.toFixed(2)}
          </span>
        </li>
      ))}
    </ul>
  );
}

export default function MlPanel({ ml }) {
  if (!ml?.used) {
    return (
      <section className="panel" aria-labelledby="ml-heading">
        <div className="panel-head">
          <h3 id="ml-heading">Machine-learning analysis</h3>
          <span className="chip"><span className="dot off" />unavailable</span>
        </div>
        <div className="notice info">
          <strong>The ML tier did not contribute to this verdict.</strong>
          <br />
          {ml?.reason || 'The ML service was not reachable.'}
          <br />
          <span style={{ color: 'var(--text-faint)' }}>
            The score above comes from the rule engine alone, which runs entirely offline. To enable
            the models, start the Python service: <code>cd ml</code> then{' '}
            <code>.venv\Scripts\python -m uvicorn app.main:app --port 8000</code>
          </span>
        </div>
      </section>
    );
  }

  return (
    <section className="panel" aria-labelledby="ml-heading">
      <div className="panel-head">
        <h3 id="ml-heading">Machine-learning analysis</h3>
        <span className="panel-sub">
          {ml.models.join(' + ')} model{ml.models.length > 1 ? 's' : ''} · {ml.latencyMs} ms
          {ml.degraded ? ' · partially degraded' : ''}
        </span>
      </div>

      {ml.message && (
        <div style={{ marginBottom: ml.url ? 20 : 0 }}>
          <div className="row spread">
            <strong style={{ fontSize: '0.9rem' }}>Message classifier</strong>
            <span className="mini-chip">
              {Math.round(ml.message.probability * 100)}% phishing · {ml.message.label}
            </span>
          </div>
          <ProbabilityBar probability={ml.message.probability} threshold={ml.message.threshold} />
          <p className="panel-sub" style={{ marginTop: 10 }}>
            Token contributions to the decision (positive pushes towards phishing):
          </p>
          <Indicators items={ml.message.topIndicators} emptyLabel="No individual token stood out." />
        </div>
      )}

      {ml.url && (
        <div>
          <div className="row spread">
            <strong style={{ fontSize: '0.9rem' }}>URL classifier</strong>
            <span className="mini-chip">
              {Math.round(ml.url.probability * 100)}% phishing · {ml.url.label}
            </span>
          </div>
          <ProbabilityBar probability={ml.url.probability} threshold={0.5} />
          <p className="panel-sub" style={{ marginTop: 10 }}>
            Lexical features that drove the decision:
          </p>
          <Indicators items={ml.url.topIndicators} emptyLabel="No individual feature stood out." />
        </div>
      )}
    </section>
  );
}
