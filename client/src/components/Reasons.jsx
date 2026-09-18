/**
 * The explainability surface: why this verdict, what makes it dangerous, and
 * which signals argued the other way.
 *
 * Trust indicators are shown as prominently as risk indicators on purpose. A
 * tool that only ever explains why something is bad teaches users nothing about
 * what "safe" looks like.
 */

export function Reasons({ reasons = [] }) {
  if (!reasons.length) {
    return (
      <section className="panel" aria-labelledby="reasons-heading">
        <div className="panel-head">
          <h3 id="reasons-heading">Why this verdict</h3>
        </div>
        <p className="empty">
          No risk indicators fired. Nothing in the wording, links or sender matched a known
          phishing or social-engineering pattern.
        </p>
      </section>
    );
  }

  return (
    <section className="panel" aria-labelledby="reasons-heading">
      <div className="panel-head">
        <h3 id="reasons-heading">Why this verdict</h3>
        <span className="panel-sub">{reasons.length} indicator{reasons.length > 1 ? 's' : ''}, strongest first</span>
      </div>

      <ol className="reasons">
        {reasons.map((reason) => (
          <li key={reason.id} className={`reason ${reason.severity}`}>
            <span className="reason-rank" aria-hidden="true">{reason.rank}</span>
            <div>
              <div className="reason-title">{reason.title}</div>
              <div className="reason-cat">{reason.categoryLabel}</div>
              <p className="reason-detail">{reason.explanation}</p>
              {reason.evidence && <div className="reason-evidence">{reason.evidence}</div>}
            </div>
            <span className="reason-points" title="Evidence points contributed">
              +{reason.contribution}
            </span>
          </li>
        ))}
      </ol>
    </section>
  );
}

export function TrustIndicators({ indicators = [] }) {
  if (!indicators.length) return null;
  return (
    <section className="panel" aria-labelledby="trust-heading">
      <div className="panel-head">
        <h3 id="trust-heading">Signals in its favour</h3>
        <span className="panel-sub">these reduced the score</span>
      </div>
      <ul className="trust">
        {indicators.map((item) => (
          <li key={item.id}>
            <span aria-hidden="true">{'\u2713'}</span>
            <span>
              <strong>{item.title}.</strong> {item.explanation}
            </span>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function Recommendations({ recommendations = [], level }) {
  if (!recommendations.length) return null;
  return (
    <section className="panel" aria-labelledby="actions-heading">
      <div className="panel-head">
        <h3 id="actions-heading">What you should do</h3>
        <span className="panel-sub">
          {level === 'high' ? 'act on all of these' : level === 'medium' ? 'verify before acting' : 'general good practice'}
        </span>
      </div>
      <ol className="actions">
        {recommendations.map((item, index) => (
          <li key={item}>
            <span className="num" aria-hidden="true">{index + 1}</span>
            <span>{item}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}

export function Tactics({ tactics = [] }) {
  if (!tactics.length) return null;
  return (
    <section className="panel" aria-labelledby="tactics-heading">
      <div className="panel-head">
        <h3 id="tactics-heading">Manipulation tactics detected</h3>
        <span className="panel-sub">{tactics.length} technique{tactics.length > 1 ? 's' : ''} in play</span>
      </div>
      <div className="grid two">
        {tactics.map((tactic) => (
          <article key={tactic.id} className="tactic-card">
            <h4>{tactic.label}</h4>
            <p>{tactic.why}</p>
            {tactic.evidence?.length > 0 && (
              <div className="quote">
                {tactic.evidence.slice(0, 2).map((e) => `\u201C${e}\u201D`).join('  \u00B7  ')}
              </div>
            )}
          </article>
        ))}
      </div>
    </section>
  );
}
