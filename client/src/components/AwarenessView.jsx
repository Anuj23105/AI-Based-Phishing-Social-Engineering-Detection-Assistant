/**
 * Awareness and training.
 *
 * The product goal is not only detection but changing behaviour, so the tactic
 * library and the scoring rules are published rather than hidden. A user who
 * understands *why* "verify within 24 hours" is a tactic can spot the next
 * campaign without any tool.
 */

import { useEffect, useState } from 'react';

import api from '../api.js';

export default function AwarenessView() {
  const [tips, setTips] = useState([]);
  const [tactics, setTactics] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [tipsData, tacticsData] = await Promise.all([api.tips(), api.tactics()]);
        if (cancelled) return;
        setTips(tipsData.tips || []);
        setTactics(tacticsData);
      } catch (err) {
        if (!cancelled) setError(err.message);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  if (error) {
    return <div className="notice error" role="alert"><strong>Could not load awareness content.</strong> {error}</div>;
  }

  return (
    <div>
      <section className="panel">
        <div className="panel-head">
          <h2>Eight habits that stop most phishing</h2>
          <span className="panel-sub">no tool required</span>
        </div>
        <div className="grid two">
          {tips.map((tip) => (
            <article key={tip.id} className="tactic-card">
              <h4>{tip.title}</h4>
              <p>{tip.body}</p>
            </article>
          ))}
        </div>
      </section>

      {tactics && (
        <>
          <section className="panel">
            <div className="panel-head">
              <h2>Social-engineering tactic library</h2>
              <span className="panel-sub">
                {tactics.tactics.length} techniques the engine recognises
              </span>
            </div>
            <div className="grid two">
              {tactics.tactics.map((tactic) => (
                <article key={tactic.id} className="tactic-card">
                  <h4>{tactic.label}</h4>
                  <p>{tactic.why}</p>
                  <div className="quote">
                    {tactic.patternCount} detection patterns · up to {tactic.maxPoints} evidence points ·
                    {' '}{tactic.categoryLabel}
                  </div>
                </article>
              ))}
            </div>
          </section>

          <section className="panel">
            <div className="panel-head">
              <h2>How scoring works</h2>
              <span className="panel-sub">published so results can be audited</span>
            </div>
            <p style={{ color: 'var(--text-dim)', marginBottom: 14 }}>{tactics.scoring.note}</p>
            <div className="bars">
              {Object.entries(tactics.scoring.categoryCaps).map(([category, cap]) => (
                <div className="bar-row" key={category}>
                  <span>{category}</span>
                  <span className="bar-track">
                    <span className="bar-fill" style={{ width: `${(cap / 65) * 100}%` }} />
                  </span>
                  <span className="bar-num">{cap}</span>
                </div>
              ))}
            </div>
            <p className="panel-sub" style={{ marginTop: 12 }}>
              Maximum evidence points each category can contribute. Bands: 0–
              {tactics.scoring.thresholds.low} low, {tactics.scoring.thresholds.low + 1}–
              {tactics.scoring.thresholds.medium} medium, {tactics.scoring.thresholds.medium + 1}–100 high.
            </p>
          </section>

          <section className="panel">
            <div className="panel-head">
              <h2>Where to report phishing</h2>
            </div>
            <div className="kv">
              <div>
                <span className="k">India — portal</span>
                <span className="v"><a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer noopener">cybercrime.gov.in</a></span>
              </div>
              <div><span className="k">India — helpline</span><span className="v">1930</span></div>
              <div><span className="k">Global</span><span className="v">reportphishing@apwg.org</span></div>
              <div>
                <span className="k">Your provider</span>
                <span className="v">Use the built-in "Report phishing" action in your mail or messaging app</span>
              </div>
            </div>
            <p className="panel-sub" style={{ marginTop: 12 }}>
              If money has already moved, report within the first hours: many banks can freeze a
              transfer while it is still in the beneficiary account.
            </p>
          </section>
        </>
      )}
    </div>
  );
}
