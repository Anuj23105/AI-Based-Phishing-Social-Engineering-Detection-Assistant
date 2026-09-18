/**
 * Risk gauge and verdict header.
 *
 * The score is communicated three ways at once — number, colour and text label —
 * so the meaning survives colour blindness, greyscale printing and screen
 * readers. The gauge is decorative (aria-hidden); the accessible value lives in
 * the adjacent text.
 */

const LEVEL_COLOR = { low: 'var(--low)', medium: 'var(--medium)', high: 'var(--high)' };
const LEVEL_ICON = { low: '\u2713', medium: '\u26A0', high: '\u2715' };

function Gauge({ score, level }) {
  const radius = 56;
  const stroke = 11;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - Math.min(100, Math.max(0, score)) / 100);

  return (
    <div className="gauge" aria-hidden="true">
      <svg width="132" height="132" viewBox="0 0 132 132">
        <circle cx="66" cy="66" r={radius} fill="none" stroke="var(--border)" strokeWidth={stroke} />
        <circle
          cx="66"
          cy="66"
          r={radius}
          fill="none"
          stroke={LEVEL_COLOR[level]}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
      </svg>
      <div className="gauge-value">
        <div className="score" style={{ color: LEVEL_COLOR[level] }}>{score}</div>
        <div className="out-of">OUT OF 100</div>
      </div>
    </div>
  );
}

export default function Verdict({ result }) {
  const { score, level, levelLabel, confidence, explanation, timings, ml, ai, engine } = result;

  return (
    <section className="panel" aria-labelledby="verdict-heading">
      <h2 id="verdict-heading" className="visually-hidden">Risk assessment</h2>
      <div className="verdict">
        <Gauge score={score} level={level} />

        <div className="verdict-body">
          <div className={`verdict-level ${level}`}>
            <span aria-hidden="true">{LEVEL_ICON[level]}</span>
            <span>
              Risk Score: {score}/100 — {levelLabel}
            </span>
          </div>

          <p className="verdict-summary">{explanation.summary}</p>

          {explanation.aiNarrative && (
            <p className="verdict-summary" style={{ color: 'var(--text-dim)', fontSize: '0.88rem' }}>
              <strong style={{ color: 'var(--accent)' }}>AI review: </strong>
              {explanation.aiNarrative}
            </p>
          )}

          <div className="verdict-meta">
            <span>{explanation.confidenceLabel} ({Math.round(confidence * 100)}%)</span>
            <span>Analysed in {timings?.totalMs ?? result.durationMs} ms</span>
            <span>
              {engine.mode === 'heuristic'
                ? 'Rule engine only'
                : `Rules${ml?.used ? ' + ML' : ''}${ai?.used ? ' + LLM' : ''}`}
            </span>
            {result.input.channel && <span>Input: {result.input.channel}</span>}
          </div>
        </div>
      </div>
    </section>
  );
}
