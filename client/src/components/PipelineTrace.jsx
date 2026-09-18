/**
 * Renders the detection pipeline as the request actually executed it:
 *
 *   Input -> Text & URL Preprocessing -> Feature Extraction
 *         -> AI/ML Risk Analysis -> Risk Scoring -> Explanation + Safe Action
 *
 * Each stage shows what it produced and when, and the Feature Extraction stage
 * expands into the five feature groups. Stages that were skipped say so, which
 * is how the user can tell that (for example) the ML service was down rather
 * than silently absent.
 */

export default function PipelineTrace({ pipeline = [], featureGroups = [] }) {
  if (!pipeline.length) return null;

  return (
    <section className="panel" aria-labelledby="pipeline-heading">
      <div className="panel-head">
        <h3 id="pipeline-heading">Detection pipeline</h3>
        <span className="panel-sub">what ran, in order, with timings</span>
      </div>

      <ol className="pipeline">
        {pipeline.map((stage, index) => (
          <li key={stage.id} className={stage.status === 'skipped' ? 'skipped' : ''}>
            <div className="rail">
              <span className="node" aria-hidden="true">
                {stage.status === 'skipped' ? '\u2013' : index + 1}
              </span>
              <span className="line" />
            </div>

            <div className="stage">
              <div className="stage-name">
                <span>{stage.label}</span>
                <span className="stage-time">+{stage.at} ms</span>
                {stage.status === 'skipped' && (
                  <span className="mini-chip" style={{ fontSize: '0.68rem' }}>skipped</span>
                )}
              </div>

              {stage.summary && <p className="stage-summary">{stage.summary}</p>}

              {stage.id === 'feature-extraction' && featureGroups.length > 0 && (
                <div className="stage-groups">
                  {featureGroups.map((group) => (
                    <span key={group.id} className={`mini-chip ${group.hits ? 'hit' : ''}`}>
                      {group.label}
                      <b>{group.hits ? `${group.hits} · +${group.points}` : '0'}</b>
                    </span>
                  ))}
                </div>
              )}

              {stage.id === 'preprocessing' && stage.facts?.urls?.length > 0 && (
                <div className="stage-groups">
                  {stage.facts.urls.slice(0, 4).map((url) => (
                    <span key={url} className="mini-chip" title={url}>
                      {url.length > 46 ? `${url.slice(0, 46)}\u2026` : url}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </li>
        ))}
      </ol>
    </section>
  );
}
