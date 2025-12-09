export function PortfolioCard({ integrity, segments }) {
  return (
    <div className="portfolio-card">
      <div className="card-head">
        <h3>Integrity snapshot</h3>
        <span className="pill">Live</span>
      </div>
      <div className="headline">
        <div>
          <p className="label">Watched directory</p>
          <h2>{integrity.directory}</h2>
        </div>
        <div className={`badge ${integrity.tone ?? 'neutral'}`}>{integrity.status}</div>
      </div>
      <div className="details">
        <div>
          <p className="label">Baseline coverage</p>
          <p className="value">{integrity.baselineFiles}</p>
        </div>
        <div>
          <p className="label">Baseline hash</p>
          <p className="value">{integrity.baselineHash}</p>
        </div>
      </div>
      <div className="details">
        <div>
          <p className="label">Last scan</p>
          <p className="value">{integrity.lastScan}</p>
        </div>
        <div>
          <p className="label">Log integrity</p>
          <p className="value">{integrity.logChain}</p>
        </div>
      </div>
      <div className="divider" />
      <div className="segments">
        {segments.map((segment) => (
          <div key={segment.title} className="segment">
            <div className="segment-top">
              <p className="label">{segment.title}</p>
              <strong>{segment.value}</strong>
            </div>
            <p className="hint">{segment.detail}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
