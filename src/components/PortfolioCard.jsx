export function PortfolioCard({ portfolio, segments }) {
  return (
    <div className="portfolio-card">
      <div className="card-head">
        <h3>Portfolio health</h3>
        <span className="pill">Live</span>
      </div>
      <div className="headline">
        <div>
          <p className="label">Net asset value</p>
          <h2>{portfolio.netAssetValue}</h2>
        </div>
        <div className="badge good">{portfolio.change}</div>
      </div>
      <div className="details">
        <div>
          <p className="label">Risk score</p>
          <p className="value">{portfolio.riskScore}</p>
        </div>
        <div>
          <p className="label">Liquidity days</p>
          <p className="value">{portfolio.liquidityDays}</p>
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
