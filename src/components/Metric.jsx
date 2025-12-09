const badgeClass = {
  good: 'good',
  caution: 'caution',
  neutral: 'neutral',
};

export function Metric({ label, value, trend, status = 'neutral', detail }) {
  return (
    <div className="metric">
      <div className="metric-top">
        <p className="label">{label}</p>
        {trend && <span className={`badge ${badgeClass[status]}`}>{trend}</span>}
      </div>
      <p className="value large">{value}</p>
      {detail && <p className="hint">{detail}</p>}
    </div>
  );
}
