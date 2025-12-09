const severityMap = {
  critical: 'critical',
  high: 'high',
  medium: 'caution',
  low: 'neutral',
};

export function Timeline({ title, items, emphasize = false }) {
  return (
    <div className={`timeline ${emphasize ? 'emphasize' : ''}`}>
      <div className="timeline-head">
        <h3>{title}</h3>
        <button className="ghost">View all</button>
      </div>
      <ul>
        {items.map((item, index) => (
          <li key={`${item.time}-${index}`}>
            <div className="time">{item.time}</div>
            <div className="content">
              <div className="title-row">
                <p className="title">{item.title}</p>
                {item.severity && <span className={`badge ${severityMap[item.severity]}`}>{item.severity}</span>}
                {item.actor && <span className="actor">{item.actor}</span>}
              </div>
              <p className="description">{item.description}</p>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
