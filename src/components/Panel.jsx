export function Panel({ title, subtitle, children }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <div>
          <p className="eyebrow">{subtitle}</p>
          <h2>{title}</h2>
        </div>
        <button className="ghost">Customize</button>
      </div>
      <div>{children}</div>
    </div>
  );
}
