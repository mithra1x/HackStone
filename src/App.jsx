import './index.css';
import { PortfolioCard } from './components/PortfolioCard';
import { Panel } from './components/Panel';
import { Timeline } from './components/Timeline';
import { Metric } from './components/Metric';

const portfolio = {
  netAssetValue: '$4.2B',
  change: '+1.3% WoW',
  riskScore: 'Low',
  liquidityDays: '14.2',
};

const segments = [
  { title: 'Assets', value: '$3.7B', detail: 'Equities, fixed income, alternatives' },
  { title: 'Liabilities', value: '$1.5B', detail: 'Short-term notes, credit facilities' },
  { title: 'Unrealized P&L', value: '+$42M', detail: 'Driven by growth in healthcare & energy' },
];

const riskMetrics = [
  { label: 'VaR (95%, 1d)', value: '$18.5M', trend: '+0.6%', status: 'caution' },
  { label: 'Duration', value: '4.8y', trend: '-0.2y', status: 'good' },
  { label: 'Convexity', value: '0.32', trend: '+0.03', status: 'neutral' },
  { label: 'Liquidity Coverage', value: '118%', trend: '+6%', status: 'good' },
];

const alerts = [
  {
    time: '09:42',
    severity: 'critical',
    title: 'Liquidity drawdown exceeds threshold',
    description: 'Short-term facility utilization climbed to 76% after settlement.',
  },
  {
    time: '09:10',
    severity: 'high',
    title: 'Stress test breach: credit spread widening',
    description: 'Credit stress scenario shows -4.8% loss versus -3% tolerance.',
  },
  {
    time: '08:25',
    severity: 'medium',
    title: 'Limit utilization trending upward',
    description: 'Hedge book consumed 67% of options budget this week.',
  },
];

const activities = [
  {
    time: '10:15',
    title: 'Rebalanced tactical tilt',
    description: 'Shifted +1.5% into cash, trimmed growth sleeve to reduce beta.',
    actor: 'Auto-policy',
  },
  {
    time: '09:58',
    title: 'Executed liquidity ladder roll',
    description: 'Rolled $75M commercial paper into 30-day buckets; improved coverage.',
    actor: 'Trader L. Bennett',
  },
  {
    time: '09:21',
    title: 'Risk scenario rerun',
    description: 'Updated macro shock inputs; VaR drift contained under target band.',
    actor: 'Risk Engine',
  },
  {
    time: '08:47',
    title: 'New data export',
    description: 'Generated holdings pack and exposure by currency for Treasury.',
    actor: 'Reporting Bot',
  },
];

export default function App() {
  return (
    <div className="app-shell">
      <header className="hero">
        <div>
          <p className="eyebrow">Unified finance command center</p>
          <h1>Portfolio, liquidity, and risk in one view</h1>
          <p className="subtext">
            Track priority actions with live status, surface alerts by severity, and export reports without
            switching contexts.
          </p>
          <div className="chips">
            <span className="chip">Real-time</span>
            <span className="chip">Single page</span>
            <span className="chip">Enterprise-ready</span>
          </div>
        </div>
        <div className="filters">
          <div className="filter">
            <label>Portfolio</label>
            <select>
              <option>Global Multi-Strategy</option>
              <option>Core Fixed Income</option>
              <option>Alternatives</option>
            </select>
          </div>
          <div className="filter">
            <label>View</label>
            <select>
              <option>Today</option>
              <option>7D</option>
              <option>MTD</option>
              <option>QTD</option>
            </select>
          </div>
          <div className="filter">
            <label>Priority</label>
            <select>
              <option>Critical & High</option>
              <option>All Alerts</option>
              <option>Mute Low</option>
            </select>
          </div>
        </div>
      </header>

      <main>
        <section className="grid">
          <Panel title="Overview" subtitle="Momentum, coverage, and headline risk">
            <div className="overview-grid">
              <PortfolioCard portfolio={portfolio} segments={segments} />
              <div className="stacked">
                <div className="row">
                  <Metric label="Cash runway" value="7.5 months" status="good" detail="Powered by liquidity ladder" />
                  <Metric label="Counterparty" value="97% clean" status="good" detail="No pending breaks" />
                </div>
                <div className="row">
                  <Metric label="Open exceptions" value="3" status="caution" detail="2 liquidity, 1 risk" />
                  <Metric label="Reports ready" value="12" status="neutral" detail="Exports updated 5m ago" />
                </div>
              </div>
            </div>
          </Panel>

          <Panel title="Risk & Liquidity" subtitle="Track coverage, stress, and sensitivity"> 
            <div className="metrics-grid">
              {riskMetrics.map((metric) => (
                <Metric key={metric.label} {...metric} />
              ))}
            </div>
            <div className="dual">
              <Timeline title="Priority alerts" items={alerts} emphasize />
              <Timeline title="Latest activity" items={activities} />
            </div>
          </Panel>

          <Panel title="Exports & Admin" subtitle="Share insights and keep guardrails in place">
            <div className="exports">
              <div className="export-card">
                <h3>Reports & Data</h3>
                <p>Export holdings, exposure by factor, and liquidity ladders in a single click.</p>
                <button>Generate pack</button>
                <button className="ghost">Schedule send</button>
              </div>
              <div className="export-card">
                <h3>Controls</h3>
                <p>Manage thresholds, approvals, and notification routing across teams.</p>
                <button>Open settings</button>
                <button className="ghost">Audit log</button>
              </div>
              <div className="export-card">
                <h3>Access</h3>
                <p>Review entitlements and track sign-ins to maintain clean governance.</p>
                <button>Review access</button>
                <button className="ghost">Download policy</button>
              </div>
            </div>
          </Panel>
        </section>
      </main>
    </div>
  );
}
