import './index.css';
import { PortfolioCard } from './components/PortfolioCard';
import { Panel } from './components/Panel';
import { Timeline } from './components/Timeline';
import { Metric } from './components/Metric';

const integrity = {
  directory: '/var/secure/watch',
  status: 'Clean baseline',
  tone: 'good',
  baselineFiles: '327 files hashed',
  baselineHash: 'SHA-256 chain ok',
  lastScan: '10:15:23 UTC',
  logChain: 'HMAC sealed logs',
};

const segments = [
  { title: 'Creates', value: '2 (24h)', detail: 'New policy.yml and agent.conf allowlist' },
  { title: 'Modifies', value: '5', detail: 'config.yaml, sudoers (T1547 Init)', },
  { title: 'Deletes', value: '0', detail: 'Quarantine on delete prevents loss' },
];

const guardrailMetrics = [
  { label: 'Baseline coverage', value: '327 files', trend: '+12 new', status: 'good', detail: 'Hidden/PII skipped per policy' },
  { label: 'Hash chain health', value: 'Stable', trend: 'OK', status: 'good', detail: 'SHA-256 + HMAC per log entry' },
  { label: 'Alerts last 24h', value: '5', trend: '3 high', status: 'caution', detail: 'Mapped to T1547, T1070, T1562' },
  { label: 'Mean time to respond', value: '12m', trend: '-4m', status: 'good', detail: 'Auto ticket + Slack dispatch' },
];

const alerts = [
  {
    time: '10:12:48',
    severity: 'critical',
    title: 'Sensitive config modified',
    description: 'config.yaml tampered outside maintenance window. MITRE T1547 (persistence).',
  },
  {
    time: '09:51:03',
    severity: 'high',
    title: 'Unexpected binary created',
    description: 'New file /var/secure/watch/tmp/.helper flagged as executable. T1059 (execution).',
  },
  {
    time: '09:15:22',
    severity: 'high',
    title: 'Log chain verification failed (resolved)',
    description: 'Previous block hash mismatch auto-healed via backup copy.',
  },
];

const activities = [
  {
    time: '10:13:10',
    title: 'Auto-reverted config.yaml',
    description: 'Restored trusted hash, opened ticket RIM-184, alerted SecOps.',
    actor: 'FIM agent',
  },
  {
    time: '10:05:40',
    title: 'Baseline refresh queued',
    description: 'Scheduled rescan after policy change; personal data paths excluded.',
    actor: 'Change manager',
  },
  {
    time: '09:52:10',
    title: 'Process snapshot taken',
    description: 'Collected ps aux + open files for correlation. MITRE T1057 (discovery).',
    actor: 'FIM agent',
  },
  {
    time: '09:30:00',
    title: 'Audit export generated',
    description: 'Signed CSV of create/modify/delete events for compliance.',
    actor: 'Reporting bot',
  },
];

export default function App() {
  return (
    <div className="app-shell">
      <header className="hero">
        <div>
          <p className="eyebrow">Real-time file integrity monitoring</p>
          <h1>Watch critical directories with secure baselines</h1>
          <p className="subtext">
            Highlight what changed, when, and why it matters—aligned to MITRE tactics—while protecting privacy and log integrity.
          </p>
          <div className="chips">
            <span className="chip">Create / Modify / Delete</span>
            <span className="chip">Hash-chained logs</span>
            <span className="chip">PII-aware policies</span>
          </div>
        </div>
        <div className="filters">
          <div className="filter">
            <label>Directory</label>
            <select>
              <option>/var/secure/watch</option>
              <option>/etc</option>
              <option>/opt/apps</option>
            </select>
          </div>
          <div className="filter">
            <label>Window</label>
            <select>
              <option>Last hour</option>
              <option>24h</option>
              <option>7d</option>
            </select>
          </div>
          <div className="filter">
            <label>Alert level</label>
            <select>
              <option>Critical / High</option>
              <option>All severities</option>
              <option>Mute low</option>
            </select>
          </div>
        </div>
      </header>

      <main>
        <section className="grid">
          <Panel title="Integrity overview" subtitle="Baseline health, coverage, and recent change rates">
            <div className="overview-grid">
              <PortfolioCard integrity={integrity} segments={segments} />
              <div className="stacked">
                <div className="row">
                  <Metric label="Baseline freshness" value="6m ago" status="good" detail="Auto rescan after updates" />
                  <Metric label="PII exclusions" value="12 paths" status="neutral" detail="/home/* and temp caches" />
                </div>
                <div className="row">
                  <Metric label="Open tickets" value="3" status="caution" detail="2 high, 1 medium" />
                  <Metric label="Alerts routed" value="Slack + SIEM" status="good" detail="Webhook + syslog mirror" />
                </div>
              </div>
            </div>
          </Panel>

          <Panel title="Detection & Integrity" subtitle="Hash coverage, alert volume, and response times">
            <div className="metrics-grid">
              {guardrailMetrics.map((metric) => (
                <Metric key={metric.label} {...metric} />
              ))}
            </div>
            <div className="dual">
              <Timeline title="Priority alerts" items={alerts} emphasize />
              <Timeline title="Latest actions" items={activities} />
            </div>
          </Panel>

          <Panel title="Governance & Export" subtitle="Share evidence, policies, and audit artifacts">
            <div className="exports">
              <div className="export-card">
                <h3>Audit log</h3>
                <p>Download hash-chained create/modify/delete timeline with UTC stamps.</p>
                <button>Download CSV</button>
                <button className="ghost">Copy webhook URL</button>
              </div>
              <div className="export-card">
                <h3>Policy</h3>
                <p>Manage exclusions to avoid personal data and tune MITRE mapping.</p>
                <button>Update policy</button>
                <button className="ghost">View diff</button>
              </div>
              <div className="export-card">
                <h3>Integrity checks</h3>
                <p>Verify log chain, baseline hash, and tamper flags across nodes.</p>
                <button>Run verification</button>
                <button className="ghost">View last proof</button>
              </div>
            </div>
          </Panel>
        </section>
      </main>
    </div>
  );
}
