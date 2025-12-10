const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const WATCH_DIR = path.join(ROOT, 'watched');
const DATA_DIR = path.join(ROOT, 'data');
const LOG_DIR = path.join(ROOT, 'logs');
const PUBLIC_DIR = path.join(ROOT, 'public');
const CONFIG_DIR = path.join(ROOT, 'config');
const BASELINE_FILE = path.join(DATA_DIR, 'baseline.json');
const LOG_FILE = path.join(LOG_DIR, 'fim.log');
const METADATA_RULES_FILE = path.join(CONFIG_DIR, 'metadata-rules.json');
const ENVIRONMENT_NAME = process.env.FIM_ENV || process.env.NODE_ENV || 'dev';

const IGNORE_NAMES = new Set(['.DS_Store', 'baseline.json', 'fim.log']);
const GOVERNANCE_KEYWORDS = /(personal|private|secret|pii)/i;

let baseline = {};
let eventHistory = [];
const sseClients = new Set();

const MITRE_LOOKUP = {
  create: { id: 'T1587', name: 'Develop Capabilities' },
  modify: { id: 'T1565', name: 'Stored Data Manipulation' },
  delete: { id: 'T1485', name: 'Data Destruction' }
};

const AI_BASELINE = {
  create: 25,
  modify: 45,
  delete: 65
};

function ensureDirectories() {
  [WATCH_DIR, DATA_DIR, LOG_DIR, PUBLIC_DIR, CONFIG_DIR].forEach((dir) => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });
  if (!fs.existsSync(BASELINE_FILE)) {
    fs.writeFileSync(BASELINE_FILE, JSON.stringify({}, null, 2));
  }
  if (!fs.existsSync(LOG_FILE)) {
    fs.writeFileSync(LOG_FILE, '');
  }
}

let metadataRulesCache = null;

async function loadMetadataRules() {
  if (metadataRulesCache) return metadataRulesCache;
  try {
    const raw = await fs.promises.readFile(METADATA_RULES_FILE, 'utf-8');
    metadataRulesCache = JSON.parse(raw || '[]');
  } catch (err) {
    metadataRulesCache = [];
  }
  return metadataRulesCache;
}

function isEnvAllowed(ruleEnvList = [], excluded = []) {
  const env = ENVIRONMENT_NAME.toLowerCase();
  if (Array.isArray(excluded) && excluded.map((v) => v.toLowerCase()).includes(env)) {
    return false;
  }
  if (!Array.isArray(ruleEnvList) || !ruleEnvList.length) return true;
  return ruleEnvList.map((v) => v.toLowerCase()).includes(env);
}

function normalizeSeverity(value) {
  const allowed = ['low', 'medium', 'high', 'critical'];
  const normalized = (value || '').toString().toLowerCase();
  return allowed.includes(normalized) ? normalized : 'low';
}

function applySeverityModifier(base, modifier, eventType) {
  if (!modifier || typeof modifier !== 'object') return base;
  if (modifier.if_event_type && modifier.if_event_type !== eventType) return base;
  return normalizeSeverity(modifier.bump || base);
}

function pickStrongerSeverity(current, candidate) {
  const rank = { low: 0, medium: 1, high: 2, critical: 3 };
  return rank[candidate] > rank[current] ? candidate : current;
}

function pickMoreSensitiveClassification(current, candidate) {
  const rank = { public: 0, internal: 1, confidential: 2, secret: 3 };
  const normalizedCurrent = (current || 'public').toLowerCase();
  const normalizedCandidate = (candidate || '').toLowerCase();
  return rank[normalizedCandidate] > rank[normalizedCurrent] ? normalizedCandidate : normalizedCurrent;
}

function matchRule(rule, normalizedPath, ext, sizeBytes, eventType) {
  if (!rule.enabled) return false;
  if (!isEnvAllowed(rule.environments, rule.exclude_environments)) return false;

  const match = rule.match || {};
  const { path_contains = [], extensions = [], path_regex, min_file_size_bytes, max_file_size_mb } = match;

  const contains = Array.isArray(path_contains)
    ? path_contains.some((kw) => normalizedPath.includes(String(kw).toLowerCase()))
    : false;

  const extMatch = Array.isArray(extensions)
    ? extensions.map((e) => String(e).toLowerCase()).includes(ext)
    : false;

  let regexMatch = false;
  if (path_regex) {
    try {
      regexMatch = new RegExp(path_regex, 'i').test(normalizedPath);
    } catch (err) {
      regexMatch = false;
    }
  }

  let sizeMatch = true;
  if (typeof min_file_size_bytes === 'number' && Number.isFinite(min_file_size_bytes)) {
    sizeMatch = sizeMatch && typeof sizeBytes === 'number' && sizeBytes >= min_file_size_bytes;
  }
  if (typeof max_file_size_mb === 'number' && Number.isFinite(max_file_size_mb)) {
    const maxBytes = max_file_size_mb * 1024 * 1024;
    sizeMatch = sizeMatch && typeof sizeBytes === 'number' && sizeBytes <= maxBytes;
  }

  return (contains || extMatch || regexMatch) && sizeMatch;
}

async function enrichEvent(event) {
  const rules = await loadMetadataRules();
  const normalizedPath = (event.path || event.file || '').toLowerCase();
  const ext = path.extname(normalizedPath);
  const sizeBytes = typeof event.sizeBytes === 'number' ? event.sizeBytes : undefined;
  const eventType = event.type;

  const base = {
    severity: 'low',
    risk_score: 10,
    tags: [],
    data_classification: 'public',
    mitre: [],
    rule_ids: [],
    recommended_action: 'Review the change and validate against expected activity.',
    alert_policy: null,
    environment: { name: ENVIRONMENT_NAME },
    ...event
  };

  let severity = normalizeSeverity(base.severity);
  let riskScore = Number.isFinite(base.risk_score) ? base.risk_score : 10;
  let dataClassification = base.data_classification;
  let recommendedAction = base.recommended_action;
  let alertPolicy = base.alert_policy;
  const tags = new Set(base.tags || []);
  const mitre = Array.isArray(base.mitre) ? [...base.mitre] : base.mitre ? [base.mitre] : [];
  const ruleIds = Array.isArray(base.rule_ids) ? [...base.rule_ids] : [];

  for (const rule of rules) {
    if (!matchRule(rule, normalizedPath, ext, sizeBytes, eventType)) continue;

    ruleIds.push(rule.id);

    const baseSeverity = normalizeSeverity(rule.base_severity);
    const modifiers = Array.isArray(rule.severity_modifiers) ? rule.severity_modifiers : [];
    const modified = modifiers.reduce((current, mod) => applySeverityModifier(current, mod, eventType), baseSeverity);
    severity = pickStrongerSeverity(severity, modified);

    if (typeof rule.risk_score === 'number' && Number.isFinite(rule.risk_score)) {
      riskScore = Math.max(riskScore, rule.risk_score);
    }

    dataClassification = pickMoreSensitiveClassification(dataClassification, rule.data_classification);

    if (Array.isArray(rule.tags)) {
      rule.tags.forEach((t) => tags.add(t));
    }

    if (Array.isArray(rule.mitre)) {
      rule.mitre.forEach((entry) => {
        if (entry && entry.tactic && entry.technique_id && entry.technique) {
          mitre.push(entry);
        }
      });
    }

    if (rule.recommended_action) {
      recommendedAction = rule.recommended_action;
    }

    if (rule.alert_policy) {
      alertPolicy = rule.alert_policy;
    }
  }

  return {
    ...base,
    severity,
    risk_score: riskScore,
    tags: Array.from(tags),
    data_classification: dataClassification,
    mitre,
    rule_ids: Array.from(new Set(ruleIds)),
    recommended_action: recommendedAction,
    alert_policy: alertPolicy
  };
}

function isIgnored(filePath) {
  const name = path.basename(filePath);
  if (IGNORE_NAMES.has(name)) return true;
  if (GOVERNANCE_KEYWORDS.test(filePath)) return true;
  return false;
}

async function hashFile(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

async function walk(dir, collector = {}) {
  const entries = await fs.promises.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (isIgnored(fullPath)) continue;
    if (entry.isDirectory()) {
      await walk(fullPath, collector);
    } else if (entry.isFile()) {
      const rel = path.relative(WATCH_DIR, fullPath);
      const hash = await hashFile(fullPath);
      collector[rel] = { hash, timestamp: new Date().toISOString() };
    }
  }
  return collector;
}

async function loadBaseline() {
  try {
    const content = await fs.promises.readFile(BASELINE_FILE, 'utf-8');
    baseline = JSON.parse(content || '{}');
  } catch (err) {
    baseline = {};
  }
  if (!Object.keys(baseline).length) {
    await rebuildBaseline();
  }
}

async function rebuildBaseline() {
  baseline = await walk(WATCH_DIR, {});
  await fs.promises.writeFile(BASELINE_FILE, JSON.stringify(baseline, null, 2));
  enrichEvent({
    id: crypto.randomUUID(),
    type: 'baseline',
    message: 'Baseline rebuilt',
    timestamp: new Date().toISOString(),
    mitre: { id: 'T1036', name: 'Normalization - baseline reset' }
  }).then(logEvent);
  return baseline;
}

function logEvent(evt) {
  const line = JSON.stringify(evt);
  fs.appendFile(LOG_FILE, line + '\n', () => {});
}

function buildAiAssessment(kind, rel, before, after) {
  const now = Date.now();
  let score = AI_BASELINE[kind] || 20;

  if (before && after && before !== after) {
    score += 22;
  } else if (!before && after) {
    score += 12;
  } else if (kind === 'delete' && before) {
    score += 15;
  }

  const recentBurst = eventHistory.filter((evt) => {
    if (!evt.file || evt.file !== rel) return false;
    const ts = new Date(evt.timestamp).getTime();
    return Number.isFinite(ts) && now - ts < 15 * 60 * 1000;
  }).length;
  if (recentBurst) {
    score += Math.min(recentBurst * 8, 24);
  }

  const ext = path.extname(rel).toLowerCase();
  if (['.sh', '.ps1', '.exe', '.dll', '.so', '.bat'].includes(ext)) {
    score += 18;
  } else if (['.json', '.yml', '.yaml', '.conf', '.ini'].includes(ext)) {
    score += 8;
  }

  score = Math.min(Math.max(Math.round(score), 0), 100);

  let label = 'Stable';
  if (score >= 80) label = 'Critical';
  else if (score >= 55) label = 'Elevated';
  else if (score >= 35) label = 'Watch';

  const reasons = [];
  if (before && after && before !== after) reasons.push('hash changed');
  if (!before && after) reasons.push('new baseline hash added');
  if (kind === 'delete') reasons.push('asset removed from scope');
  if (recentBurst > 1) reasons.push('burst of changes');
  if (ext) reasons.push(`file type ${ext || 'unknown'}`);

  return {
    score,
    label,
    reason: reasons.length ? reasons.join(', ') : 'routine activity'
  };
}

function pushEvent(evt) {
  eventHistory.unshift(evt);
  eventHistory = eventHistory.slice(0, 200);
  logEvent(evt);
  broadcast(evt);
}

function broadcast(payload) {
  const data = `data: ${JSON.stringify(payload)}\n\n`;
  sseClients.forEach((res) => res.write(data));
}

async function handleChange(kind, filePath) {
  if (!filePath) return;
  const rel = path.relative(WATCH_DIR, filePath);
  if (rel.startsWith('..') || isIgnored(filePath)) return;
  const timestamp = new Date().toISOString();
  const mitre = MITRE_LOOKUP[kind];
  let before = baseline[rel]?.hash || null;
  let after = null;
  let sizeBytes = null;

  if (kind === 'delete') {
    delete baseline[rel];
  } else if (fs.existsSync(filePath)) {
    try {
      const stats = await fs.promises.stat(filePath);
      sizeBytes = stats.size;
    } catch (err) {
      sizeBytes = null;
    }
    after = await hashFile(filePath);
    baseline[rel] = { hash: after, timestamp };
  }

  await fs.promises.writeFile(BASELINE_FILE, JSON.stringify(baseline, null, 2));

  const baseEvent = {
    id: crypto.randomUUID(),
    type: kind,
    path: rel,
    file: rel,
    hash: after || before || null,
    timestamp,
    sizeBytes,
    beforeHash: before,
    afterHash: after,
    mitre
  };

  const enrichedEvent = await enrichEvent(baseEvent);

  const evt = {
    ...enrichedEvent,
    message: describeEvent(kind, rel, before, after),
    aiAssessment: buildAiAssessment(kind, rel, before, after)
  };

  pushEvent(evt);
}

function describeEvent(kind, relPath, before, after) {
  const map = {
    create: `Created ${relPath} and secured new baseline hash`,
    modify: `Modified ${relPath}; baseline hash updated`,
    delete: `Deleted ${relPath} from monitored scope`
  };
  const base = map[kind] || `${kind} ${relPath}`;
  if (kind === 'modify' && before && after && before !== after) {
    return `${base} (hash diff detected)`;
  }
  if (kind === 'delete' && before) {
    return `${base} (previous hash ${before.slice(0, 8)}...)`;
  }
  return base;
}

function setupWatcher() {
  try {
    const watcher = fs.watch(WATCH_DIR, { recursive: true }, async (eventType, filename) => {
      if (!filename) return;
      const target = path.join(WATCH_DIR, filename);
      const rel = path.relative(WATCH_DIR, target);
      if (eventType === 'rename') {
        if (fs.existsSync(target)) {
          await handleChange(baseline[rel] ? 'modify' : 'create', target);
        } else {
          await handleChange('delete', target);
        }
      } else if (eventType === 'change') {
        await handleChange('modify', target);
      }
    });
    watcher.on('error', (err) => {
      console.error('Watcher error:', err.message);
    });
    console.log(`Watching ${WATCH_DIR}`);
  } catch (err) {
    console.error('Failed to start watcher', err);
  }
}

function serveStatic(req, res, urlPath) {
  const normalized = urlPath === '/' ? '/index.html' : urlPath;
  const filePath = path.join(PUBLIC_DIR, path.normalize(normalized));
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403); res.end('Forbidden'); return true;
  }
  if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
    const ext = path.extname(filePath);
    const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };
    res.writeHead(200, { 'Content-Type': types[ext] || 'text/plain' });
    fs.createReadStream(filePath).pipe(res);
    return true;
  }
  return false;
}

function handleSSE(req, res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive'
  });
  res.write(`data: ${JSON.stringify({ type: 'connected', timestamp: new Date().toISOString() })}\n\n`);
  sseClients.add(res);
  req.on('close', () => sseClients.delete(res));
}

async function requestHandler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname === '/api/events' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ events: eventHistory, baselineSize: Object.keys(baseline).length }));
    return;
  }

  if (url.pathname === '/api/rebuild' && req.method === 'POST') {
    await rebuildBaseline();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, baselineSize: Object.keys(baseline).length }));
    return;
  }

  if (url.pathname === '/api/config' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ watchDir: WATCH_DIR, governanceFilter: GOVERNANCE_KEYWORDS.source }));
    return;
  }

  if (url.pathname === '/stream' && req.method === 'GET') {
    handleSSE(req, res);
    return;
  }

  if (serveStatic(req, res, url.pathname)) return;

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
}

async function bootstrap() {
  ensureDirectories();
  await loadBaseline();
  setupWatcher();

  const server = http.createServer((req, res) => {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      });
      res.end();
      return;
    }
    res.setHeader('Access-Control-Allow-Origin', '*');
    requestHandler(req, res);
  });

  const port = process.env.PORT || 3000;
  server.listen(port, () => {
    console.log(`FIM server running at http://localhost:${port}`);
  });
}

bootstrap();
