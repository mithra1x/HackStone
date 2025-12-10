const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const WATCH_DIR = path.join(ROOT, 'watched');
const DATA_DIR = path.join(ROOT, 'data');
const LOG_DIR = path.join(ROOT, 'logs');
const PUBLIC_DIR = path.join(ROOT, 'public');
const BASELINE_FILE = path.join(DATA_DIR, 'baseline.json');
const LOG_FILE = path.join(LOG_DIR, 'fim.log');

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
  [WATCH_DIR, DATA_DIR, LOG_DIR, PUBLIC_DIR].forEach((dir) => {
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
  logEvent({
    id: crypto.randomUUID(),
    type: 'baseline',
    message: 'Baseline rebuilt',
    timestamp: new Date().toISOString(),
    mitre: { id: 'T1036', name: 'Normalization - baseline reset' }
  });
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

  if (kind === 'delete') {
    delete baseline[rel];
  } else if (fs.existsSync(filePath)) {
    after = await hashFile(filePath);
    baseline[rel] = { hash: after, timestamp };
  }

  await fs.promises.writeFile(BASELINE_FILE, JSON.stringify(baseline, null, 2));

  const evt = {
    id: crypto.randomUUID(),
    type: kind,
    file: rel,
    timestamp,
    beforeHash: before,
    afterHash: after,
    mitre,
    severity: kind === 'delete' ? 'high' : kind === 'modify' ? 'medium' : 'info',
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
