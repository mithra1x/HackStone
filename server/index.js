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
const STAGING_DIR = path.join(ROOT, 'staging');
const BASELINE_FILE = path.join(DATA_DIR, 'baseline.json');
const LOG_FILE = path.join(LOG_DIR, 'fim.log');
const AGENTS_FILE = path.join(CONFIG_DIR, 'agents.json');

const IGNORE_NAMES = new Set(['.DS_Store', 'baseline.json', 'fim.log']);
const GOVERNANCE_KEYWORDS = /(personal|private|secret|pii)/i;
const IGNORE_RULES = [
  {
    ignore: true,
    extensions: ['.swp', '.swo'],
    patterns: ['*.swp', '*.swo', '*~'],
    description: 'Ignore Vim swap files'
  },
  {
    ignore: true,
    extensions: ['.tmp'],
    patterns: ['.tmp', '.*.tmp'],
    description: 'Ignore temporary placeholder files'
  },
  {
    ignore: true,
    patterns: ['.*.swp', '.*.swo', '.*~'],
    description: 'Ignore hidden editor swap/backup files'
  }
].map((rule) => ({
  ...rule,
  extensions: (rule.extensions || []).map((ext) => ext.toLowerCase()),
  regexes: (rule.patterns || []).map(globToRegex)
}));

let baseline = {};
let eventHistory = [];
const sseClients = new Set();
let agentRegistry = new Map();
const MAX_BODY_SIZE = 1 * 1024 * 1024; // 1MB

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
  [WATCH_DIR, DATA_DIR, LOG_DIR, PUBLIC_DIR, CONFIG_DIR, STAGING_DIR].forEach((dir) => {
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

function globToRegex(glob) {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp(`^${escaped}$`);
}

function fileExtNormalized(name) {
  const match = name.match(/(\.[^./]+)$/);
  return match ? match[1].toLowerCase() : '';
}

function matchesIgnoreRule(rule, name) {
  const candidate = name.toLowerCase();
  const ext = fileExtNormalized(candidate);
  if (rule.extensions && rule.extensions.includes(ext)) return true;
  if (rule.regexes && rule.regexes.some((regex) => regex.test(candidate))) return true;
  return false;
}

function isIgnored(filePath) {
  const name = path.basename(filePath);
  if (IGNORE_NAMES.has(name)) return true;
  if (GOVERNANCE_KEYWORDS.test(filePath)) return true;
  if (IGNORE_RULES.some((rule) => rule.ignore && matchesIgnoreRule(rule, name))) return true;
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
    // Skip ignored files before attempting to descend or hash
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

async function loadAgentRegistry() {
  agentRegistry = new Map();
  if (!fs.existsSync(AGENTS_FILE)) return;
  try {
    const content = await fs.promises.readFile(AGENTS_FILE, 'utf-8');
    const parsed = JSON.parse(content || '[]');
    if (Array.isArray(parsed)) {
      parsed.forEach((agent) => {
        if (agent && agent.id) {
          agentRegistry.set(agent.id, agent);
        }
      });
    }
  } catch (err) {
    console.warn('Failed to load agent registry:', err.message);
  }
}

async function loadBaseline() {
  try {
    const content = await fs.promises.readFile(BASELINE_FILE, 'utf-8');
    baseline = JSON.parse(content || '{}');
  } catch (err) {
    baseline = {};
  }
  await purgeIgnoredBaselineEntries();
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

async function purgeIgnoredBaselineEntries() {
  let changed = false;
  for (const rel of Object.keys(baseline)) {
    const absolute = path.join(WATCH_DIR, rel);
    if (isIgnored(absolute)) {
      delete baseline[rel];
      changed = true;
    }
  }
  if (changed) {
    await fs.promises.writeFile(BASELINE_FILE, JSON.stringify(baseline, null, 2));
  }
}

function logEvent(evt) {
  const line = JSON.stringify(evt);
  fs.appendFile(LOG_FILE, line + '\n', () => {});
}

function processAndBroadcastEvent(rawEvent, sourceMeta = {}) {
  const kind = rawEvent.type || rawEvent.action;
  const file = rawEvent.file || rawEvent.path;
  if (!kind || !file) return null;

  const timestamp = rawEvent.timestamp || new Date().toISOString();
  const beforeHash = rawEvent.beforeHash ?? rawEvent.prev_hash ?? rawEvent.prevHash ?? null;
  const afterHash = rawEvent.afterHash ?? rawEvent.hash ?? null;
  const mitre = rawEvent.mitre || MITRE_LOOKUP[kind];
  const severity = rawEvent.severity || (kind === 'delete' ? 'high' : kind === 'modify' ? 'medium' : 'info');
  const message = rawEvent.message || describeEvent(kind, file, beforeHash, afterHash);
  const aiAssessment = rawEvent.aiAssessment || buildAiAssessment(kind, file, beforeHash, afterHash);

  const evt = {
    id: rawEvent.id || crypto.randomUUID(),
    type: kind,
    file,
    timestamp,
    beforeHash,
    afterHash,
    mitre,
    severity,
    message,
    aiAssessment,
    source: sourceMeta.source || 'local',
    agentId: sourceMeta.agentId || null,
    user: rawEvent.user ?? null,
    uid: rawEvent.uid ?? null,
    gid: rawEvent.gid ?? null,
    mode: rawEvent.mode ?? null,
    extra: rawEvent.extra ?? rawEvent.metadata ?? null
  };

  pushEvent(evt);
  return evt;
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

function parseJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > MAX_BODY_SIZE) {
        const err = new Error('Payload too large');
        err.statusCode = 413;
        reject(err);
        req.destroy();
      }
    });
    req.on('end', () => {
      if (!body) {
        const err = new Error('Empty body');
        err.statusCode = 400;
        reject(err);
        return;
      }
      try {
        const parsed = JSON.parse(body);
        resolve(parsed);
      } catch (err) {
        err.statusCode = 400;
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function validateAgentId(agentId) {
  if (!agentId) return true;
  if (!agentRegistry || agentRegistry.size === 0) return true;
  return agentRegistry.has(agentId);
}

function validateAgentEvent(evt) {
  if (!evt || typeof evt !== 'object') return false;
  const required = ['path', 'action', 'timestamp'];
  return required.every((field) => evt[field]);
}

async function handleChange(kind, filePath) {
  if (!filePath) return;
  const rel = path.relative(WATCH_DIR, filePath);
  // Drop ignored paths before hashing, diffing, or emitting events
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

  processAndBroadcastEvent(
    {
      type: kind,
      file: rel,
      timestamp,
      beforeHash: before,
      afterHash: after,
      mitre,
      severity: kind === 'delete' ? 'high' : kind === 'modify' ? 'medium' : 'info',
      message: describeEvent(kind, rel, before, after),
      aiAssessment: buildAiAssessment(kind, rel, before, after)
    },
    { source: 'local' }
  );
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

  if (url.pathname === '/api/agent/events' && req.method === 'POST') {
    try {
      const payload = await parseJsonBody(req);
      const events = Array.isArray(payload) ? payload : [payload];
      if (!events.length) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: 'No events provided' }));
        return;
      }

      let received = 0;
      for (const evt of events) {
        if (!validateAgentEvent(evt)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Invalid event payload; path, action, and timestamp required' }));
          return;
        }

        const agentId = evt.agent_id || evt.agentId || null;
        if (!validateAgentId(agentId)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Unknown agent_id' }));
          return;
        }

        processAndBroadcastEvent(
          {
            type: evt.action,
            file: evt.path,
            timestamp: evt.timestamp,
            beforeHash: evt.prev_hash ?? evt.prevHash ?? null,
            afterHash: evt.hash ?? evt.afterHash ?? null,
            mitre: evt.mitre,
            severity: evt.severity,
            message: evt.message,
            aiAssessment: evt.aiAssessment,
            extra: evt.extra,
            user: evt.user,
            uid: evt.uid,
            gid: evt.gid,
            mode: evt.mode
          },
          { source: 'agent', agentId }
        );
        received += 1;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, received }));
    } catch (err) {
      res.writeHead(err.statusCode || 400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: err.message || 'Invalid request' }));
    }
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
  await loadAgentRegistry();
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
