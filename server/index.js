const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_WATCH_DIR = path.join(ROOT, 'watched');
const DATA_DIR = path.join(ROOT, 'data');
const BASELINE_DIR = path.join(DATA_DIR, 'baseline');
const LOG_DIR = path.join(ROOT, 'logs');
const PUBLIC_DIR = path.join(ROOT, 'public');
const CONFIG_DIR = path.join(ROOT, 'config');
const STAGING_DIR = path.join(ROOT, 'staging');
const CONFIG_FILE = path.join(CONFIG_DIR, 'server_config.json');
const METADATA_RULES_FILE = path.join(CONFIG_DIR, 'metadata_rules.json');
const LEGACY_BASELINE_FILE = path.join(DATA_DIR, 'baseline.json');
const LOCAL_BASELINE_ID = 'local';
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

let baselines = new Map();
let eventHistory = [];
const sseClients = new Set();
let agentRegistry = new Map();
let watchPaths = [];
let ignorePatternRegexes = [];
const lastKnownMetaByPath = new Map();
const MAX_BODY_SIZE = 1 * 1024 * 1024; // 1MB
const IDEMPOTENCY_CACHE_LIMIT = 10000;
const IDEMPOTENCY_CACHE_TTL_MS = 10 * 60 * 1000;
const processedEventIds = new Map(); // event_id -> timestamp
const agentEventBuffer = [];
const MAX_AGENT_BUFFER_SIZE = 2000;
let agentBufferProcessing = false;
const SUPPRESS_WINDOW_SECONDS = 10;
const SUPPRESS_THRESHOLD = 5;
const SUPPRESSION_STALE_MS = 5 * 60 * 1000;
const suppressionTracker = new Map();
let metadataRules = [];
const EVENT_BUFFER_LIMIT = 500;

const DEFAULT_METADATA_RULES = [
  {
    description: 'Credentials and secrets',
    match: {
      path_keywords: [
        'secret',
        'password',
        'passwd',
        'credential',
        'token',
        'apikey',
        'api_key',
        'private_key'
      ]
    },
    severity: 'high',
    tags: ['credentials', 'sensitive']
  }
];

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3 };

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

const TIMELINE_RANGE_MS = {
  '24h': 24 * 60 * 60 * 1000,
  '12h': 12 * 60 * 60 * 1000,
  '1h': 60 * 60 * 1000,
  '15m': 15 * 60 * 1000,
  '5m': 5 * 60 * 1000
};

const TIMELINE_GROUP_WINDOW_MS = 2 * 60 * 1000;
const TIMELINE_SHORT_LIVED_WINDOW_MS = 5 * 60 * 1000;

function ensureDirectories() {
  [DEFAULT_WATCH_DIR, DATA_DIR, BASELINE_DIR, LOG_DIR, PUBLIC_DIR, CONFIG_DIR, STAGING_DIR].forEach((dir) => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });
  if (!fs.existsSync(LOG_FILE)) {
    fs.writeFileSync(LOG_FILE, '');
  }
}

function sanitizeBaselineId(id) {
  if (!id) return 'unknown';
  return String(id).replace(/[^A-Za-z0-9._-]/g, '_');
}

function sanitizeForFilename(name) {
  if (!name) return 'unknown';
  return String(name)
    .replace(/[^A-Za-z0-9._-]/g, '_')
    .replace(/_{2,}/g, '_')
    .slice(0, 120);
}

function baselineFilePath(baselineId) {
  const safeId = baselineId === LOCAL_BASELINE_ID ? LOCAL_BASELINE_ID : sanitizeBaselineId(baselineId);
  return path.join(BASELINE_DIR, `${safeId}.json`);
}

function backupCorruptBaseline(filePath) {
  try {
    const backupPath = `${filePath}.bad-${Date.now()}`;
    fs.renameSync(filePath, backupPath);
    console.error(`Baseline file ${filePath} was corrupted. Backed up to ${backupPath}`);
  } catch (err) {
    console.error(`Failed to back up corrupt baseline file ${filePath}:`, err.message);
  }
}

async function ensureBaselineStorage() {
  ensureDirectories();
  const localPath = baselineFilePath(LOCAL_BASELINE_ID);
  if (!fs.existsSync(localPath)) {
    if (fs.existsSync(LEGACY_BASELINE_FILE)) {
      try {
        fs.copyFileSync(LEGACY_BASELINE_FILE, localPath);
      } catch (err) {
        console.warn('Failed to migrate legacy baseline file, starting fresh:', err.message);
        fs.writeFileSync(localPath, JSON.stringify({}, null, 2));
      }
    } else {
      fs.writeFileSync(localPath, JSON.stringify({}, null, 2));
    }
  }
}

function loadServerConfig() {
  const defaults = {
    watch_paths: ['./watched'],
    ignore_patterns: ['*.swp', '*.swo', '*~', '.DS_Store']
  };

  if (!fs.existsSync(CONFIG_FILE)) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(defaults, null, 2));
    console.log('Created default config/server_config.json');
  }

  let parsed = defaults;
  try {
    const content = fs.readFileSync(CONFIG_FILE, 'utf-8');
    parsed = JSON.parse(content || '{}');
  } catch (err) {
    console.error('Failed to parse config/server_config.json, falling back to defaults:', err.message);
    parsed = defaults;
  }

  const rawPaths = Array.isArray(parsed.watch_paths) ? parsed.watch_paths : defaults.watch_paths;
  watchPaths = rawPaths
    .map((p) => (p.startsWith('/') ? p : path.resolve(ROOT, p)))
    .filter(Boolean);
  if (!watchPaths.length) {
    watchPaths = defaults.watch_paths.map((p) => path.resolve(ROOT, p));
  }

  watchPaths.forEach((dir) => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });

  const patterns = Array.isArray(parsed.ignore_patterns) ? parsed.ignore_patterns : defaults.ignore_patterns;
  ignorePatternRegexes = patterns.map(globToRegex);

  console.log('Watching paths:', watchPaths.join(', '));
  console.log('Ignore patterns:', patterns.join(', '));
}

function severityRankValue(severity) {
  return SEVERITY_RANK[(severity || '').toLowerCase()] ?? -1;
}

function normalizeRule(rule) {
  const match = rule.match || {};
  const normalizeArray = (val) => (Array.isArray(val) ? val : []).map((v) => String(v).toLowerCase());
  const path_keywords = normalizeArray(match.path_keywords);
  const path_patterns = normalizeArray(match.path_patterns);
  const extensions = normalizeArray(match.extensions);

  return {
    description: rule.description || 'unnamed rule',
    match: { path_keywords, path_patterns, extensions },
    severity: (rule.severity || '').toLowerCase() || null,
    tags: Array.isArray(rule.tags) ? rule.tags : [],
    mitre: rule.mitre || null
  };
}

function loadMetadataRules() {
  if (!fs.existsSync(METADATA_RULES_FILE)) {
    fs.writeFileSync(METADATA_RULES_FILE, JSON.stringify(DEFAULT_METADATA_RULES, null, 2));
    console.log('Created default config/metadata_rules.json');
  }

  try {
    const content = fs.readFileSync(METADATA_RULES_FILE, 'utf-8');
    const parsed = JSON.parse(content || '[]');
    if (!Array.isArray(parsed)) throw new Error('metadata_rules.json must contain an array');
    metadataRules = parsed.map(normalizeRule);
    console.log(`Loaded ${metadataRules.length} metadata rules`);
  } catch (err) {
    console.warn('Failed to load metadata_rules.json; continuing with no rules:', err.message);
    metadataRules = [];
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
  if (ignorePatternRegexes.some((regex) => regex.test(name))) return true;
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

async function walk(dir, collector = {}, baselineId = LOCAL_BASELINE_ID) {
  const entries = await fs.promises.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    // Skip ignored files before attempting to descend or hash
    if (isIgnored(fullPath)) continue;
    if (entry.isDirectory()) {
      await walk(fullPath, collector);
    } else if (entry.isFile()) {
      const rel = path.relative(ROOT, fullPath);
      const hash = await hashFile(fullPath);
      const { metadata } = await collectFilesystemMetadata(fullPath);
      collector[rel] = { hash, updated_at: new Date().toISOString(), metadata };
      setLastKnownMetadata(baselineId, rel, metadata);
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

function normalizeBaselineData(data = {}) {
  const normalized = {};
  for (const [rel, entry] of Object.entries(data)) {
    if (!entry) continue;
    const hash = entry.hash || entry.afterHash || null;
    const updated_at = entry.updated_at || entry.timestamp || null;
    const metadata = entry.metadata ? ensureMetadataObject(entry.metadata) : null;
    normalized[rel] = { hash, metadata, updated_at };
  }
  return normalized;
}

function baselineMetaKey(baselineId, rel) {
  return `${baselineId}:${rel}`;
}

function setLastKnownMetadata(baselineId, rel, metadata) {
  if (!rel) return;
  lastKnownMetaByPath.set(baselineMetaKey(baselineId, rel), metadata);
}

function getLastKnownMetadata(baselineId, rel) {
  return lastKnownMetaByPath.get(baselineMetaKey(baselineId, rel)) || null;
}

async function loadBaseline(baselineId = LOCAL_BASELINE_ID) {
  await ensureBaselineStorage();
  const filePath = baselineFilePath(baselineId);
  let data = {};
  try {
    if (!fs.existsSync(filePath)) {
      await fs.promises.writeFile(filePath, JSON.stringify({}, null, 2));
    }
    const content = await fs.promises.readFile(filePath, 'utf-8');
    data = JSON.parse(content || '{}');
  } catch (err) {
    console.error(`Failed to parse baseline file for ${baselineId}:`, err.message);
    backupCorruptBaseline(filePath);
    data = {};
  }
  const normalized = normalizeBaselineData(data);
  baselines.set(baselineId, normalized);
  for (const [rel, entry] of Object.entries(normalized)) {
    if (entry?.metadata) {
      setLastKnownMetadata(baselineId, rel, ensureMetadataObject(entry.metadata));
    }
  }

  if (baselineId === LOCAL_BASELINE_ID) {
    await purgeIgnoredBaselineEntries(baselineId);
    const allWithinWatchPaths = Object.keys(normalized).every((rel) => {
      const absolute = path.join(ROOT, rel);
      return watchPaths.some((dir) => !path.relative(dir, absolute).startsWith('..'));
    });
    if (!Object.keys(normalized).length || !allWithinWatchPaths) {
      await rebuildBaseline();
    }
  }

  return baselines.get(baselineId);
}

async function getBaseline(baselineId = LOCAL_BASELINE_ID) {
  if (baselines.has(baselineId)) return baselines.get(baselineId);
  return loadBaseline(baselineId);
}

function totalBaselineEntries() {
  let total = 0;
  for (const data of baselines.values()) {
    total += Object.keys(data || {}).length;
  }
  return total;
}

async function saveBaseline(baselineId = LOCAL_BASELINE_ID) {
  const data = baselines.get(baselineId) || {};
  const filePath = baselineFilePath(baselineId);
  await fs.promises.writeFile(filePath, JSON.stringify(data, null, 2));
}

async function rebuildBaseline() {
  const baselineId = LOCAL_BASELINE_ID;
  const rebuilt = {};
  for (const dir of watchPaths) {
    if (fs.existsSync(dir)) {
      await walk(dir, rebuilt, baselineId);
    }
  }
  baselines.set(baselineId, rebuilt);
  await saveBaseline(baselineId);
  logEvent({
    id: crypto.randomUUID(),
    type: 'baseline',
    message: 'Baseline rebuilt',
    timestamp: new Date().toISOString(),
    mitre: { id: 'T1036', name: 'Normalization - baseline reset' }
  });
  return rebuilt;
}

async function purgeIgnoredBaselineEntries(baselineId = LOCAL_BASELINE_ID) {
  if (baselineId !== LOCAL_BASELINE_ID) return;
  const data = baselines.get(baselineId) || {};
  let changed = false;
  for (const rel of Object.keys(data)) {
    const absolute = path.join(ROOT, rel);
    if (isIgnored(absolute)) {
      delete data[rel];
      changed = true;
    }
  }
  if (changed) {
    baselines.set(baselineId, data);
    await saveBaseline(baselineId);
  }
}

async function updateBaselineFromEvent(baselineId, rel, kind, afterHash, metadata) {
  const now = new Date().toISOString();
  const data = await getBaseline(baselineId);

  if (kind === 'delete') {
    if (metadata) {
      setLastKnownMetadata(baselineId, rel, ensureMetadataObject(metadata));
    }
    delete data[rel];
  } else if (afterHash) {
    const normalizedMeta = ensureMetadataObject(metadata);
    setLastKnownMetadata(baselineId, rel, normalizedMeta);
    data[rel] = {
      hash: afterHash,
      metadata: normalizedMeta,
      updated_at: now
    };
  }

  baselines.set(baselineId, data);
  await saveBaseline(baselineId);
}

function logEvent(evt) {
  const line = JSON.stringify(evt);
  fs.appendFile(LOG_FILE, line + '\n', () => {});
}

function suppressionKey(evt) {
  return [evt.source || 'local', evt.agentId || 'null', evt.file, evt.type || evt.action || 'unknown'].join('|');
}

function cleanupSuppressionTracker(now = Date.now()) {
  for (const [key, state] of suppressionTracker.entries()) {
    if (now - state.lastSeenMs > SUPPRESSION_STALE_MS) {
      suppressionTracker.delete(key);
    }
  }
}

function emitSummaryEvent(evt, state) {
  const windowStart = new Date(state.windowStartMs).toISOString();
  const windowEnd = new Date(state.lastSeenMs).toISOString();
  const sourceLabel = evt.source === 'agent' ? `agent ${evt.agentId || 'unknown'}` : 'local watcher';

  return {
    ...evt,
    id: crypto.randomUUID(),
    timestamp: windowEnd,
    is_summary: true,
    summary: {
      suppressed: state.suppressedCount,
      total_in_window: state.count,
      window_seconds: SUPPRESS_WINDOW_SECONDS,
      window_start: windowStart,
      window_end: windowEnd
    },
    message: `Suppressed ${state.suppressedCount} repeated ${evt.type} events for ${evt.file} (${sourceLabel}) in ${SUPPRESS_WINDOW_SECONDS}s`,
    beforeHash: null,
    afterHash: null,
    aiAssessment: evt.aiAssessment,
    severity: evt.severity || 'info'
  };
}

function applyBurstSuppression(evt, nowMs = Date.now()) {
  cleanupSuppressionTracker(nowMs);
  const key = suppressionKey(evt);
  const windowMs = SUPPRESS_WINDOW_SECONDS * 1000;
  let summaryEvent = null;

  if (!suppressionTracker.has(key)) {
    suppressionTracker.set(key, {
      windowStartMs: nowMs,
      lastSeenMs: nowMs,
      count: 1,
      suppressedCount: 0
    });
    return { suppressed: false, summaryEvent: null };
  }

  const state = suppressionTracker.get(key);
  if (nowMs - state.windowStartMs > windowMs) {
    if (state.suppressedCount > 0) {
      summaryEvent = emitSummaryEvent(evt, state);
    }
    state.windowStartMs = nowMs;
    state.lastSeenMs = nowMs;
    state.count = 1;
    state.suppressedCount = 0;
    suppressionTracker.set(key, state);
    return { suppressed: false, summaryEvent };
  }

  state.lastSeenMs = nowMs;
  state.count += 1;
  if (state.count > SUPPRESS_THRESHOLD) {
    state.suppressedCount += 1;
    suppressionTracker.set(key, state);
    return { suppressed: true, summaryEvent: null };
  }

  suppressionTracker.set(key, state);
  return { suppressed: false, summaryEvent: null };
}

function normalizeMode(mode) {
  if (mode === undefined || mode === null) return null;
  const numeric = typeof mode === 'string' ? parseInt(mode, 8) : Number(mode);
  if (Number.isNaN(numeric)) return null;
  return (numeric & 0o777).toString(8).padStart(4, '0');
}

function normalizeTimestamp(ts) {
  if (!ts) return null;
  const date = ts instanceof Date ? ts : new Date(ts);
  const time = date.getTime();
  if (!Number.isFinite(time)) return null;
  return date.toISOString();
}

function lookupUser(uid) {
  if (uid === undefined || uid === null) return null;
  try {
    return os.userInfo({ uid }).username || null;
  } catch (err) {
    return null;
  }
}

function normalizeMetadata(rawEvent = {}) {
  const metaSource = rawEvent.metadata || rawEvent.meta || {};
  const fields = { ...rawEvent, ...metaSource };
  const uid = fields.uid ?? null;
  const gid = fields.gid ?? null;
  const mode = normalizeMode(fields.mode ?? fields.permissions);
  const size = fields.size ?? null;
  const mtime = normalizeTimestamp(fields.mtime);
  const ctime = normalizeTimestamp(fields.ctime);
  const user = fields.user ?? lookupUser(uid);

  if (
    uid === null &&
    gid === null &&
    user === null &&
    mode === null &&
    size === null &&
    mtime === null &&
    ctime === null
  ) {
    return {
      uid: null,
      gid: null,
      user: null,
      mode: null,
      size: null,
      mtime: null,
      ctime: null
    };
  }

  return { uid, gid, user, mode, size, mtime, ctime };
}

function emptyMetadata() {
  return {
    uid: null,
    gid: null,
    user: null,
    mode: null,
    size: null,
    mtime: null,
    ctime: null
  };
}

async function collectFilesystemMetadata(filePath) {
  try {
    const stat = await fs.promises.lstat(filePath);
    return {
      metadata: {
        uid: stat.uid ?? null,
        gid: stat.gid ?? null,
        user: lookupUser(stat.uid),
        mode: normalizeMode(stat.mode),
        size: stat.size ?? null,
        mtime: normalizeTimestamp(stat.mtime),
        ctime: normalizeTimestamp(stat.ctime)
      },
      found: true
    };
  } catch (err) {
    return { metadata: emptyMetadata(), found: false };
  }
}

function metadataFromBaseline(entry) {
  if (!entry || !entry.metadata) return null;
  return normalizeMetadata({ metadata: entry.metadata });
}

function ensureMetadataObject(meta) {
  if (!meta) return emptyMetadata();
  const normalized = normalizeMetadata({ metadata: meta });
  return normalized || emptyMetadata();
}

function applyMetadataRules(evt) {
  if (!metadataRules.length) {
    evt.rule_matches = [];
    return evt;
  }

  const pathValue = (evt.path || evt.file || '').toLowerCase();
  const tagSet = new Set(Array.isArray(evt.tags) ? evt.tags : []);
  const matches = [];
  let finalSeverity = (evt.severity || 'info').toLowerCase();
  let finalSeverityRank = severityRankValue(finalSeverity);
  let mitreCandidate = null;
  let mitreCandidateRank = -1;

  for (const rule of metadataRules) {
    const match = rule.match || {};
    const hasKeywordMatch = (match.path_keywords || []).some((kw) => pathValue.includes(kw));
    const hasPatternMatch = (match.path_patterns || []).some((ptn) => pathValue.includes(ptn));
    const hasExtensionMatch = (match.extensions || []).some((ext) => pathValue.endsWith(ext));
    const matched = hasKeywordMatch || hasPatternMatch || hasExtensionMatch;

    if (!matched) continue;

    matches.push(rule.description);
    (rule.tags || []).forEach((t) => tagSet.add(t));

    const ruleRank = severityRankValue(rule.severity);
    if (ruleRank > finalSeverityRank) {
      finalSeverity = rule.severity;
      finalSeverityRank = ruleRank;
    }

    if (rule.mitre && ruleRank >= mitreCandidateRank) {
      mitreCandidate = rule.mitre;
      mitreCandidateRank = ruleRank;
    }
  }

  evt.severity = finalSeverity;
  if (mitreCandidate) {
    evt.mitre = mitreCandidate;
  }
  const uniqueTags = Array.from(tagSet).filter(Boolean);
  if (uniqueTags.length) {
    evt.tags = uniqueTags;
  }
  evt.rule_matches = matches;
  return evt;
}

async function applyQuarantine(evt) {
  const baseQuarantine = { recommended: false, performed: false, staged_path: null, error: null };
  if (evt.severity !== 'high') {
    return { quarantine: baseQuarantine, message: null };
  }

  if (evt.source === 'agent') {
    return {
      quarantine: { ...baseQuarantine, recommended: true, performed: false, reason: 'remote_event' },
      message: 'Quarantine recommended on agent host.'
    };
  }

  const copyResult = await stageLocalFileCopy(evt);
  return {
    quarantine: {
      ...baseQuarantine,
      recommended: true,
      performed: copyResult.performed,
      staged_path: copyResult.staged_path,
      error: copyResult.error
    },
    message: copyResult.error ? 'Quarantine copy attempted; review error details.' : 'Quarantine copy stored in staging.'
  };
}

async function stageLocalFileCopy(evt) {
  const defaultResult = { performed: false, staged_path: null, error: null, message: null };
  const relPath = evt.file || evt.path;
  if (!relPath) {
    return { ...defaultResult, error: 'No file path available for quarantine copy' };
  }

  const absolute = path.isAbsolute(relPath) ? path.normalize(relPath) : path.join(ROOT, relPath);
  const normalizedRoot = path.normalize(ROOT + path.sep);
  if (!absolute.startsWith(normalizedRoot)) {
    return { ...defaultResult, error: 'Source path resolved outside workspace; skipping copy' };
  }

  const timestamp = (evt.timestamp || new Date().toISOString()).replace(/[:.]/g, '-');
  const safeBase = sanitizeForFilename(path.basename(relPath) || 'file');
  const destName = `${timestamp}__local__${safeBase}`;
  const destPath = path.join(STAGING_DIR, destName);

  try {
    await fs.promises.access(absolute, fs.constants.R_OK);
  } catch (err) {
    const missingErr = err && err.code === 'ENOENT';
    return { ...defaultResult, error: missingErr ? 'file not found' : err.message };
  }

  try {
    await fs.promises.copyFile(absolute, destPath);
    const relStaged = path.relative(ROOT, destPath).replace(/\\/g, '/');
    return { ...defaultResult, performed: true, staged_path: relStaged };
  } catch (err) {
    return { ...defaultResult, error: err.message };
  }
}

function metadataHasValues(meta) {
  if (!meta) return false;
  return Object.values(meta).some((value) => value !== null);
}

function normalizeEventShape(evt) {
  if (!evt) return evt;
  const normalized = { ...evt };
  if (!normalized.path) {
    normalized.path = normalized.file || normalized.path || null;
  }
  if (!normalized.action) {
    normalized.action = normalized.type || normalized.action || null;
  }
  return normalized;
}

async function processAndBroadcastEvent(rawEvent, sourceMeta = {}) {
  const kind = rawEvent.type || rawEvent.action;
  const file = rawEvent.file || rawEvent.path;
  if (!kind || !file) return null;

  const baselineId = sourceMeta.source === 'agent' ? sanitizeBaselineId(sourceMeta.agentId) : LOCAL_BASELINE_ID;
  if (sourceMeta.source === 'agent' && !sourceMeta.agentId) {
    throw new Error('Missing agentId for agent event');
  }

  const baselineData = await getBaseline(baselineId);
  const baselineEntry = baselineData[file];

  const timestamp = rawEvent.timestamp || new Date().toISOString();
  let beforeHash = rawEvent.beforeHash ?? rawEvent.prev_hash ?? rawEvent.prevHash ?? null;
  const afterHash = rawEvent.afterHash ?? rawEvent.hash ?? null;
  if (!beforeHash) {
    beforeHash = baselineEntry?.hash || null;
  }

  const mitre = rawEvent.mitre || MITRE_LOOKUP[kind];
  const severity = rawEvent.severity || (kind === 'delete' ? 'high' : kind === 'modify' ? 'medium' : 'info');
  const message = rawEvent.message || describeEvent(kind, file, beforeHash, afterHash);
  const aiAssessment = rawEvent.aiAssessment || buildAiAssessment(kind, file, beforeHash, afterHash);

  const baselineMeta = metadataFromBaseline(baselineEntry);
  const incomingMeta = normalizeMetadata(rawEvent);
  const chosenMetadata = metadataHasValues(incomingMeta) ? incomingMeta : baselineMeta || incomingMeta;
  const metadata = ensureMetadataObject(chosenMetadata);

  const pathValue = rawEvent.path || file;
  const actionValue = rawEvent.action || kind;

  const evt = {
    id: rawEvent.id || crypto.randomUUID(),
    type: kind,
    file,
    path: pathValue,
    timestamp,
    beforeHash,
    afterHash,
    mitre,
    severity,
    message,
    aiAssessment,
    source: sourceMeta.source || 'local',
    agentId: sourceMeta.agentId || null,
    metadata,
    prevMetadata: baselineMeta || null,
    user: rawEvent.user ?? metadata.user ?? null,
    uid: rawEvent.uid ?? metadata.uid ?? null,
    gid: rawEvent.gid ?? metadata.gid ?? null,
    mode: rawEvent.mode ?? metadata.mode ?? null,
    permissions: rawEvent.permissions ?? metadata.mode ?? null,
    size: rawEvent.size ?? metadata.size ?? null,
    mtime: rawEvent.mtime ?? metadata.mtime ?? null,
    ctime: rawEvent.ctime ?? metadata.ctime ?? null,
    extra: rawEvent.extra ?? rawEvent.metadata ?? null,
    action: actionValue
  };

  applyMetadataRules(evt);

  const quarantineResult = await applyQuarantine(evt);
  if (quarantineResult) {
    evt.quarantine = quarantineResult.quarantine;
    if (quarantineResult.message) {
      evt.message = `${evt.message} ${quarantineResult.message}`.trim();
    }
  }

  await updateBaselineFromEvent(baselineId, file, kind, afterHash, metadata);

  const suppression = applyBurstSuppression(evt);
  if (suppression.summaryEvent) {
    pushEvent(suppression.summaryEvent);
  }
  if (suppression.suppressed) {
    return { ...evt, suppressed: true };
  }

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
  const normalized = normalizeEventShape(evt);
  storeEventInHistory(normalized);
}

function storeEventInHistory(evt, { skipLog = false, skipBroadcast = false } = {}) {
  const normalized = normalizeEventShape(evt);
  eventHistory.unshift(normalized);
  if (eventHistory.length > EVENT_BUFFER_LIMIT) {
    eventHistory = eventHistory.slice(0, EVENT_BUFFER_LIMIT);
  }
  if (!skipLog) {
    logEvent(normalized);
  }
  if (!skipBroadcast) {
    broadcast(normalized);
  }
}

function broadcast(payload) {
  const data = `data: ${JSON.stringify(payload)}\n\n`;
  sseClients.forEach((res) => res.write(data));
}

function eventTimestampMs(evt) {
  const ts = new Date(evt.timestamp).getTime();
  return Number.isFinite(ts) ? ts : null;
}

function resolveTimelineRange(range) {
  if (!range || !TIMELINE_RANGE_MS[range]) return '24h';
  return range;
}

function pickHighestSeverity(events) {
  return events.reduce((winner, evt) => {
    const value = SEVERITY_RANK[evt.severity] ?? -1;
    const winningValue = SEVERITY_RANK[winner] ?? -1;
    return value > winningValue ? evt.severity : winner;
  }, 'info');
}

function isScriptPath(relPath = '') {
  const ext = path.extname(relPath).toLowerCase();
  return ['.sh', '.ps1', '.bat', '.cmd', '.py', '.js'].includes(ext);
}

function isSensitivePath(relPath = '') {
  const lowered = relPath.toLowerCase();
  const sensitiveKeywords = ['.env', 'credential', 'secret', 'password', 'ssh', 'id_rsa', 'id_dsa', 'token'];
  return sensitiveKeywords.some((kw) => lowered.includes(kw));
}

function describeActions(actions, durationMs) {
  const sorted = Array.from(actions).sort();
  const actionText = sorted.join(', ');
  if (!durationMs || durationMs < 1000) return actionText;
  const minutes = Math.max(Math.round(durationMs / 60000), 1);
  return `${actionText} within ${minutes} min`;
}

function classifyTimelineGroup(group) {
  const events = group.events;
  const first = events[0];
  const pathValue = first.path || first.file || 'unknown';
  const actions = new Set(events.map((evt) => evt.action || evt.type));
  const duration = group.endTs - group.startTs;
  const hasCreate = actions.has('create');
  const hasDelete = actions.has('delete');
  const modifyCount = events.filter((evt) => (evt.action || evt.type) === 'modify').length;

  let title = 'File activity observed';
  let summary = `Actions: ${describeActions(actions, duration)}.`;
  let why = first.message || 'Observed file activity.';
  let mitre = first.mitre || null;

  if (hasCreate && hasDelete && duration <= TIMELINE_SHORT_LIVED_WINDOW_MS) {
    title = 'Short-lived file (possible staging/cleanup)';
    summary = 'File was created and removed within minutes.';
    why = 'Short-lived artifacts can indicate staging or cover tracks.';
  } else if (isScriptPath(pathValue)) {
    title = 'Script activity detected';
    summary = `${describeActions(actions, duration)} on script-like file.`;
    why = 'Script files are commonly used for execution and persistence.';
    if (!mitre) mitre = { id: 'T1059', name: 'Command and Scripting Interpreter' };
  } else if (isSensitivePath(pathValue)) {
    title = 'Sensitive file touched';
    summary = `${describeActions(actions, duration)} on sensitive or credential-like path.`;
    why = 'Credentials/config changes can indicate credential access or persistence.';
  } else if (modifyCount >= 3 && duration <= TIMELINE_GROUP_WINDOW_MS) {
    title = 'Rapid file modifications';
    summary = 'Burst of modifications detected in a short window.';
    why = 'Burst changes may indicate automated activity.';
  }

  const withAssessment = events.find((evt) => evt.aiAssessment?.reason);
  if (withAssessment && !why) {
    why = withAssessment.aiAssessment.reason;
  } else if (withAssessment && why && !why.includes(withAssessment.aiAssessment.reason)) {
    why = `${why} AI assessment: ${withAssessment.aiAssessment.reason}`;
  }

  return { title, summary, why, mitre };
}

function buildTimelineEntry(group, idx) {
  const events = group.events;
  const first = events[0];
  const timestampStart = new Date(group.startTs).toISOString();
  const timestampEnd = new Date(group.endTs).toISOString();
  const actors = {
    source: first.source || 'local',
    agentId: first.agentId || null,
    user: first.user || first.metadata?.user || null
  };
  const artifactPath = first.path || first.file || 'unknown';
  const actions = Array.from(new Set(events.map((evt) => evt.action || evt.type)));
  const beforeHash = events.find((evt) => evt.beforeHash)?.beforeHash || null;
  const afterHash = [...events].reverse().find((evt) => evt.afterHash)?.afterHash || null;
  const { title, summary, why, mitre } = classifyTimelineGroup(group);

  return {
    id: `tl_${idx}_${crypto.randomUUID()}`,
    start: timestampStart,
    end: timestampEnd,
    title,
    summary,
    why,
    severity: pickHighestSeverity(events),
    mitre: mitre || first.mitre || null,
    actors,
    artifacts: [
      {
        path: artifactPath,
        actions,
        beforeHash,
        afterHash
      }
    ],
    raw_event_ids: events.map((evt) => evt.id)
  };
}

function buildTimelineStats(entries, rawCount) {
  const pathCounts = new Map();
  const mitreCounts = new Map();

  entries.forEach((entry) => {
    entry.artifacts.forEach((artifact) => {
      const prev = pathCounts.get(artifact.path) || 0;
      pathCounts.set(artifact.path, prev + 1);
    });
    if (entry.mitre?.id) {
      const prev = mitreCounts.get(entry.mitre.id) || 0;
      mitreCounts.set(entry.mitre.id, prev + 1);
    }
  });

  const top_paths = Array.from(pathCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([pathValue, count]) => ({ path: pathValue, count }));

  const top_mitre = Array.from(mitreCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([id, count]) => ({ id, count }));

  return {
    total_entries: entries.length,
    total_raw_events: rawCount,
    top_paths,
    top_mitre
  };
}

function buildTimeline(rangeParam = '24h') {
  const range = resolveTimelineRange(rangeParam);
  const now = Date.now();
  const windowMs = TIMELINE_RANGE_MS[range];
  const windowStart = now - windowMs;

  const windowEvents = eventHistory
    .map((evt) => normalizeEventShape(evt))
    .filter((evt) => {
      const ts = eventTimestampMs(evt);
      return ts !== null && ts >= windowStart;
    });

  const sorted = [...windowEvents].sort((a, b) => eventTimestampMs(a) - eventTimestampMs(b));
  const groups = [];
  let current = null;

  for (const evt of sorted) {
    const ts = eventTimestampMs(evt);
    if (ts === null) continue;
    const user = evt.user || evt.metadata?.user || '';
    const groupKey = `${evt.source || 'local'}|${evt.agentId || ''}|${user}|${evt.path || evt.file || ''}`;

    if (current && current.key === groupKey && ts - current.endTs <= TIMELINE_GROUP_WINDOW_MS) {
      current.events.push(evt);
      current.endTs = ts;
    } else {
      if (current) groups.push(current);
      current = { key: groupKey, startTs: ts, endTs: ts, events: [evt] };
    }
  }
  if (current) groups.push(current);

  const entries = groups.map((group, idx) => buildTimelineEntry(group, idx));
  entries.sort((a, b) => new Date(b.end) - new Date(a.end));

  return {
    range,
    entries,
    stats: buildTimelineStats(entries, sorted.length)
  };
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
  const required = ['agent_id', 'path', 'action', 'timestamp'];
  if (!required.every((field) => evt[field])) return false;
  const allowedActions = new Set(['create', 'modify', 'delete']);
  return allowedActions.has(evt.action);
}

function deriveEventId(evt, agentId) {
  const provided = evt.event_id || evt.eventId || evt.id;
  if (provided) return String(provided);
  const base = `${agentId || ''}|${evt.path}|${evt.action}|${evt.timestamp}`;
  return crypto.createHash('sha256').update(base).digest('hex');
}

function normalizeAgentEvent(evt, agentId) {
  const eventId = deriveEventId(evt, agentId);
  return {
    ...evt,
    agentId,
    event_id: eventId,
    id: eventId,
    action: evt.action,
    path: evt.path,
    timestamp: evt.timestamp,
    prev_hash: evt.prev_hash ?? evt.prevHash ?? evt.beforeHash ?? null,
    hash: evt.hash ?? evt.afterHash ?? null
  };
}

function cleanupIdempotencyCache(now = Date.now()) {
  for (const [id, ts] of processedEventIds) {
    if (now - ts > IDEMPOTENCY_CACHE_TTL_MS) {
      processedEventIds.delete(id);
    }
  }
}

function isDuplicateEvent(eventId, now = Date.now()) {
  cleanupIdempotencyCache(now);
  return processedEventIds.has(eventId);
}

function markEventProcessed(eventId, now = Date.now()) {
  processedEventIds.set(eventId, now);
  if (processedEventIds.size > IDEMPOTENCY_CACHE_LIMIT) {
    const oldestKey = processedEventIds.keys().next().value;
    processedEventIds.delete(oldestKey);
  }
}

function enqueueAgentEvent(bufferedEvent) {
  if (agentEventBuffer.length >= MAX_AGENT_BUFFER_SIZE) {
    const dropped = agentEventBuffer.shift();
    console.warn(
      `agent_ingest buffer full; dropping oldest event ${dropped?.event?.event_id || dropped?.event?.id || 'unknown'}`
    );
    dropped?.onComplete?.('dropped');
  }
  agentEventBuffer.push(bufferedEvent);
  processAgentEventBuffer();
}

async function processAgentEventBuffer() {
  if (agentBufferProcessing) return;
  agentBufferProcessing = true;
  try {
    while (agentEventBuffer.length) {
      const buffered = agentEventBuffer.shift();
      const status = await handleBufferedAgentEvent(buffered);
      buffered.onComplete?.(status);
    }
  } finally {
    agentBufferProcessing = false;
  }
}

async function handleBufferedAgentEvent(buffered) {
  const now = Date.now();
  const eventId = buffered?.event?.event_id;
  if (!eventId) return 'error';
  if (isDuplicateEvent(eventId, now)) {
    return 'duplicate';
  }

  try {
    await processAndBroadcastEvent(
      {
        ...buffered.event,
        id: eventId,
        type: buffered.event.action,
        action: buffered.event.action,
        path: buffered.event.path,
        beforeHash: buffered.event.prev_hash,
        afterHash: buffered.event.hash
      },
      { source: 'agent', agentId: buffered.event.agentId }
    );
    markEventProcessed(eventId, now);
    return 'processed';
  } catch (err) {
    console.error('Failed to process agent event', err.message || err);
    return 'error';
  }
}

function processAgentEventsBatch(events) {
  return new Promise((resolve) => {
    const summary = { received: events.length, processed: 0, duplicates: 0 };
    if (!events.length) {
      resolve(summary);
      return;
    }

    let remaining = events.length;
    events.forEach((event) => {
      enqueueAgentEvent({
        event,
        onComplete: (status) => {
          if (status === 'duplicate') summary.duplicates += 1;
          else summary.processed += 1;

          remaining -= 1;
          if (remaining === 0) {
            resolve(summary);
          }
        }
      });
    });
  });
}

function describeAgentIds(events) {
  const ids = new Set(events.map((evt) => evt.agentId || 'unknown'));
  if (ids.size === 1) return ids.values().next().value;
  return 'mixed';
}

async function handleChange(kind, filePath, baseDir) {
  if (!filePath) return;
  const relWithinBase = baseDir ? path.relative(baseDir, filePath) : path.relative(ROOT, filePath);
  if (relWithinBase.startsWith('..')) return;
  const rel = path.relative(ROOT, filePath);
  // Drop ignored paths before hashing, diffing, or emitting events
  if (rel.startsWith('..') || isIgnored(filePath)) return;
  const timestamp = new Date().toISOString();
  const mitre = MITRE_LOOKUP[kind];
  const baselineId = LOCAL_BASELINE_ID;
  const baselineData = await getBaseline(baselineId);
  const baselineEntry = baselineData[rel];
  let before = baselineEntry?.hash || null;
  let after = null;

  const metadataResult = await collectFilesystemMetadata(filePath);
  let metadata = metadataResult.metadata;

  if (kind === 'delete') {
    const cached = getLastKnownMetadata(baselineId, rel);
    const baselineMeta = metadataFromBaseline(baselineEntry);
    if (!metadataResult.found) {
      metadata = ensureMetadataObject(cached || baselineMeta || metadata);
    } else {
      metadata = ensureMetadataObject(metadata);
    }
  } else if (fs.existsSync(filePath)) {
    after = await hashFile(filePath);
    metadata = ensureMetadataObject(metadata);
  } else {
    metadata = ensureMetadataObject(metadata);
  }

  await processAndBroadcastEvent(
    {
      type: kind,
      file: rel,
      timestamp,
      beforeHash: before,
      afterHash: after,
      mitre,
      severity: kind === 'delete' ? 'high' : kind === 'modify' ? 'medium' : 'info',
      message: describeEvent(kind, rel, before, after),
      aiAssessment: buildAiAssessment(kind, rel, before, after),
      metadata
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
    for (const dir of watchPaths) {
      const watcher = fs.watch(dir, { recursive: true }, async (eventType, filename) => {
        if (!filename) return;
        const target = path.join(dir, filename);
        const rel = path.relative(ROOT, target);
        const baselineData = await getBaseline(LOCAL_BASELINE_ID);
        const baselineEntry = baselineData[rel];
        if (eventType === 'rename') {
          if (fs.existsSync(target)) {
            await handleChange(baselineEntry ? 'modify' : 'create', target, dir);
          } else {
            await handleChange('delete', target, dir);
          }
        } else if (eventType === 'change') {
          await handleChange('modify', target, dir);
        }
      });
      watcher.on('error', (err) => {
        console.error('Watcher error:', err.message);
      });
      console.log(`Watching ${dir}`);
    }
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
    const events = eventHistory.map(normalizeEventShape);
    res.end(JSON.stringify({ events, baselineSize: totalBaselineEntries() }));
    return;
  }

  if (url.pathname === '/api/timeline' && req.method === 'GET') {
    const range = url.searchParams.get('range') || '24h';
    const timeline = buildTimeline(range);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(timeline));
    return;
  }

  if (url.pathname === '/api/rebuild' && req.method === 'POST') {
    await rebuildBaseline();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, baselineSize: totalBaselineEntries() }));
    return;
  }

  if (url.pathname === '/api/config' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    const primaryWatchDir = watchPaths[0] || DEFAULT_WATCH_DIR;
    res.end(JSON.stringify({
      watchDir: primaryWatchDir,
      watchDirs: watchPaths,
      governanceFilter: GOVERNANCE_KEYWORDS.source
    }));
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

      const normalizedEvents = [];
      for (const evt of events) {
        if (!validateAgentEvent(evt)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              ok: false,
              error:
                'Invalid event payload; agent_id, path, action, and timestamp required; action must be one of create, modify, delete'
            })
          );
          return;
        }

        const agentId = evt.agent_id || evt.agentId || null;
        if (!validateAgentId(agentId)) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ ok: false, error: 'Unknown agent_id' }));
          return;
        }

        normalizedEvents.push(normalizeAgentEvent(evt, agentId));
      }

      const summary = await processAgentEventsBatch(normalizedEvents);
      const agentIdForLog = describeAgentIds(normalizedEvents);
      console.log(
        `agent_ingest: received=${summary.received} processed=${summary.processed} duplicates=${summary.duplicates} agentId=${agentIdForLog}`
      );

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, ...summary }));
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
  loadServerConfig();
  loadMetadataRules();
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
