const { test, before, after } = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const path = require('node:path');

const PORT = 3100;
const BASE_URL = `http://localhost:${PORT}`;
const ROOT = path.resolve(__dirname, '..');

let serverProcess;

async function waitForServerReady(proc) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      proc.kill('SIGTERM');
      reject(new Error('Server did not start within 10s'));
    }, 10000);

    proc.once('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`Server exited early with code ${code}`));
    });

    const onData = (chunk) => {
      const output = chunk.toString();
      if (output.includes('FIM server running')) {
        clearTimeout(timer);
        proc.stdout.off('data', onData);
        resolve();
      }
    };

    proc.stdout.on('data', onData);
  });
}

before(async () => {
  serverProcess = spawn(process.execPath, ['server/index.js'], {
    env: { ...process.env, PORT: PORT.toString() },
    cwd: ROOT,
    stdio: ['ignore', 'pipe', 'pipe']
  });

  await waitForServerReady(serverProcess);
});

after(() => {
  if (serverProcess && !serverProcess.killed) {
    serverProcess.kill('SIGTERM');
  }
});

test('GET /api/events responds with event list and baseline size', async () => {
  const response = await fetch(`${BASE_URL}/api/events`);
  assert.strictEqual(response.status, 200);
  const data = await response.json();
  assert.ok(Array.isArray(data.events), 'events should be an array');
  assert.strictEqual(typeof data.baselineSize, 'number', 'baselineSize should be numeric');
});

test('GET /api/config exposes watch directory and governance filter', async () => {
  const response = await fetch(`${BASE_URL}/api/config`);
  assert.strictEqual(response.status, 200);
  const data = await response.json();
  assert.ok(data.watchDir && typeof data.watchDir === 'string', 'watchDir should be provided');
  assert.ok(data.governanceFilter && typeof data.governanceFilter === 'string', 'governanceFilter should be provided');
});

