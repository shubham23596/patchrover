import { spawn } from 'node:child_process';
import { access, mkdir, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve } from 'node:path';

const host = '127.0.0.1';
const port = 4173;
const url = `http://${host}:${port}/`;
const reportDirectory = resolve('.lighthouseci/reports');
const lighthouseCLI = resolve('node_modules/lighthouse/cli/index.js');

async function executable(candidates) {
  for (const candidate of candidates) {
    if (!candidate) continue;
    if (!candidate.includes('/')) return candidate;
    try {
      await access(candidate, constants.X_OK);
      return candidate;
    } catch {
      // Try the next known Chrome location.
    }
  }
  throw new Error('Chrome was not found. Set CHROME_PATH to a Chrome or Chromium executable.');
}

function run(command, args, options = {}) {
  return new Promise((accept, reject) => {
    const child = spawn(command, args, { stdio: options.stdio || 'inherit', ...options });
    child.once('error', reject);
    child.once('exit', (code) => code === 0 ? accept() : reject(new Error(`${command} exited with ${code}`)));
  });
}

async function waitForServer() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // The preview server is still starting.
    }
    await new Promise((accept) => setTimeout(accept, 250));
  }
  throw new Error(`preview did not become ready at ${url}`);
}

const chromePath = await executable([
  process.env.CHROME_PATH,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  'google-chrome',
  'chromium'
]);

await mkdir(reportDirectory, { recursive: true });
const server = spawn('npm', ['run', 'preview', '--', '--host', host, '--port', String(port)], {
  stdio: ['ignore', 'pipe', 'pipe'],
  env: { ...process.env, ASTRO_TELEMETRY_DISABLED: '1' }
});

try {
  await waitForServer();
  const scores = [];
  for (let index = 1; index <= 3; index += 1) {
    const output = resolve(reportDirectory, `run-${index}.json`);
    await run(process.execPath, [
      lighthouseCLI,
      url,
      '--quiet',
      '--output=json',
      `--output-path=${output}`,
      '--chrome-flags=--headless --no-sandbox --disable-gpu',
      '--only-categories=performance,accessibility,best-practices,seo'
    ], { env: { ...process.env, CHROME_PATH: chromePath } });
    const report = JSON.parse(await readFile(output, 'utf8'));
    scores.push(Object.fromEntries(Object.entries(report.categories).map(([id, category]) => [id, category.score])));
  }

  const categories = ['performance', 'accessibility', 'best-practices', 'seo'];
  let failed = false;
  for (const category of categories) {
    const values = scores.map((score) => score[category]).sort((left, right) => left - right);
    const median = values[Math.floor(values.length / 2)];
    const formatted = Math.round(median * 100);
    console.log(`${category}: ${formatted}`);
    if (median < 0.95) failed = true;
  }
  if (failed) throw new Error('one or more Lighthouse median scores are below 95');
} finally {
  server.kill('SIGTERM');
}
