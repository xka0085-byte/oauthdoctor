import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { spawn } from 'node:child_process';
import path from 'node:path';

const cli = path.resolve('bin/oauthdoctor.mjs');
const server = createServer((req, res) => {
  const target = `http://127.0.0.1:${server.address()?.port}/mcp`;
  if (req.url === '/mcp') {
    res.writeHead(401, { 'www-authenticate': `Bearer resource_metadata="${target}/.well-known/oauth-protected-resource"` });
    res.end(); return;
  }
  if (req.url.endsWith('/.well-known/oauth-protected-resource')) {
    const body = req.headers['x-test-mismatch'] ? { resource: `${target}/wrong` } : { resource: target };
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); return;
  }
  res.writeHead(404); res.end();
});
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const target = `http://127.0.0.1:${server.address().port}/mcp`;
function run(url) { return new Promise(resolve => { const p = spawn(process.execPath, [cli, 'inspect', url, '--json'], { env: { ...process.env } }); let out = ''; let err = ''; p.stdout.on('data', x => out += x); p.stderr.on('data', x => err += x); p.on('close', code => resolve({ code, report: out ? JSON.parse(out) : null, error: err })); }); }
try {
  const good = await run(target);
  assert.equal(good.code, 0); assert.equal(good.report.status, 'PASS');
  assert.equal(good.report.findings.some(x => x.code === 'PRM_NO_AUTHORIZATION_SERVERS'), false);
  const mismatchServer = createServer((req, res) => {
    const base = `http://127.0.0.1:${mismatchServer.address()?.port}/mcp`;
    if (req.url === '/mcp') { res.writeHead(401, { 'www-authenticate': `Bearer resource_metadata="${base}/meta"` }); res.end(); }
    else if (req.url.endsWith('/meta')) { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ resource: `${base}/other` })); }
    else { res.writeHead(404); res.end(); }
  });
  mismatchServer.listen(0, '127.0.0.1'); await once(mismatchServer, 'listening');
  const bad = await run(`http://127.0.0.1:${mismatchServer.address().port}/mcp`);
  assert.equal(bad.code, 1); assert.ok(bad.report.findings.some(x => x.code === 'PRM_RESOURCE_MISMATCH'));
  mismatchServer.close();
  const publicEndpoint = await run(`${target}/missing`);
  assert.equal(publicEndpoint.code, 1); assert.equal(publicEndpoint.report.status, 'FAIL');
  console.log('oauthdoctor smoke tests passed');
} finally { server.close(); }
