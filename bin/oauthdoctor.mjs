#!/usr/bin/env node
import { createHash } from 'node:crypto';

const VERSION = '0.1.0';
const LIMIT = 1_048_576;
const TIMEOUT = 10_000;
const help = `oauthdoctor ${VERSION}\nRead-only MCP OAuth discovery diagnostics.\nUsage: oauthdoctor inspect <https-url> [--json]\nNo login, token exchange, or credential storage is performed.`;
const findings = [];

function add(code, severity, message, evidence = null) {
  findings.push({ code, severity, message, evidence });
}

async function get(url) {
  const response = await fetch(url, {
    redirect: 'manual',
    signal: AbortSignal.timeout(TIMEOUT),
    headers: { accept: 'application/json' },
  });
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > LIMIT) throw Error('response exceeds 1 MiB');
  return { status: response.status, headers: response.headers, body: bytes.toString('utf8') };
}

function parse(value) {
  try { return JSON.parse(value); } catch { return null; }
}

const args = process.argv.slice(2);
if (args.includes('--help') || !args.length) {
  console.log(help);
  process.exitCode = args.length ? 0 : 3;
} else if (args[0] !== 'inspect' || !args[1]) {
  console.error(help);
  process.exitCode = 3;
} else {
  let target;
  try {
    target = new URL(args[1]);
    const localHttp = target.protocol === 'http:' && ['127.0.0.1', 'localhost', '::1'].includes(target.hostname);
    if (target.protocol !== 'https:' && !localHttp) throw Error('OAuth metadata must use HTTPS (HTTP is allowed only for localhost fixtures)');
  } catch (error) {
    console.error(`Invalid target: ${error.message}`);
    target = null;
    process.exitCode = 3;
  }

  if (target) {
    let report;
    try {
      const challenge = await get(target);
      const wwwAuthenticate = challenge.headers.get('www-authenticate');
      let resourceMetadataUrl = null;
      if (challenge.status !== 401) add('NO_401', 'FAIL', `Expected unauthenticated HTTP 401, received ${challenge.status}`);
      if (!wwwAuthenticate) add('NO_WWW_AUTHENTICATE', 'FAIL', '401 response must include WWW-Authenticate with resource_metadata');
      else {
        const match = wwwAuthenticate.match(/resource_metadata\s*=\s*"?([^",\s]+)"?/i);
        if (match) resourceMetadataUrl = match[1];
        else add('NO_RESOURCE_METADATA', 'FAIL', 'WWW-Authenticate does not expose a parseable resource_metadata URL');
      }

      let prm = null;
      let as = null;
      if (resourceMetadataUrl) {
        const metadata = await get(new URL(resourceMetadataUrl, target).toString());
        if (metadata.status !== 200) add('PRM_NOT_200', 'FAIL', `Protected Resource Metadata returned ${metadata.status}`);
        prm = parse(metadata.body);
        if (!prm) add('PRM_INVALID_JSON', 'FAIL', 'Protected Resource Metadata is not JSON');
        else {
          if (prm.resource !== target.toString()) add('PRM_RESOURCE_MISMATCH', 'FAIL', 'Protected Resource Metadata resource does not match the requested resource URL');
          if (prm.authorization_servers !== undefined) {
            if (!Array.isArray(prm.authorization_servers) || !prm.authorization_servers.length) {
              add('PRM_INVALID_AUTHORIZATION_SERVERS', 'FAIL', 'authorization_servers must be a non-empty array when present');
            } else {
              let issuerUrl;
              try {
                issuerUrl = new URL(prm.authorization_servers[0]);
                if (issuerUrl.protocol !== 'https:') throw Error('issuer must use HTTPS');
              } catch {
                add('PRM_INVALID_AUTHORIZATION_SERVER', 'FAIL', 'authorization_servers must contain valid HTTPS issuer URLs');
              }
              if (issuerUrl) {
                const authorizationMetadata = await get(new URL('/.well-known/oauth-authorization-server', issuerUrl).toString());
                if (authorizationMetadata.status !== 200) add('AS_METADATA_NOT_200', 'FAIL', `Authorization Server Metadata returned ${authorizationMetadata.status}`);
                as = parse(authorizationMetadata.body);
                if (!as) add('AS_METADATA_INVALID_JSON', 'FAIL', 'Authorization Server Metadata is not JSON');
                else {
                  if (!as.issuer) add('AS_ISSUER_MISSING', 'FAIL', 'Authorization Server Metadata is missing issuer');
                  else {
                    try { if (new URL(as.issuer).origin !== issuerUrl.origin) add('ISSUER_ORIGIN_MISMATCH', 'FAIL', 'Metadata issuer origin differs from advertised authorization server'); }
                    catch { add('AS_ISSUER_INVALID', 'FAIL', 'Authorization Server Metadata issuer is not a valid URL'); }
                  }
                  if (!as.authorization_endpoint) add('AUTHORIZATION_ENDPOINT_MISSING', 'FAIL', 'authorization_endpoint is missing');
                  if (!as.token_endpoint) add('TOKEN_ENDPOINT_MISSING', 'FAIL', 'token_endpoint is missing');
                  if (!as.code_challenge_methods_supported?.includes('S256')) add('PKCE_S256_NOT_ADVERTISED', 'WARN', 'S256 PKCE support is not advertised; this probe does not execute authorization');
                }
              }
            }
          }
        }
      }

      if (!findings.some((finding) => finding.severity === 'FAIL')) add('DISCOVERY_METADATA_PRESENT', 'INFO', '401 challenge and valid protected resource metadata were observed; authorization server metadata is checked only when advertised');
      report = {
        tool: 'oauthdoctor', version: VERSION, checkedAt: new Date().toISOString(), target: target.origin + target.pathname,
        status: findings.some((finding) => finding.severity === 'FAIL') ? 'FAIL' : 'PASS', findings,
        observations: { httpStatus: challenge.status, resourceMetadataUrl, prmHash: prm ? createHash('sha256').update(JSON.stringify(prm)).digest('hex') : null, asIssuer: as?.issuer ?? null, authorizationEndpoint: as?.authorization_endpoint ?? null, tokenEndpoint: as?.token_endpoint ?? null },
        limitations: ['Discovery-only, read-only probe. No OAuth authorization, token exchange, PKCE round trip, scope behavior, token audience validation, or refresh flow was tested.', 'A PASS is not an OAuth security certification.'],
      };
    } catch (error) {
      report = { tool: 'oauthdoctor', version: VERSION, checkedAt: new Date().toISOString(), target: target.origin + target.pathname, status: 'UNKNOWN', findings: [...findings, { code: 'PROBE_FAILED', severity: 'UNKNOWN', message: error.message }], limitations: ['External endpoint unavailable or response could not be safely parsed.'] };
    }
    console.log(args.includes('--json') ? JSON.stringify(report, null, 2) : `${report.status} ${report.target}\n${report.findings.map((finding) => `${finding.severity} ${finding.code}: ${finding.message}`).join('\n')}\nLimitations: ${report.limitations.join(' ')}`);
    process.exitCode = report.status === 'PASS' ? 0 : report.status === 'FAIL' ? 1 : 2;
  }
}
