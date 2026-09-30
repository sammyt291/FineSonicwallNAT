'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { loadConfig, watchCertificates } = require('../src/config');

test('loads HTTPS paths relative to config and validates the port', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'natpilot-config-'));
  const file = path.join(directory, 'config.json');
  fs.writeFileSync(file, JSON.stringify({ port: 9443, https: { enabled: true, certificate: 'tls/cert.pem', privateKey: 'tls/key.pem' } }));
  const config = loadConfig(file);
  assert.equal(config.port, 9443);
  assert.equal(config.https.certificate, path.join(directory, 'tls/cert.pem'));
});

test('certificate watcher waits for files to settle and handles atomic replacement', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'natpilot-tls-'));
  const cert = path.join(directory, 'cert.pem'); const key = path.join(directory, 'key.pem');
  fs.writeFileSync(cert, 'old cert'); fs.writeFileSync(key, 'old key');
  let reloads = 0;
  const stop = watchCertificates({ https: { certificate: cert, privateKey: key, certificateAuthority: null, settleMilliseconds: 250 } }, () => { reloads += 1; });
  fs.writeFileSync(`${cert}.new`, 'new cert'); fs.renameSync(`${cert}.new`, cert);
  fs.writeFileSync(key, 'partial');
  await new Promise((resolve) => setTimeout(resolve, 100));
  fs.writeFileSync(key, 'complete key');
  await new Promise((resolve) => setTimeout(resolve, 450));
  stop();
  assert.equal(reloads, 1);
});
