'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { addressPayload, deployPortForward, parseDigestChallenge, SonicWallClient } = require('../src/sonicwall');

test('parses SHA-256 digest authentication challenge', () => {
  const result = parseDigestChallenge('Digest realm="sonicwall", nonce="abc", qop="auth", algorithm=SHA-256');
  assert.equal(result.realm, 'sonicwall');
  assert.equal(result.algorithm, 'SHA-256');
});

test('converts CIDR source to SonicOS network object', () => {
  assert.deepEqual(addressPayload('Office', 'WAN', '198.51.100.0/24'), {
    name: 'Office', zone: 'WAN', network: { subnet: '198.51.100.0', mask: '255.255.255.0' },
  });
});

test('deployment stages objects, NAT and access policies, then commits', async () => {
  const calls = [];
  const client = {
    baseUrl: 'https://fw/api/sonicos', login: async () => {},
    post: async (path, body) => { calls.push({ method: 'POST', path, body }); return {}; },
    delete: async (path) => { calls.push({ method: 'DELETE', path }); },
  };
  const result = await deployPortForward({ host: 'fw' }, {
    id: 9, name: 'Camera HTTPS', externalIp: '203.0.113.5', internalIp: '10.0.0.5', sourceIps: '198.51.100.10',
    sourcePort: 443, destinationPort: 8443, protocol: 'TCP', fromZone: 'WAN', toZone: 'LAN', inboundInterface: 'X1', outboundInterface: 'X0',
  }, () => client);
  assert.equal(result.apiVersion, 7);
  assert.equal(calls.at(-1).path, 'config/pending');
  const nat = calls.find((call) => call.path === 'nat-policies/ipv4').body.nat_policies[0].ipv4;
  assert.equal(nat.inbound_interface.name, 'X1');
  assert.equal(nat.translated_service.name.endsWith('SERVICE-8443'), true);
  const access = calls.find((call) => call.path === 'access-rules/ipv4').body.access_rules[0].ipv4;
  assert.equal(access.from.zone, 'WAN');
  assert.equal(access.action, 'allow');
  assert.equal(calls.find((call) => call.path === 'address-groups/ipv4'), undefined);
});

test('deployment discards all staged changes after an API failure', async () => {
  const calls = [];
  const client = {
    baseUrl: 'https://fw/api/sonicos', login: async () => {},
    post: async (path) => { calls.push(`POST ${path}`); if (path === 'nat-policies/ipv4') throw new Error('rejected'); return {}; },
    delete: async (path) => { calls.push(`DELETE ${path}`); },
  };
  await assert.rejects(() => deployPortForward({}, {
    id: 1, name: 'Test', externalIp: '203.0.113.1', internalIp: '10.0.0.1', sourceIps: 'Any', sourcePort: 80, destinationPort: 80, protocol: 'TCP',
  }, () => client), /rejected/);
  assert.equal(calls.at(-1), 'DELETE config/pending');
});

test('client probes SonicOS v8 before the stable v7 API', async () => {
  const urls = [];
  const response = (status, auth) => ({ status, ok: status < 400, headers: { get: () => auth }, json: async () => ({}), text: async () => '' });
  const client = new SonicWallClient({ host: 'fw.local', username: 'api', password: 'secret', fetchImpl: async (url) => {
    urls.push(url); return url.includes('/v8/') ? response(404) : response(401, 'Digest realm="sonicwall", nonce="abc", qop="auth", algorithm=SHA-256');
  } });
  await client.initialize();
  assert.equal(client.baseUrl, 'https://fw.local/api/sonicos');
  assert.equal(urls[0], 'https://fw.local/api/sonicos/v8/auth');
});
