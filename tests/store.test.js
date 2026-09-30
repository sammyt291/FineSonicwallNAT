'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { Store, hashPassword, verifyPassword } = require('../src/store');

test('passwords use a salted scrypt hash', () => {
  const encoded = hashPassword('correct horse battery staple');
  assert.equal(verifyPassword('correct horse battery staple', encoded), true);
  assert.equal(verifyPassword('incorrect', encoded), false);
  assert.equal(encoded.includes('correct horse'), false);
});

test('owner is permanent and rules persist', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'natpilot-'));
  const file = path.join(directory, 'data.json');
  const store = new Store(file);
  const owner = store.createOwner('owner', 'very-long-password');
  assert.equal(owner.permanentAdmin, true);
  assert.throws(() => store.createOwner('other', 'very-long-password'));
  const firewall = store.addFirewall({ name: 'HQ', host: 'https://fw.local' });
  store.addForward({ firewallId: firewall.id, sourcePort: 443, destinationPort: 8443, sourceIps: 'Any' });
  assert.equal(new Store(file).state.forwards[0].destinationPort, 8443);
});
