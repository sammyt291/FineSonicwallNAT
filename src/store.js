'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, encoded) {
  const [salt, expected] = String(encoded).split(':');
  if (!salt || !expected) return false;
  const actual = crypto.scryptSync(password, salt, 64);
  const target = Buffer.from(expected, 'hex');
  return actual.length === target.length && crypto.timingSafeEqual(actual, target);
}

class Store {
  constructor(file) {
    this.file = file;
    this.state = { users: [], firewalls: [], forwards: [], nextIds: { user: 1, firewall: 1, forward: 1 } };
    this.load();
  }

  load() {
    if (fs.existsSync(this.file)) this.state = JSON.parse(fs.readFileSync(this.file, 'utf8'));
  }

  save() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const temporary = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(temporary, `${JSON.stringify(this.state, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temporary, this.file);
  }

  createOwner(username, password) {
    if (this.state.users.some((user) => user.permanentAdmin)) throw new Error('A permanent administrator already exists.');
    if (!username || password.length < 10) throw new Error('Username is required and password must be at least 10 characters.');
    const user = { id: this.state.nextIds.user++, username, passwordHash: hashPassword(password), role: 'admin', permanentAdmin: true };
    this.state.users.push(user); this.save(); return user;
  }

  authenticate(username, password) {
    const user = this.state.users.find((entry) => entry.username === username);
    return user && verifyPassword(password, user.passwordHash) ? user : null;
  }

  user(id) { return this.state.users.find((entry) => entry.id === Number(id)); }
  firewall(id) { return this.state.firewalls.find((entry) => entry.id === Number(id)); }

  addUser({ username, password, role }) {
    if (this.state.users.some((user) => user.username === username)) throw new Error('That username already exists.');
    if (!['viewer', 'operator', 'admin'].includes(role) || password.length < 10) throw new Error('Use a valid role and a password of at least 10 characters.');
    this.state.users.push({ id: this.state.nextIds.user++, username, passwordHash: hashPassword(password), role, permanentAdmin: false }); this.save();
  }

  addFirewall(input) {
    const firewall = { id: this.state.nextIds.firewall++, ...input };
    this.state.firewalls.push(firewall); this.save(); return firewall;
  }

  updateForward(id, changes) {
    const forward = this.state.forwards.find((entry) => entry.id === Number(id));
    if (!forward) throw new Error('Port forward not found.');
    Object.assign(forward, changes); this.save(); return forward;
  }

  addForward(input) {
    if (!this.firewall(input.firewallId)) throw new Error('Select a configured firewall.');
    for (const port of [input.sourcePort, input.destinationPort]) {
      if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Ports must be between 1 and 65535.');
    }
    const forward = { id: this.state.nextIds.forward++, ...input, enabled: true, status: 'pending', createdAt: new Date().toISOString() };
    this.state.forwards.push(forward); this.save(); return forward;
  }
}

module.exports = { Store, hashPassword, verifyPassword };
