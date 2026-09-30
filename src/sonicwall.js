'use strict';

const crypto = require('node:crypto');
const https = require('node:https');
const nodeFetch = require('node-fetch');

class SonicWallError extends Error {
  constructor(message, status, details) {
    super(message); this.name = 'SonicWallError'; this.status = status; this.details = details;
  }
}

function parseDigestChallenge(header = '') {
  const challenges = header.split(/,\s*(?=Digest\s)/i).filter((part) => /^\s*Digest\s/i.test(part));
  const parsed = challenges.map((part) => {
    const values = {};
    const input = part.replace(/^\s*Digest\s+/i, '');
    for (const match of input.matchAll(/(\w+)="([^"]*)"/g)) values[match[1]] = match[2];
    for (const match of input.matchAll(/(\w+)=([^",\s]+)/g)) values[match[1]] ??= match[2];
    return values;
  }).filter((item) => item.realm && item.nonce);
  return parsed.find((item) => String(item.algorithm).toUpperCase().startsWith('SHA-256')) || parsed[0];
}

class SonicWallClient {
  constructor({ host, username, password, verifyTls = true, timeoutMs = 15000, fetchImpl = nodeFetch }) {
    this.origin = /^https?:\/\//i.test(host) ? host.replace(/\/$/, '') : `https://${host.replace(/\/$/, '')}`;
    this.username = username; this.password = password; this.verifyTls = verifyTls;
    this.timeoutMs = timeoutMs; this.fetchImpl = fetchImpl;
    this.baseUrl = ''; this.challenge = null; this.nonceCount = 0; this.bearerToken = null;
    this.agent = new https.Agent({ rejectUnauthorized: verifyTls });
  }

  async rawFetch(url, options = {}) {
    // node-fetch style mocks use agent; Node's built-in fetch ignores it. SonicWall
    // appliances should use a trusted cert in production; NODE_TLS_REJECT_UNAUTHORIZED
    // is deliberately not modified process-wide.
    return this.fetchImpl(url, { ...options, agent: this.agent, signal: AbortSignal.timeout(this.timeoutMs) });
  }

  async initialize() {
    const candidates = [`${this.origin}/api/sonicos/v8`, `${this.origin}/api/sonicos`];
    for (const candidate of candidates) {
      try {
        const response = await this.rawFetch(`${candidate}/auth`, { method: 'POST', headers: this.headers(), body: '{}' });
        if (response.status < 400 || response.headers.get('www-authenticate')) { this.baseUrl = candidate; return this; }
      } catch { /* try the stable SonicOS 7 path next */ }
    }
    throw new SonicWallError(`No supported SonicOS API found at ${this.origin}. Enable SonicOS API and HTTPS management.`);
  }

  headers(method, target) {
    const headers = { Accept: 'application/json', 'Content-Type': 'application/json' };
    if (this.bearerToken) headers.Authorization = `Bearer ${this.bearerToken}`;
    else if (this.challenge && method && target) headers.Authorization = this.digestHeader(method, target);
    return headers;
  }

  digestHeader(method, target) {
    const item = this.challenge;
    const algorithm = String(item.algorithm || 'MD5').toUpperCase();
    const digest = (value) => crypto.createHash(algorithm.startsWith('SHA-256') ? 'sha256' : 'md5').update(value).digest('hex');
    const cnonce = crypto.randomBytes(8).toString('hex');
    const nc = (++this.nonceCount).toString(16).padStart(8, '0');
    let ha1 = digest(`${this.username}:${item.realm}:${this.password}`);
    if (algorithm.endsWith('-SESS')) ha1 = digest(`${ha1}:${item.nonce}:${cnonce}`);
    const ha2 = digest(`${method}:${target}`);
    const qop = item.qop?.split(',').map((value) => value.trim()).find((value) => value === 'auth') || item.qop;
    const response = qop ? digest(`${ha1}:${item.nonce}:${nc}:${cnonce}:${qop}:${ha2}`) : digest(`${ha1}:${item.nonce}:${ha2}`);
    let header = `Digest username="${this.username}", realm="${item.realm}", nonce="${item.nonce}", uri="${target}", response="${response}", algorithm=${item.algorithm || 'MD5'}`;
    if (qop) header += `, qop=${qop}, nc=${nc}, cnonce="${cnonce}"`;
    if (item.opaque) header += `, opaque="${item.opaque}"`;
    return header;
  }

  async login() {
    if (!this.baseUrl) await this.initialize();
    const url = `${this.baseUrl}/auth`; const target = new URL(url).pathname;
    let response = await this.rawFetch(url, { method: 'POST', headers: this.headers(), body: '{}' });
    if (response.status === 401) {
      this.challenge = parseDigestChallenge(response.headers.get('www-authenticate'));
      if (this.challenge) response = await this.rawFetch(url, { method: 'POST', headers: this.headers('POST', target), body: '{}' });
      else response = await this.rawFetch(url, { method: 'POST', headers: { ...this.headers(), Authorization: `Basic ${Buffer.from(`${this.username}:${this.password}`).toString('base64')}` }, body: '{}' });
    }
    if (response.status === 403) throw new SonicWallError('Another SonicWall administrator session is active.', 403);
    if (!response.ok) throw await this.apiError(response, 'SonicWall login failed');
    const body = await response.json().catch(() => ({}));
    const info = body.status?.info; this.bearerToken = (Array.isArray(info) ? info[0] : info)?.bearer_token || null;
  }

  async request(method, path, body) {
    if (!this.baseUrl) await this.login();
    const url = `${this.baseUrl}/${path.replace(/^\//, '')}`; const target = new URL(url).pathname;
    let response = await this.rawFetch(url, { method, headers: this.headers(method, target), body: body === undefined ? undefined : JSON.stringify(body) });
    if (response.status === 401) {
      const challenge = parseDigestChallenge(response.headers.get('www-authenticate'));
      if (challenge) { this.challenge = challenge; this.nonceCount = 0; }
      else await this.login();
      response = await this.rawFetch(url, { method, headers: this.headers(method, target), body: body === undefined ? undefined : JSON.stringify(body) });
    }
    if (!response.ok) throw await this.apiError(response, `${method} ${path} failed`);
    const text = await response.text(); return text ? JSON.parse(text) : {};
  }

  async apiError(response, fallback) {
    const text = await response.text().catch(() => ''); let details;
    try { details = JSON.parse(text); } catch { details = text; }
    const info = details?.status?.info; const message = (Array.isArray(info) ? info[0] : info)?.message;
    return new SonicWallError(message || `${fallback} (HTTP ${response.status})`, response.status, details);
  }

  get(path) { return this.request('GET', path); }
  post(path, body = {}) { return this.request('POST', path, body); }
  delete(path) { return this.request('DELETE', path); }
}

function objectName(rule, suffix) {
  const stem = String(rule.name || 'Port forward').replace(/[^a-z0-9._ -]/gi, '').trim().replace(/\s+/g, '-').slice(0, 32);
  return `NATPILOT-${rule.id}-${stem}-${suffix}`;
}

function addressPayload(name, zone, ip) {
  if (ip.includes('/')) {
    const [network, prefix] = ip.split('/');
    const bits = Number(prefix); const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    const subnetMask = [24, 16, 8, 0].map((shift) => (mask >>> shift) & 255).join('.');
    return { name, zone, network: { subnet: network, mask: subnetMask } };
  }
  return { name, zone, host: { ip } };
}

async function deployPortForward(firewall, rule, clientFactory = (settings) => new SonicWallClient(settings)) {
  const client = clientFactory(firewall);
  await client.login();
  const names = {
    publicAddress: objectName(rule, 'PUBLIC'), internalAddress: objectName(rule, 'PRIVATE'),
    publicService: objectName(rule, `SERVICE-${rule.sourcePort}`), privateService: objectName(rule, `SERVICE-${rule.destinationPort}`),
    source: rule.sourceIps === 'Any' ? 'Any' : objectName(rule, 'SOURCES'), nat: objectName(rule, 'NAT'), access: objectName(rule, 'ACCESS'),
  };
  try {
    await client.post('address-objects/ipv4', { address_objects: [{ ipv4: addressPayload(names.publicAddress, rule.fromZone || 'WAN', rule.externalIp) }] });
    await client.post('address-objects/ipv4', { address_objects: [{ ipv4: addressPayload(names.internalAddress, rule.toZone || 'LAN', rule.internalIp) }] });
    if (rule.sourceIps !== 'Any') {
      const sources = rule.sourceIps.split(',').map((source) => source.trim()).filter(Boolean);
      const members = [];
      for (let index = 0; index < sources.length; index += 1) {
        const name = objectName(rule, `SOURCE-${index + 1}`); members.push({ name });
        await client.post('address-objects/ipv4', { address_objects: [{ ipv4: addressPayload(name, rule.fromZone || 'WAN', sources[index]) }] });
      }
      if (members.length === 1) names.source = members[0].name;
      else await client.post('address-groups/ipv4', { address_groups: [{ address_group: { name: names.source, address_object: members } }] });
    }
    const protocols = rule.protocol === 'TCP/UDP' ? ['TCP', 'UDP'] : [rule.protocol];
    const createService = async (name, port) => {
      if (protocols.length === 1) {
        const protocol = protocols[0]; const key = protocol.toLowerCase();
        await client.post('service-objects', { service_objects: [{ name, protocol: { protocol_type: protocol, [key]: { begin: port, end: port } } }] });
      } else {
        const members = [];
        for (const protocol of protocols) {
          const memberName = `${name}-${protocol}`; const key = protocol.toLowerCase(); members.push({ name: memberName });
          await client.post('service-objects', { service_objects: [{ name: memberName, protocol: { protocol_type: protocol, [key]: { begin: port, end: port } } }] });
        }
        await client.post('service-groups', { service_groups: [{ name, service_object: members }] });
      }
    };
    await createService(names.publicService, rule.sourcePort);
    if (rule.destinationPort === rule.sourcePort) names.privateService = names.publicService;
    else await createService(names.privateService, rule.destinationPort);
    await client.post('nat-policies/ipv4', { nat_policies: [{ ipv4: {
      name: names.nat, enable: true, original_source: { name: names.source }, translated_source: { name: 'Original' },
      original_destination: { name: names.publicAddress }, translated_destination: { name: names.internalAddress },
      original_service: { name: names.publicService }, translated_service: { name: names.privateService },
      inbound_interface: { name: rule.inboundInterface || 'Any' }, outbound_interface: { name: rule.outboundInterface || 'Any' },
      comment: `Managed by NATpilot rule ${rule.id}`,
    } }] });
    await client.post('access-rules/ipv4', { access_rules: [{ ipv4: {
      name: names.access, action: 'allow', from: { zone: rule.fromZone || 'WAN' }, to: { zone: rule.toZone || 'LAN' },
      source: { address: { name: names.source } }, destination: { address: { name: names.publicAddress } },
      service: { name: names.publicService }, enable: true, log: true, comment: `Managed by NATpilot rule ${rule.id}`,
    } }] });
    await client.post('config/pending');
    return { names, apiVersion: client.baseUrl.endsWith('/v8') ? 8 : 7 };
  } catch (error) {
    await client.delete('config/pending').catch(() => {});
    throw error;
  }
}

module.exports = { SonicWallClient, SonicWallError, parseDigestChallenge, addressPayload, deployPortForward, objectName };
