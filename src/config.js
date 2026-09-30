'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_CONFIG = Object.freeze({
  host: '0.0.0.0',
  port: 8080,
  https: {
    enabled: false,
    certificate: '',
    privateKey: '',
    certificateAuthority: null,
    watch: true,
    settleMilliseconds: 2000,
  },
  dataFile: './data/natpilot.json',
  sessionSecret: '',
});

function loadConfig(configPath = process.env.NATPILOT_CONFIG || './config.json') {
  const absoluteConfigPath = path.resolve(configPath);
  let supplied = {};
  if (fs.existsSync(absoluteConfigPath)) {
    supplied = JSON.parse(fs.readFileSync(absoluteConfigPath, 'utf8'));
  }
  const config = {
    ...DEFAULT_CONFIG,
    ...supplied,
    https: { ...DEFAULT_CONFIG.https, ...(supplied.https || {}) },
  };
  config.port = Number(config.port);
  if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
    throw new Error('config.port must be an integer between 1 and 65535');
  }
  if (config.https.enabled && (!config.https.certificate || !config.https.privateKey)) {
    throw new Error('HTTPS requires https.certificate and https.privateKey');
  }
  const base = path.dirname(absoluteConfigPath);
  config.dataFile = path.resolve(base, config.dataFile);
  for (const key of ['certificate', 'privateKey', 'certificateAuthority']) {
    if (config.https[key]) config.https[key] = path.resolve(base, config.https[key]);
  }
  config.configPath = absoluteConfigPath;
  return config;
}

function readTlsOptions(config) {
  const options = {
    cert: fs.readFileSync(config.https.certificate),
    key: fs.readFileSync(config.https.privateKey),
  };
  if (config.https.certificateAuthority) {
    options.ca = fs.readFileSync(config.https.certificateAuthority);
  }
  return options;
}

/**
 * Watch parent directories instead of certificate files themselves: atomic renewals
 * commonly replace an inode. Events are debounced, then sizes and mtimes must remain
 * unchanged for the complete settle window before the callback is invoked.
 */
function watchCertificates(config, onStableChange, logger = console) {
  const files = [config.https.certificate, config.https.privateKey, config.https.certificateAuthority]
    .filter(Boolean).map((file) => path.resolve(file));
  const directories = [...new Set(files.map(path.dirname))];
  const settle = Math.max(250, Number(config.https.settleMilliseconds) || 2000);
  let timer;
  let closed = false;
  let lastSnapshot = '';

  const snapshot = () => files.map((file) => {
    try {
      const stat = fs.statSync(file);
      return `${file}:${stat.size}:${stat.mtimeMs}`;
    } catch {
      return `${file}:missing`;
    }
  }).join('|');

  const waitUntilStable = () => {
    clearTimeout(timer);
    const before = snapshot();
    timer = setTimeout(() => {
      if (closed) return;
      const after = snapshot();
      if (before !== after || after.includes(':missing')) {
        waitUntilStable();
        return;
      }
      if (after !== lastSnapshot) {
        lastSnapshot = after;
        Promise.resolve(onStableChange()).catch((error) => logger.error('Certificate reload failed:', error));
      }
    }, settle);
  };

  lastSnapshot = snapshot();
  const watchers = directories.map((directory) => fs.watch(directory, (_event, filename) => {
    if (!filename || files.includes(path.resolve(directory, filename.toString()))) waitUntilStable();
  }));
  return () => {
    closed = true;
    clearTimeout(timer);
    watchers.forEach((watcher) => watcher.close());
  };
}

module.exports = { DEFAULT_CONFIG, loadConfig, readTlsOptions, watchCertificates };
