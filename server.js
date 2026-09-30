#!/usr/bin/env node
'use strict';

const http = require('node:http');
const https = require('node:https');
const readline = require('node:readline/promises');
const process = require('node:process');
const { createApp } = require('./src/app');
const { loadConfig, readTlsOptions, watchCertificates } = require('./src/config');
const { Store } = require('./src/store');

async function initialize(store) {
  const args = process.argv.slice(3);
  const value = (name) => args[args.indexOf(name) + 1];
  let username = value('--username');
  let password = value('--password');
  if (!username || !password) {
    if (!process.stdin.isTTY) throw new Error('Use --username and --password in non-interactive environments.');
    const prompt = readline.createInterface({ input: process.stdin, output: process.stdout });
    username ||= await prompt.question('Permanent admin username: ');
    password ||= await prompt.question('Permanent admin password (10+ characters): ');
    prompt.close();
  }
  store.createOwner(username, password);
  console.log(`Permanent administrator '${username}' created.`);
}

function runServer(app, config) {
  let server;
  const listen = (tlsOptions) => new Promise((resolve, reject) => {
    server = config.https.enabled ? https.createServer(tlsOptions || readTlsOptions(config), app) : http.createServer(app);
    server.once('error', reject);
    server.listen(config.port, config.host, () => {
      console.log(`NATpilot listening on ${config.https.enabled ? 'https' : 'http'}://${config.host}:${config.port}`);
      resolve();
    });
  });
  const restart = async () => {
    let tlsOptions;
    try {
      // Validate and load the replacement pair before taking the current listener down.
      tlsOptions = readTlsOptions(config);
    } catch (error) {
      console.error('New certificate could not be read; keeping the current listener.', error);
      return;
    }
    console.log('Stable certificate change detected; restarting HTTPS listener…');
    await new Promise((resolve) => server.close(resolve));
    try { await listen(tlsOptions); console.log('HTTPS certificate reloaded.'); }
    catch (error) { console.error('New certificate could not be loaded; retry after the next certificate change.', error); }
  };
  return listen().then(() => {
    if (config.https.enabled && config.https.watch) watchCertificates(config, restart);
    return server;
  });
}

async function main() {
  const config = loadConfig();
  const store = new Store(config.dataFile);
  if (process.argv[2] === 'init') return initialize(store);
  if (!store.state.users.some((user) => user.permanentAdmin)) throw new Error('No owner exists. Run `npm run init -- --username admin --password ...` first.');
  return runServer(createApp({ store, config }), config);
}

if (require.main === module) main().catch((error) => { console.error(error.message); process.exitCode = 1; });
module.exports = { initialize, runServer };
