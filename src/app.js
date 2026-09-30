'use strict';

const express = require('express');
const session = require('express-session');
const { SonicWallClient, deployPortForward } = require('./sonicwall');

function createApp({ store, config, deploy = deployPortForward }) {
  const app = express();
  app.set('view engine', 'ejs');
  app.set('views', `${__dirname}/../views`);
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());
  app.use('/static', express.static(`${__dirname}/../static`));
  app.use(session({
    name: 'natpilot.sid', secret: config.sessionSecret || 'development-only-change-me',
    resave: false, saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'strict', secure: Boolean(config.https.enabled), maxAge: 8 * 60 * 60 * 1000 },
  }));

  app.use((req, res, next) => {
    req.currentUser = store.user(req.session.userId);
    res.locals.currentUser = req.currentUser;
    res.locals.message = req.session.message;
    delete req.session.message;
    next();
  });
  const message = (req, text, type = 'success') => { req.session.message = { text, type }; };
  const requireLogin = (req, res, next) => req.currentUser ? next() : res.redirect('/login');
  const requireRole = (...roles) => (req, res, next) => {
    if (!req.currentUser) return res.redirect('/login');
    if (!roles.includes(req.currentUser.role)) { message(req, 'You do not have permission to perform that action.', 'error'); return res.redirect('/'); }
    return next();
  };

  app.get('/login', (req, res) => res.render('login'));
  app.post('/login', (req, res) => {
    const user = store.authenticate(String(req.body.username || '').trim(), req.body.password || '');
    if (!user) { message(req, 'Incorrect username or password.', 'error'); return res.redirect('/login'); }
    req.session.regenerate((error) => {
      if (error) return res.status(500).send('Unable to create session');
      req.session.userId = user.id; return res.redirect('/');
    });
  });
  app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

  app.get('/', requireLogin, (req, res) => {
    const forwards = store.state.forwards.map((forward) => ({ ...forward, firewallName: store.firewall(forward.firewallId)?.name || 'Unknown' }));
    const stats = { total: forwards.length, active: forwards.filter((rule) => rule.enabled).length,
      firewalls: store.state.firewalls.length, restricted: forwards.filter((rule) => rule.sourceIps !== 'Any').length };
    res.render('dashboard', { forwards, stats });
  });

  app.get('/forwards/new', requireRole('admin', 'operator'), (_req, res) => res.render('forward-form', { firewalls: store.state.firewalls }));
  app.post('/forwards/new', requireRole('admin', 'operator'), (req, res) => {
    try {
      store.addForward({ name: req.body.name.trim(), firewallId: Number(req.body.firewallId), protocol: req.body.protocol,
        sourcePort: Number(req.body.sourcePort), destinationPort: Number(req.body.destinationPort), externalIp: req.body.externalIp.trim(),
        internalIp: req.body.internalIp.trim(), sourceIps: req.body.sourceIps.trim() || 'Any',
        fromZone: req.body.fromZone.trim() || 'WAN', toZone: req.body.toZone.trim() || 'LAN',
        inboundInterface: req.body.inboundInterface.trim() || 'Any', outboundInterface: req.body.outboundInterface.trim() || 'Any', createdBy: req.currentUser.id });
      message(req, 'Port forward saved and queued for deployment.'); return res.redirect('/');
    } catch (error) { message(req, error.message, 'error'); return res.redirect('/forwards/new'); }
  });
  app.post('/forwards/:id/toggle', requireRole('admin', 'operator'), (req, res) => {
    const rule = store.state.forwards.find((entry) => entry.id === Number(req.params.id));
    if (rule) { rule.enabled = !rule.enabled; store.save(); message(req, 'Rule state updated.'); }
    res.redirect('/');
  });
  app.post('/forwards/:id/deploy', requireRole('admin', 'operator'), async (req, res) => {
    const rule = store.state.forwards.find((entry) => entry.id === Number(req.params.id));
    const firewall = rule && store.firewall(rule.firewallId);
    if (!rule || !firewall) { message(req, 'Rule or firewall not found.', 'error'); return res.redirect('/'); }
    store.updateForward(rule.id, { status: 'deploying', deploymentError: null });
    try {
      const result = await deploy(firewall, rule);
      store.updateForward(rule.id, { status: 'deployed', deployedAt: new Date().toISOString(), remoteObjects: result.names, apiVersion: result.apiVersion });
      message(req, `Rule deployed and committed through SonicOS API v${result.apiVersion}.`);
    } catch (error) {
      store.updateForward(rule.id, { status: 'failed', deploymentError: error.message });
      message(req, `Deployment failed: ${error.message}`, 'error');
    }
    return res.redirect('/');
  });
  app.post('/forwards/:id/delete', requireRole('admin'), (req, res) => {
    store.state.forwards = store.state.forwards.filter((entry) => entry.id !== Number(req.params.id)); store.save();
    message(req, 'Rule removed.'); res.redirect('/');
  });

  app.get('/admin', requireRole('admin'), (_req, res) => res.render('admin', { users: store.state.users, firewalls: store.state.firewalls }));
  app.post('/admin/firewalls/:id/test', requireRole('admin'), async (req, res) => {
    const firewall = store.firewall(req.params.id);
    if (!firewall) { message(req, 'Firewall not found.', 'error'); return res.redirect('/admin'); }
    try {
      const client = new SonicWallClient(firewall); await client.login(); const version = await client.get('version');
      firewall.lastTestedAt = new Date().toISOString(); firewall.lastTestResult = 'Connected'; firewall.version = version; store.save();
      message(req, `Connected successfully using ${client.baseUrl.endsWith('/v8') ? 'SonicOS API v8' : 'SonicOS API v7'}.`);
    } catch (error) { firewall.lastTestResult = error.message; store.save(); message(req, `Connection failed: ${error.message}`, 'error'); }
    return res.redirect('/admin');
  });
  app.post('/admin/firewalls', requireRole('admin'), (req, res) => {
    store.addFirewall({ name: req.body.name.trim(), host: req.body.host.trim().replace(/\/$/, ''), username: req.body.username,
      password: req.body.password, verifyTls: req.body.verifyTls === 'on' });
    message(req, 'Firewall added.'); res.redirect('/admin');
  });
  app.post('/admin/users', requireRole('admin'), (req, res) => {
    try { store.addUser(req.body); message(req, 'Account created.'); } catch (error) { message(req, error.message, 'error'); }
    res.redirect('/admin');
  });
  app.post('/admin/users/:id/role', requireRole('admin'), (req, res) => {
    const user = store.user(req.params.id);
    if (!user || user.permanentAdmin) message(req, 'The permanent administrator cannot be changed.', 'error');
    else if (!['viewer', 'operator', 'admin'].includes(req.body.role)) message(req, 'Invalid role.', 'error');
    else { user.role = req.body.role; store.save(); message(req, 'Permissions updated.'); }
    res.redirect('/admin');
  });
  app.get('/api/forwards', requireLogin, (_req, res) => res.json(store.state.forwards));
  return app;
}

module.exports = { createApp };
