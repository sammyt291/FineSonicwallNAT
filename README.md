# NATpilot — SonicWall NAT Manager

NATpilot is a Node.js/Express web application for documenting and managing SonicWall port forwards from an internal server. It provides local role-based accounts, firewall inventory, a guided NAT rule builder, and a searchable overview.

> NATpilot writes port forwards through the official SonicOS REST API. Validate changes on a non-production appliance first and keep a current configuration backup.

## Requirements

- Node.js 20 or newer
- An internal HTTPS reverse proxy, or a certificate and private key for NATpilot's built-in HTTPS listener

## First-time setup

```bash
npm install
cp config.example.json config.json
# Edit config.json, especially sessionSecret.
npm run init -- --username admin --password 'choose-a-long-password'
npm start
```

The first account is the permanent owner and cannot be demoted. NATpilot refuses to start until this account exists.

## Server and HTTPS configuration

NATpilot reads `./config.json` by default. Set `NATPILOT_CONFIG=/path/to/config.json` to use another file.

```json
{
  "host": "0.0.0.0",
  "port": 8443,
  "https": {
    "enabled": true,
    "certificate": "/etc/letsencrypt/live/natpilot/fullchain.pem",
    "privateKey": "/etc/letsencrypt/live/natpilot/privkey.pem",
    "certificateAuthority": null,
    "watch": true,
    "settleMilliseconds": 2000
  },
  "dataFile": "./data/natpilot.json",
  "sessionSecret": "replace-with-a-long-random-value"
}
```

- `host` and `port` select the listener address.
- `https.enabled` selects HTTP or HTTPS.
- `certificate`, `privateKey`, and optional `certificateAuthority` accept absolute paths or paths relative to the config file.
- With `https.watch` enabled, NATpilot watches the certificate directories, including atomic file replacements used by certificate renewal tools. It waits until file sizes and modification times remain unchanged for `settleMilliseconds`, then gracefully closes and recreates the HTTPS listener with the new certificate. In-flight connections are allowed to finish.
- `dataFile` is created with owner-only permissions and updated using an atomic rename.

## SonicOS API deployment

NATpilot supports the stable SonicOS 7 API used by current TZ Gen 7 appliances (including TZ 570/570W/670 and comparable models) and probes the SonicOS API v8 path first for forward compatibility. Enable **SonicOS API** and HTTPS management on the appliance, create a dedicated administrator, then use **Admin → Test API** before deploying.

A deployment stages consistently named public/private address objects, source address objects or a group, public/private service objects, an IPv4 NAT policy, and a WAN-to-LAN access rule. NATpilot commits all staged changes only after every request succeeds; if any request fails it sends `DELETE /config/pending` to discard the staged transaction and records the error on the rule. Separate public and private ports, TCP/UDP, source CIDRs, zones, and inbound/outbound interfaces are supported.

The client negotiates SHA-256 or MD5 HTTP Digest authentication (with Basic fallback for older configurations), recognizes bearer tokens returned by newer firmware, and honors each firewall's TLS verification setting. SonicOS permits a limited number of administrator sessions, so a conflicting active administrator session can prevent deployment.

Implementation references: [SonicOS 7.1 API Guide](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-1-api/Content/Topics/Overview/api-overview.htm) and [SonicOS 7.1 system administration documentation](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-1-system/Content/Topics/API/api.htm).

## Roles

- **Viewer:** read-only dashboard and JSON rule inventory.
- **Operator:** create, enable, and disable forwards.
- **Admin:** operator abilities plus firewall, account, role, and deletion management.

## Production notes

Use a random, stable `sessionSecret`, restrict the listener to trusted networks, back up the data file, and use a least-privilege SonicWall API account. Firewall credentials are stored in the owner-only data file in this MVP; integrate a secrets manager for production deployments.

## Tests

```bash
npm test
npm run check
```
