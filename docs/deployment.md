# Deployment on a VM

Installation guide for the platform on an internal Linux virtual machine, behind
a DNS name and an enterprise certificate. Reference files: `deploy/`.

## Target architecture

```
Analysts (browser)
   │  HTTPS, VM DNS name, enterprise certificate
   ▼
nginx  ──  serves the built front end (web/dist)
   │       relays /api to the internal API (SSE without buffering)
   ▼
uvicorn (systemd service `sherlock`, dedicated user, 127.0.0.1:8000, 1 worker)
   │
   ├── /var/lib/sherlock/hunts.db        internal database (hunts, reports, audit, CTI analyses)
   ├── /var/lib/sherlock/.secrets.enc    encrypted store of the API keys (entered in the Configuration screen)
   └── /etc/sherlock/sherlock.env             server configuration (never an API key inside)
```

Network egress from the VM, to open on the firewall and proxy side:

| Destination | Usage | Path |
|---|---|---|
| Internal AI gateway | agent reasoning | direct (internal) |
| On-prem anonymization endpoint | semantic anonymization | direct (internal) |
| `login.microsoftonline.com`, `api.loganalytics.io`, `graph.microsoft.com` | Sentinel, Defender | internet proxy |
| `oauth2.googleapis.com`, `*-chronicle.googleapis.com` | Google SecOps | internet proxy |
| `api.tavily.com`, `otx.alienvault.com`, `www.circl.lu`, `www.virustotal.com`, `threatfox.abuse.ch` + report pages | threat intelligence (the only outbound flow of the upstream phase) | internet proxy |

## Prerequisites

- Linux VM (Debian/Ubuntu; adapt the packages for RHEL), root access.
- Python 3.11 or 3.12 with the `venv` module; Node 20 (only to build the front end,
  otherwise build elsewhere and copy `web/dist`); nginx; rsync.
- The VM DNS name and its TLS certificate (full chain + private key), obtained from your
  PKI or an ACME provider.
- The access credentials: AI gateway URL and key, anonymization endpoint and key, SIEM identities
  (SecOps service account, Entra ID app registration), threat intelligence keys.

## Installation

1. Clone the repository on the VM and run the script, as root:

   ```bash
   git clone <repo-url> ~/sherlock-src && cd ~/sherlock-src
   sudo bash deploy/install.sh
   ```

   The script creates the `sherlock` user, installs the code in `/opt/sherlock`, the dependencies
   in a venv, builds the front end, generates `/etc/sherlock/sherlock.env` with an encrypted-store
   key, installs and starts the systemd service, and drops the nginx configuration.

2. Complete `/etc/sherlock/sherlock.env`: AI gateway and model identifiers, anonymization endpoint,
   internal DNS suffixes, internet proxy and CA bundle. Then `systemctl restart sherlock`.
   The Sentinel workspace can be entered from the Configuration screen (Subscription ID,
   resource group, workspace name: the platform finds the Workspace ID through Azure
   Resource Manager); `SHL_WORKSPACE_ALIASES` remains the path for multiple workspaces
   and takes precedence if set.

3. Certificate and DNS: place the chain in `/etc/sherlock/tls/fullchain.pem` and the key in
   `/etc/sherlock/tls/privkey.pem` (mode 600, root), set `server_name` in
   `/etc/nginx/sites-available/sherlock`, enable the site:

   ```bash
   ln -s /etc/nginx/sites-available/sherlock /etc/nginx/sites-enabled/
   nginx -t && systemctl reload nginx
   ```

4. First administrator account (once only, password prompted at the keyboard):

   ```bash
   sudo -u sherlock env $(grep -v '^#' /etc/sherlock/sherlock.env | xargs) \
     /opt/sherlock/.venv/bin/python /opt/sherlock/scripts/create_account.py <identifier> --roles analyst,admin
   ```

5. Open `https://<dns-name>/`, sign in, then in **Configuration** enter the keys
   (AI gateway, anonymizer, SIEM, threat intelligence) and test each connection. The keys go into
   the encrypted store `/var/lib/sherlock/.secrets.enc`; they are never read back by the API.

## Checks

- `curl -s https://<dns-name>/health`: `{"status":"ok", ...}` with the number of active SIEM
  sources.
- `journalctl -u sherlock -f`: service logs (no secret appears there).
- Launch a short hypothesis hunt and follow the investigation feed.

## Operations

- **Update**: `git pull` in the clone, then `sudo bash deploy/install.sh` (the script
  is idempotent: it replaces the code, reinstalls the dependencies, rebuilds the front end and
  restarts the service). A hunt in progress at the moment of restart is lost - deploy
  outside investigation windows; hunts in the upstream phase are restored from the database.
- **Backups**: `/var/lib/sherlock/hunts.db` and `/var/lib/sherlock/.secrets.enc`, with the
  `SHL_SECRET_STORE_KEY` key from `/etc/sherlock/sherlock.env` kept separately (without it, the store is
  unreadable and the API keys have to be re-entered).
- **Rotation**: the API keys are replaced in the Configuration screen; the certificate is
  replaced in `/etc/sherlock/tls/` followed by `systemctl reload nginx`.
- **Vault**: set `SHL_KEY_VAULT_URL` and grant the VM's managed identity
  the Secrets User and Secrets Officer roles on the vault: the local store is no longer used.

## What changes between development and production

`SHL_ENVIRONMENT=prod` disables the development conveniences: no more secrets read from
`SHL_SECRET_*` environment variables (encrypted store or vault only), no more
test identity headers, simulated SIEM mode refused, session cookie marked `Secure`.
