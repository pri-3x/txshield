# Deploy TxShield on Oracle Cloud (Always Free)

One VM runs everything: the API (with Anvil simulation), the dashboard,
Postgres, and Caddy for automatic HTTPS. Only ports 80 and 443 are public.
The API needs an API key, the dashboard needs a password, and `/metrics`
and the database are not reachable from the internet.

Cost: Oracle's Always Free Ampere (ARM) allowance covers this (2 OCPU and
12 GB of memory as of mid 2026; check the current limits in your account).
Sepolia RPC: a free Alchemy or Infura plan is enough for a demo.

## 1. Create the VM (Oracle console)

1. Sign up at cloud.oracle.com (a card is needed for identity verification).
2. **Compute → Instances → Create instance**
   - Image: **Canonical Ubuntu 24.04**
   - Shape: **Ampere → VM.Standard.A1.Flex**, 2 OCPU, 12 GB memory
     ("Out of capacity" errors are common; retry later or in another
     availability domain)
   - Networking: keep "Assign a public IPv4 address" on
   - SSH keys: paste your public key (`cat ~/.ssh/id_ed25519.pub`)
3. **Open ports 80 and 443**: instance → subnet → default security list →
   **Add ingress rules**: source `0.0.0.0/0`, TCP, destination ports `80,443`.

## 2. Get a Sepolia RPC URL

Create a free app at alchemy.com (or infura.io) for **Ethereum Sepolia** and
copy its HTTPS URL, for example `https://eth-sepolia.g.alchemy.com/v2/<key>`.
You add it on the VM yourself in step 3; it never needs to leave the VM.

## 3. Install

```bash
ssh ubuntu@<public-ip>
```

```bash
git clone https://github.com/pri-3x/txshield.git && cd txshield
```

```bash
deploy/oracle/setup.sh
```

The first run installs Docker and adds you to the `docker` group: log out,
log back in, and run it again. The next run writes `deploy/oracle/.env`
with generated secrets. Then add your RPC URL:

```bash
nano deploy/oracle/.env
```

Set `TXSHIELD_RPC_URLS=11155111=https://eth-sepolia.g.alchemy.com/v2/<key>`, save, and run
`deploy/oracle/setup.sh` once more. It builds the images (several minutes
the first time) and prints the URLs:

- Dashboard: `https://app.<ip-with-dashes>.sslip.io` (user `admin`)
- API: `https://api.<ip-with-dashes>.sslip.io`

The passwords and API keys are in `deploy/oracle/.env` (`cat` it on the VM).
`sslip.io` hostnames resolve to the IP inside them, so no domain is needed.
To use your own domain, point DNS at the VM and set `API_HOST` and
`APP_HOST` in `.env`.

## 4. Connect the browser extension

Extension settings: API URL `https://api.<ip-with-dashes>.sslip.io`, API key
`TXSHIELD_CLIENT_API_KEY` from `.env`, dashboard URL
`https://app.<ip-with-dashes>.sslip.io`. Switch your wallet to Sepolia.

## Operate

```bash
cd ~/txshield
```

```bash
docker compose -f deploy/oracle/docker-compose.yml --env-file deploy/oracle/.env logs -f api
```

Update to the latest code:

```bash
git pull && deploy/oracle/setup.sh
```

Give someone API access: generate a key (`openssl rand -hex 20`), append it
to `TXSHIELD_API_KEYS` in `.env` (comma-separated, at least 24 characters),
and re-run `setup.sh`.

## Limits

- One small VM: simulations run two at a time; limits are 1 request per
  second per client with bursts of 10.
- Analyses are kept for 14 days without sender addresses or calldata (the
  default privacy settings).
- Free-tier capacity and limits are Oracle's to change; idle Always Free
  instances can be reclaimed, so log in occasionally.
