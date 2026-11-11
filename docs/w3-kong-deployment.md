# W3 Kong State B deployment

## What this deployment changes

- VAmPI no longer publishes host port `5000`.
- Kong is the only public proxy on host port `8000`; the Kong Admin API is not published.
- VAmPI requires `VAMPI_JWT_SECRET` at startup. The secret is supplied from an ignored runtime file.
- Kong DB-less configuration has public login/register routes and a protected catch-all route with `jwt`, `acl`, and `rate-limiting` plugins.

## Operator requirements before deployment

1. On Ubuntu Server, pull the current Git branch containing these changes.
2. Confirm the existing `vampi` container holds the W2 test data. The deployment script makes a timestamped copy of `/vampi/database/database.db` before it removes that container.
3. Create the ignored file `.env.state-b` from `.env.state-b.example`, then generate a new Base64URL secret. Do not reuse `random` or any W2 secret. The deployment script rejects the example placeholder.
4. Review the generated backup in `.state-b/backups/` before considering W2 data safe. The script stops VAmPI before copying SQLite to avoid a concurrent-write snapshot.
5. This deployment refuses to create an empty database. For a clean rebuild, restore a prepared lab database first; the reproducible seed procedure is tracked separately for W4 packaging.

## Deploy

```bash
cd /path/to/owasp-api-defense-lab
cp .env.state-b.example .env.state-b
nano .env.state-b
chmod 600 .env.state-b
./deploy_state_b.sh --replace-vampi
```

The explicit `--replace-vampi` flag is required because the operation stops and recreates the application container. It is not a command to run until the test database backup has been checked.

Before removing VAmPI, the script renders the ignored runtime configuration and runs `kong config parse` in the pinned `kong:3.9.1` image. A malformed `kong.yml` therefore stops the deployment before the W2 database container is changed.

## First validation on Ubuntu

```bash
docker ps --format 'table {{.Names}}\t{{.Ports}}'
docker logs --tail 100 kong-gateway
docker logs --tail 100 vampi
```

Expected ports: Kong exposes `0.0.0.0:8000`; VAmPI has no host port; Kong Admin API has no host port.

## Required Kali evidence

1. `curl -i http://UBUNTU_IP:5000/` fails to connect.
2. `POST /users/v1/login` through port 8000 succeeds and produces a JWT with `iss=vampi-state-b`.
3. A valid JWT reaches `/me`; no Authorization header gets `401` from Kong.
4. Compare `docker logs kong-gateway` and `docker logs vampi`: the rejected request is present only in Kong's log.
5. Send six login requests in one minute from the same Kali IP: the sixth is `429`.
6. Send 61 requests to a protected route in one minute from one Kali IP with one valid token: the 61st is `429`.

## Scope note

The `acl` plugin confirms the request maps to Kong's `authenticated` group. It does not decide ownership of a book or user-specific admin rights. Those controls remain W3-BACKEND work. The protected-route rate limit uses source IP because this lab intentionally has one shared Kong Consumer; it is therefore a lab-level control, not a per-user quota.
