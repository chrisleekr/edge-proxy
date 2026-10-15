# Get started

Run the whole system on your machine, send traffic through it and publish a change. Takes about five minutes, most of it the first image build.

You need Docker with Compose v2 and `make`.

## 1. Start it

```bash
make demo
```

This starts admin, Postgres, Valkey, one edge, a mock upstream and a mock identity provider (`loadtest/compose.yaml`). A seed job creates an admin user, publishes a sample policy and gives the edge its service token.

| Service | Address |
|---|---|
| Edge (traffic) | `http://127.0.0.1:8080` |
| Admin UI | `http://127.0.0.1:8081`, user `loadtest`, password `load test password for local runs only` |

## 2. Send traffic

The edge trusts the client IP only from its CDN. Here `curl` plays the CDN by sending CloudFront's viewer header:

```bash
curl -i -H 'Host: api.example.com' -H 'CloudFront-Viewer-Address: 203.0.113.7:443' http://127.0.0.1:8080/hello
```

The mock upstream answers `200`. The sample policy also has these rules:

| Request | Rule | Result |
|---|---|---|
| `/private/...` with no token | `private-needs-auth` | `401` with `WWW-Authenticate: Bearer` |
| More than 100 `/login` per minute from one IP | `login` | `429` |

Try the limit:

```bash
for i in $(seq 1 105); do curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: api.example.com' -H 'CloudFront-Viewer-Address: 203.0.113.9:443' http://127.0.0.1:8080/login; done | sort | uniq -c
```

You should see 100 `200`s and five `429`s.

## 3. Change the policy

1. Open the admin UI and sign in.
2. On **Rules**, open `login`. In **Then**, change `"limit": 100` to `5`, then **Apply to draft** and **Save draft**.
3. On **Publish**, enter a message and press **Publish**.
4. Within a few seconds the edge loads the new version. Run the loop again with a new IP, such as `203.0.113.10`: only 5 requests get through.
5. On **Versions**, open the new version and **Revert** it if you want the old limit back. A revert is itself a new version.

Every step you took is on **Audit**.

## 4. Clean up

```bash
make demo-down
```

!!! warning "Demo only"
    The demo trusts any peer as a CDN so that `curl` on your machine can stand in for one, and its secrets are in the compose file. Never copy its settings into a deployment. See [Deploy](deploy/index.md).

## Next

- [Policy](use/policy.md): what rules can match and do.
- [Dashboard](use/dashboard.md): every page of the admin UI.
