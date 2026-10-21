# Get started

Run the whole system on your machine, send traffic through it and publish a change. Takes about five minutes, most of it the first image build.

You need Docker with Compose v2 and `make`.

## 1. Start it

```bash
make demo
```

This starts admin, Postgres, Valkey, one edge, a mock upstream, a mock identity provider and a log shipper that posts the edge's access lines to admin for **Routes** (`loadtest/compose.yaml`). A seed job creates an admin user, publishes the demo policy (`loadtest/tools/demo-policy.json`) and gives the edge its service token. The demo policy has an example of each kind of rule, template, CORS policy, issuer and setting, so every page of the admin UI has something on it.

| Service | Address |
|---|---|
| Edge (traffic) | `http://127.0.0.1:8080` |
| Admin UI | `http://127.0.0.1:8081`, user `admin`, password `local-dev-login` |

## 2. Send traffic

The edge reads the client IP from the CDN's header, and only when the request comes from a peer in `TRUSTED_PROXIES`. The demo sets `TRUSTED_PROXIES` to every address, so here `curl` plays that path by sending CloudFront's viewer header:

```bash
curl -i -H 'Host: api.example.com' -H 'CloudFront-Viewer-Address: 203.0.113.7:443' http://127.0.0.1:8080/hello
```

The mock upstream answers `200`. Some of the demo policy's rules:

| Request | Rule | Result |
|---|---|---|
| `/private/...` with no token | `private-needs-auth` | `401` with `WWW-Authenticate: Bearer` |
| More than 2 `/login` per minute from one IP | `login-per-ip` | `429` as an HTML page (the `friendly-429` template), and the IP stays blocked for a 1 minute penalty |
| `/api/` from one IP faster than 20 per minute, after a burst of 10 | `api-burst` | `429` |
| `/api/` from one IP over 10 per minute | `api-shadow` | Nothing: it is log only, so **Stats** counts what it would have limited. Its 1 minute penalty only applies once it is set to block |

Try the login limit:

```bash
for i in $(seq 1 5); do curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: api.example.com' -H 'CloudFront-Viewer-Address: 203.0.113.9:443' http://127.0.0.1:8080/login; done | sort | uniq -c
```

You should see two `200`s and three `429`s.

To watch the dashboard fill up, send steady traffic that exercises every rule, template, CORS policy and issuer, until you press Ctrl+C:

```bash
make demo-traffic
```

`RATE` (requests per second, default 200) and `IPS` (client addresses, default 300) change it, for example `RATE=1000 make demo-traffic`. Requests show on the dashboard within about 20 seconds. The demo's edge waits up to 150ms for Valkey (`VALKEY_TIMEOUT`, 50ms by default), because a Docker VM with 2 CPUs that also runs the traffic can pause Valkey for longer than 50ms.

To see what the edge does when Valkey is down, run this in a second terminal while the traffic runs. It pauses Valkey for 90 seconds (`OUTAGE`), and the dashboard then says what each rule's **When Valkey cannot answer** setting did with the checks Valkey did not answer: uncounted, a `503`, or counted on the edge alone:

```bash
make demo-outage
```

## 3. Change the policy

1. Open the admin UI and sign in.
2. On **Rules**, open `login-per-ip`. In **Then**, set **Limit** to `5`, then **Apply to draft** and **Save draft**.
3. On **Publish**, enter a message and press **Publish to all traffic**.
4. Within a few seconds the edge loads the new version. Run the loop again with a new IP, such as `203.0.113.10`, and `seq 1 7`: five requests get through.
5. On **Versions**, open the new version and **Revert** it if you want the old limit back. A revert is itself a new version.

Every step you took is on **Audit**.

## 4. Clean up

```bash
make demo-down
```

!!! warning "Demo only"
    The demo trusts any peer as a CDN so that `curl` on your machine can stand in for one, its secrets are in the compose file, and its log shipper reads Docker's socket to find the edge's output. Never copy its settings into a deployment. See [Deploy](deploy/index.md).

## Next

- [Policy](use/policy.md): what rules can match and do.
- [Dashboard](use/dashboard.md): every page of the admin UI.
