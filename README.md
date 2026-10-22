# Edge Proxy

A Go reverse proxy that sits between your CDN or WAF and the load balancer or gateway that routes your services. It enforces application policy for every route in one layer (rate limits shared by every replica, JWT validation, CORS, header rules, locale detection and templated error responses), then forwards each request, `Host` unchanged, to that one load balancer or gateway. Policy is managed in an admin UI, where every change is validated, tested, published as a version, optionally canaried and written to a tamper-evident audit log.

```text
CDN / WAF  ->  Edge Proxy  ->  your load balancer or gateway  ->  your services
```

**Documentation:** https://chrisleekr.github.io/edge-proxy/. Start with [why it exists and what it does not do](docs/index.md), then [Get started](docs/get-started.md).

## Try it

Needs Docker with Compose v2 and `make`.

```bash
make demo        # one edge, admin, Postgres, Valkey, a log shipper and mocks
make demo-down   # remove everything
```

[Get started](docs/get-started.md) has the admin sign-in, requests to send and a change to publish. To run it for real, see [Deploy](docs/deploy/index.md).

## Develop

```bash
make test   # tests with real Valkey and Postgres, plus the 100% edge coverage gate
make ci     # every gate CI runs
```

`make` lists every target. See [Development](docs/build/development.md) for the full list, CI and releases.
