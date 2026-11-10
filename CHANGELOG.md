# Changelog

## [1.2.0](https://github.com/chrisleekr/edge-proxy/compare/v1.1.0...v1.2.0) (2026-11-10)


### Features

* **admin:** add attention acks, autopilot case switches and DRAIN_DELAY ([#24](https://github.com/chrisleekr/edge-proxy/issues/24)) ([b87d807](https://github.com/chrisleekr/edge-proxy/commit/b87d807fac7aafe5a72c5654b19e96a2db375e4f))
* **edge:** add trusted client allowlist (snapshot schema 6) ([#23](https://github.com/chrisleekr/edge-proxy/issues/23)) ([78673bd](https://github.com/chrisleekr/edge-proxy/commit/78673bd62e14c578a6fb42e3ecc1e7ed6540675a))
* **ui:** rework admin navigation and add allowlist, autopilot and attention controls ([#25](https://github.com/chrisleekr/edge-proxy/issues/25)) ([c4a5d07](https://github.com/chrisleekr/edge-proxy/commit/c4a5d0778533a351465f8c37850106f489b0674c))


### Bug Fixes

* **loadtest:** replace config_rules in the autopilot load-full setup ([#21](https://github.com/chrisleekr/edge-proxy/issues/21)) ([feeabbb](https://github.com/chrisleekr/edge-proxy/commit/feeabbb27e5fb5baf6719ae1485952859ea95005))

## [1.1.0](https://github.com/chrisleekr/edge-proxy/compare/v1.0.0...v1.1.0) (2026-11-03)


### Features

* **admin:** add anomaly notifications, overlay rules and the autopilot API ([#16](https://github.com/chrisleekr/edge-proxy/issues/16)) ([2cd041f](https://github.com/chrisleekr/edge-proxy/commit/2cd041ff145ce07542ff09802e5f0abdddeb38f5))
* **autopilot:** add the autopilot runner with its image, CI and load tests ([#17](https://github.com/chrisleekr/edge-proxy/issues/17)) ([eac3096](https://github.com/chrisleekr/edge-proxy/commit/eac30964b7d67c7fccb163cc37ce0e8f67201ace))
* **edge:** add client signals, distinct and response-count limits, and rule expiry ([#15](https://github.com/chrisleekr/edge-proxy/issues/15)) ([8bbe37e](https://github.com/chrisleekr/edge-proxy/commit/8bbe37efe921a2b8c361bf6dded78b15fc397b6b))
* **tracing:** add OpenTelemetry tracing to edge and admin ([#12](https://github.com/chrisleekr/edge-proxy/issues/12)) ([1910976](https://github.com/chrisleekr/edge-proxy/commit/1910976f4847e9a45c8fe64e693163e6642c98a2))
* **ui:** add autopilot, memory, notifications, find and client pages to the admin UI ([#18](https://github.com/chrisleekr/edge-proxy/issues/18)) ([a327bcc](https://github.com/chrisleekr/edge-proxy/commit/a327bccf00d9ea457d57f8d0b7af3d7ac5119190))

## 1.0.0 (2026-10-22)


### Features

* single UPSTREAM_URL edge, observed routes, and admin bootstrap (backend) ([#2](https://github.com/chrisleekr/edge-proxy/issues/2)) ([a425126](https://github.com/chrisleekr/edge-proxy/commit/a425126b8293a21fac32b020f5aa7211089bc183))
* **ui:** redesign admin UI with dashboard, routes view and docs screenshot gate ([#3](https://github.com/chrisleekr/edge-proxy/issues/3)) ([ed1964d](https://github.com/chrisleekr/edge-proxy/commit/ed1964dcd7a5f0dbcd251866af00b4ec55d0c2cf))
