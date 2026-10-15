#!/bin/sh
# Container build + smoke (CLAUDE.md quality gates): builds the edge, admin
# and load-test images, then checks the edge image becomes ready from a
# bootstrap snapshot with no admin or Valkey. POSIX sh, so it also runs in
# the docker image GitLab uses.
set -eu
cd "$(dirname "$0")/../.."

docker build -q -f build/edge.Dockerfile -t edge-proxy/edge:dev .
docker build -q -f build/admin.Dockerfile -t edge-proxy/admin:dev .
docker build -q -f build/tools.Dockerfile -t edge-proxy/tools:dev .

id="edge-smoke-$$"
cleanup() { docker rm -f "${id}" >/dev/null 2>&1 || true; docker volume rm "${id}" >/dev/null 2>&1 || true; docker network rm "${id}" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker network create "${id}" >/dev/null
docker volume create "${id}" >/dev/null
docker run --rm -e SHARED=/shared -v "${id}:/shared" edge-proxy/tools:dev bootstrap
docker run -d --name "${id}" --network "${id}" --network-alias edge -v "${id}:/shared:ro" \
  -e BOOTSTRAP_PATH=/shared/bootstrap.json -e CLIENT_IP_SOURCE=cloudfront -e TRUSTED_PROXIES=10.0.0.0/8 \
  -e UPSTREAMS=app=http://upstream:8080 -e UPSTREAM_HOSTS=api.example.com=app edge-proxy/edge:dev >/dev/null
if ! docker run --rm --network "${id}" edge-proxy/tools:dev probe http://edge:9090/readyz; then
  docker logs "${id}"
  exit 1
fi
echo "edge image ready from a bootstrap snapshot"
