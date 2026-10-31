#!/bin/sh
# Container build + smoke: builds the edge, admin, autopilot runner and
# load-test images, then checks the edge image becomes ready from a
# bootstrap snapshot with no admin or Valkey, and the runner image starts on
# a read-only root, refuses to run without its settings and holds the Claude
# Code binary for its platform. POSIX sh, so it also runs in the docker image
# GitLab uses.
set -eu
cd "$(dirname "$0")/../.."

docker build -q -f build/edge.Dockerfile -t edge-proxy/edge:dev .
docker build -q -f build/admin.Dockerfile -t edge-proxy/admin:dev .
docker build -q -f build/tools.Dockerfile -t edge-proxy/tools:dev .
docker build -q -f build/autopilot.Dockerfile -t edge-proxy/autopilot:dev .

# Without -tags grpcnotrace each binary silently grows by about 13 MB. The
# build info is plain text in the binary, so grep finds the tag without Go.
bins="$(mktemp -d)"
for name in edge admin tools; do
  c="$(docker create "edge-proxy/${name}:dev")"
  docker cp -q "${c}:/${name}" "${bins}/${name}"
  docker rm "${c}" >/dev/null
  if ! grep -aq 'tags=grpcnotrace' "${bins}/${name}"; then
    echo "${name} image was built without -tags grpcnotrace" >&2
    exit 1
  fi
done
rm -rf "${bins}"

# The runner is Node, not Go, so it is not in the loop above.
rc=0
out="$(docker run --rm --read-only --tmpfs /tmp edge-proxy/autopilot:dev 2>&1)" || rc=$?
case "${rc}:${out}" in
  1:*AUTOPILOT_ADMIN_URL*) echo "autopilot image refuses to run without AUTOPILOT_ADMIN_URL" ;;
  *) echo "${out}" >&2; echo "autopilot image exited ${rc}; want 1 naming AUTOPILOT_ADMIN_URL" >&2; exit 1 ;;
esac
# npm skips a non-matching optional package silently; without it every Claude
# run fails. This checks only the image built for this host's platform.
docker run --rm --read-only edge-proxy/autopilot:dev -e \
  "process.getBuiltinModule('node:fs').accessSync('node_modules/@anthropic-ai/claude-agent-sdk-linux-' + process.arch + '/claude')" \
  || { echo "autopilot image has no Claude Code binary for its platform" >&2; exit 1; }

id="edge-smoke-$$"
cleanup() { docker rm -f "${id}" >/dev/null 2>&1 || true; docker volume rm "${id}" >/dev/null 2>&1 || true; docker network rm "${id}" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker network create "${id}" >/dev/null
docker volume create "${id}" >/dev/null
docker run --rm -e SHARED=/shared -v "${id}:/shared" edge-proxy/tools:dev bootstrap
docker run -d --name "${id}" --network "${id}" --network-alias edge -v "${id}:/shared:ro" \
  -e BOOTSTRAP_PATH=/shared/bootstrap.json -e CLIENT_IP_SOURCE=cloudfront -e TRUSTED_PROXIES=10.0.0.0/8 \
  -e UPSTREAM_URL=http://upstream:8080 edge-proxy/edge:dev >/dev/null
if ! docker run --rm --network "${id}" edge-proxy/tools:dev probe http://edge:9090/readyz; then
  docker logs "${id}"
  exit 1
fi
echo "edge image ready from a bootstrap snapshot"
