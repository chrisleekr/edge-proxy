#!/usr/bin/env bash
# Builds and lints the admin UI, then runs its browser smoke tests against a
# real admin and Postgres, the edge's stream tests in Chromium, Firefox and
# WebKit, and the docs screenshot check. Needs Docker for testcontainers.
set -euo pipefail
cd "$(dirname "$0")/../.."

# Keep in step with node-version in .github/workflows/ci.yml.
node_version="26.12.1"

if ! command -v node >/dev/null; then
  # GitLab's Go image has no Node: install the pinned release, checked
  # against hashes recorded here rather than ones fetched alongside it.
  # .tar.gz because that image has no xz.
  case "$(uname -m)" in
    x86_64) arch=x64 sha=0fd1eb7770598f52a21995edf6ed35fc690400fa437c2386af329519e9143132 ;;
    aarch64) arch=arm64 sha=a6c01af459dd8972ab3fb08ee5da81244d26ba8c4944a62d5bbba8c597ae154f ;;
    *) echo "no pinned Node for $(uname -m)" >&2; exit 1 ;;
  esac
  tarball="node-v${node_version}-linux-${arch}.tar.gz"
  dir="$(mktemp -d)"
  curl -fsSL "https://nodejs.org/dist/v${node_version}/${tarball}" -o "${dir}/${tarball}"
  echo "${sha}  ${dir}/${tarball}" | sha256sum -c -
  tar -xzf "${dir}/${tarball}" -C "${dir}"
  export PATH="${dir}/node-v${node_version}-linux-${arch}/bin:${PATH}"
fi

(
  cd web/admin
  npm ci
  npx eslint .
  npm run build
  npx playwright install --with-deps chromium firefox webkit
)

UI_SMOKE=1 go test -count=1 -run '^TestUISmoke$' ./internal/admin
BROWSER_SMOKE=1 go test -count=1 -run '^TestBrowserStreams$' ./internal/edge
./scripts/ci/screenshots.sh
