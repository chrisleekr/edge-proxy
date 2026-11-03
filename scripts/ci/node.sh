# shellcheck shell=bash
# Sourced by ui.sh and autopilot.sh: puts the pinned Node on PATH when the
# machine has none. Keep in step with node-version in
# .github/workflows/ci.yml and the Node stage of build/admin.Dockerfile and
# build/autopilot.Dockerfile.
node_version="26.13.0"

if ! command -v node >/dev/null; then
  # GitLab's Go image has no Node: install the pinned release, checked
  # against hashes recorded here rather than ones fetched alongside it.
  # .tar.gz because that image has no xz.
  case "$(uname -m)" in
    x86_64) arch=x64 sha=5848553868b402d3fabb5b09270649977780a390f832155721025a08b5104455 ;;
    aarch64) arch=arm64 sha=439e9c438acdf6a6ffe47418da709153d66c4bed812e30a473faacb107dd2791 ;;
    *) echo "no pinned Node for $(uname -m)" >&2; exit 1 ;;
  esac
  tarball="node-v${node_version}-linux-${arch}.tar.gz"
  dir="$(mktemp -d)"
  curl -fsSL "https://nodejs.org/dist/v${node_version}/${tarball}" -o "${dir}/${tarball}"
  echo "${sha}  ${dir}/${tarball}" | sha256sum -c -
  tar -xzf "${dir}/${tarball}" -C "${dir}"
  export PATH="${dir}/node-v${node_version}-linux-${arch}/bin:${PATH}"
fi
