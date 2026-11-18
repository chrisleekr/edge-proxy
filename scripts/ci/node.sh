# shellcheck shell=bash
# Sourced by ui.sh and autopilot.sh: puts the pinned Node on PATH when the
# machine has none. Keep in step with node-version in
# .github/workflows/ci.yml and the Node stage of build/admin.Dockerfile and
# build/autopilot.Dockerfile.
node_version="26.13.1"

if ! command -v node >/dev/null; then
  # GitLab's Go image has no Node: install the pinned release, checked
  # against hashes recorded here rather than ones fetched alongside it.
  # .tar.gz because that image has no xz.
  case "$(uname -m)" in
    x86_64) arch=x64 sha=518674de2b621728a5e4486f5fb3b7d2900bb3cc4aa97969edaa463db99f9778 ;;
    aarch64) arch=arm64 sha=80a330b35415382878df18d41afbd106ea89bfb3be0087d6608e289a14c5cc7d ;;
    *) echo "no pinned Node for $(uname -m)" >&2; exit 1 ;;
  esac
  tarball="node-v${node_version}-linux-${arch}.tar.gz"
  dir="$(mktemp -d)"
  curl -fsSL "https://nodejs.org/dist/v${node_version}/${tarball}" -o "${dir}/${tarball}"
  echo "${sha}  ${dir}/${tarball}" | sha256sum -c -
  tar -xzf "${dir}/${tarball}" -C "${dir}"
  export PATH="${dir}/node-v${node_version}-linux-${arch}/bin:${PATH}"
fi
