#!/bin/sh
# Release images: builds the edge, admin and autopilot runner images for
# PLATFORMS (default amd64 and arm64) and pushes them as <prefix> (the proxy),
# <prefix>-admin and <prefix>-autopilot with every given tag.
# A leading v is dropped, so release-please's v1.2.3 becomes 1.2.3.
# Needs docker buildx with a multi-platform builder and a registry login.
# POSIX sh for the docker image GitLab uses.
set -eu
cd "$(dirname "$0")/../.."

if [ "$#" -lt 2 ]; then
  echo "usage: publish.sh <repository prefix> <tag> [tag ...]" >&2
  exit 64
fi
prefix=$1
shift
version=${1#v}
platforms=${PLATFORMS:-linux/amd64,linux/arm64}

for app in edge admin autopilot; do
  repo=${prefix}
  [ "${app}" != edge ] && repo=${prefix}-${app}
  tags=""
  for tag in "$@"; do
    tags="${tags} --tag ${repo}:${tag#v}"
  done
  # Word splitting of $tags is intended: tags never contain spaces.
  # shellcheck disable=SC2086
  docker buildx build --platform "${platforms}" --push \
    --label "org.opencontainers.image.version=${version}" \
    -f "build/${app}.Dockerfile" ${tags} .
done
