#!/usr/bin/env bash
# release-please reads Conventional Commit subjects; one it can't parse is left
# out of the version bump and the changelog. Checks PR_TITLE (the squash
# commit) and every commit in BASE..HEAD.
set -euo pipefail

pattern='^(feat|fix|perf|revert|refactor|docs|chore|style|test|build|ci)(\([a-z0-9._/-]+\))?!?: .+'
bad="$({ printf '%s\n' "${PR_TITLE}"; git log --no-merges --format=%s "${BASE}..${HEAD}"; } | grep -Ev "${pattern}" || true)"
if [[ -n "${bad}" ]]; then
  echo "not a Conventional Commit subject:" >&2
  echo "${bad}" >&2
  exit 1
fi
