#!/usr/bin/env bash
# Runs fuzz targets briefly. Seed corpora in testdata/fuzz run in every
# `go test`; this adds new random inputs so parser and matcher regressions on
# the trust boundary fail CI. Go fuzzes one target per invocation.
# MRs set BASE to the commit they branched from and fuzz only targets whose
# package dependencies changed. A run without BASE (scheduled pipelines, local
# `make fuzz`) fuzzes everything.
set -euo pipefail

fuzztime="${FUZZTIME:-20s}"
base="${BASE:-}"
# GitLab passes all zeros as the base of a new branch.
[[ "${base}" =~ ^0+$ ]] && base=""
# A force-push leaves the previous head out of the clone; fuzz everything then.
[[ -n "${base}" ]] && ! git cat-file -e "${base}^{commit}" 2>/dev/null && base=""

changed=""
if [[ -n "${base}" ]]; then
  files="$(git diff --no-renames --name-only "${base}" HEAD)"
  if grep -Eq '^go\.(mod|sum)$' <<<"${files}"; then
    base=""
  else
    mod="$(go list -m)"
    while IFS= read -r f; do
      d="$(dirname "${f}")"
      if [[ "${f}" == *.go && "/${f}" != */testdata/* ]]; then
        [[ "${d}" == "." ]] && changed+="${mod}"$'\n' || changed+="${mod}/${d}"$'\n'
        continue
      fi
      # Other files reach a package as testdata or go:embed, both somewhere below
      # the package directory, so every ancestor directory counts as changed.
      while [[ "${d}" != "." ]]; do
        changed+="${mod}/${d}"$'\n'
        d="$(dirname "${d}")"
      done
      changed+="${mod}"$'\n'
    done <<<"${files}"
  fi
fi

targets=()
for pkg in $(go list ./...); do
  # Decided before `go test -list`, so skipped packages are not compiled.
  if [[ -n "${base}" ]]; then
    # Captured first: grep -q closing the pipe early would fail go list under
    # pipefail. A package rebuilt for a test is listed as "path [pkg.test]".
    deps="$(go list -deps -test -f '{{.ImportPath}}' "${pkg}" | sed 's/ .*//')"
    grep -qxFf <(echo "${changed}") <<<"${deps}" || continue
  fi
  for target in $(go test -list '^Fuzz' "${pkg}" | grep '^Fuzz' || true); do
    targets+=("${pkg} ${target}")
  done
done

if [[ -n "${base}" ]]; then
  echo "fuzzing scoped to changes since ${base}: ${#targets[@]} targets"
else
  echo "fuzzing all targets: ${#targets[@]} found"
fi
if [[ -z "${base}" && "${#targets[@]}" == 0 ]]; then
  echo "no fuzz targets yet"
fi
for t in "${targets[@]+"${targets[@]}"}"; do
  read -r pkg target <<<"${t}"
  echo "fuzz ${pkg} ${target} for ${fuzztime}"
  go test -run='^$' -fuzz="^${target}\$" -fuzztime="${fuzztime}" "${pkg}"
done
