#!/usr/bin/env bash
# Comments and docs state their reason instead of citing design sections, ADRs
# or doc paths, which drift silently when sections move. Allowed: a section of
# a named standard (RFC, SP 800-63B), and Markdown links, which the strict
# docs build checks.
set -euo pipefail

found="$(git grep -nIE 'ADR-[0-9]|docs/design|design §|§[0-9]' -- ':!CLAUDE.md' ':!scripts/ci/citations.sh' |
  perl -ne '($t = $_) =~ s/^[^:]+:\d+://;
    $t =~ s/\[[^\]]*\]\([^)]*\)//g;
    $t =~ s/(RFC \d+|SP 800-63B(?: Rev 4)?) §[\d.]+//g;
    print if $t =~ /ADR-\d|docs\/design|design §|§\d/' || true)"

if [[ -n "${found}" ]]; then
  echo "state the reason instead of citing a design section, ADR or doc path:" >&2
  echo "${found}" >&2
  exit 1
fi
