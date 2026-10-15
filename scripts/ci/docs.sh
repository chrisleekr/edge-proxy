#!/bin/sh
# Docs gate: the lockfile matches pyproject.toml, then a strict build, which
# fails on broken links, missing anchors and pages left out of the nav.
set -eu
cd "$(dirname "$0")/../.."

uv lock --check
uv run --locked --group docs mkdocs build --strict
