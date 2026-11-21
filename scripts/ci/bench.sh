#!/usr/bin/env bash
# Runs every benchmark briefly so they keep compiling and their own sanity
# checks keep passing. Allocation budgets are enforced by tests (testing.AllocsPerRun),
# which are deterministic; ns/op on shared CI runners is too noisy to gate.
set -euo pipefail

go test -run='^$' -bench=. -benchtime=100x -benchmem ./...

# The allocation tests skip themselves under -race, where sync.Pool drops
# items at random, and make test runs the edge with -race: run them here.
go test -count=1 -run='Alloc' ./...
