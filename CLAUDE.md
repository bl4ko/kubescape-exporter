# CLAUDE.md

## Overview

Prometheus exporter + REST API for Kubescape CRD data. Reads VulnerabilityManifest and WorkloadConfigurationScanSummary CRDs, exposes summary metrics with fixable dimension and per-CVE REST API.

## Build & Run

- Build: `make build`
- Test: `make test`
- Docker: `make docker-build`
- Local dev: `go run ./cmd/kubescape-exporter --kubeconfig ~/.kube/config --port 8080`

## Architecture

- Watchers use raw Watch/List (not informers) with `ResourceVersion: "fullSpec"` for Kubescape aggregated API
- In-memory store with sync.RWMutex
- Custom Prometheus collector recomputes metrics on each scrape
- Single HTTP server on :8080 serves /metrics, /api/v1/*, /healthz, /readyz

## Conventions

- Go standard library only (except prometheus client_golang and k8s client-go)
- log/slog for structured logging
- No external HTTP frameworks
