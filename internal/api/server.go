package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/bl4ko/kubescape-exporter/internal/store"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server is the HTTP server exposing metrics and REST API endpoints.
type Server struct {
	store  *store.Store
	mux    *http.ServeMux
	server *http.Server
}

// NewServer creates a new Server with all routes registered.
func NewServer(s *store.Store, port int) *Server {
	mux := http.NewServeMux()

	srv := &Server{
		store: s,
		mux:   mux,
		server: &http.Server{
			Addr:         fmt.Sprintf(":%d", port),
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}

	mux.Handle("GET /metrics", promhttp.Handler())

	mux.HandleFunc("GET /api/v1/vulnerabilities", srv.listVulnerabilities)
	mux.HandleFunc("GET /api/v1/vulnerabilities/summary", srv.vulnerabilitySummary)

	mux.HandleFunc("GET /api/v1/images", srv.listImages)
	mux.HandleFunc("GET /api/v1/images/{name}", srv.getImage)

	mux.HandleFunc("GET /api/v1/compliance", srv.listCompliance)
	mux.HandleFunc("GET /api/v1/compliance/summary", srv.complianceSummary)

	mux.HandleFunc("GET /healthz", srv.healthz)
	mux.HandleFunc("GET /readyz", srv.readyz)

	return srv
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe() error {
	slog.Info("starting HTTP server", "addr", s.server.Addr)
	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	slog.Info("shutting down HTTP server")
	return s.server.Shutdown(ctx)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}
