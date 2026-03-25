package api

import (
	"net/http"
)

// healthz handles GET /healthz and always returns 200 OK.
func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyz handles GET /readyz. Returns 200 if the store has completed
// its initial data load, 503 otherwise.
func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	if s.store.IsReady() {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
}
