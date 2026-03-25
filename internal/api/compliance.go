package api

import (
	"net/http"
	"strings"
)

// ComplianceResponse is the JSON representation of a single compliance check result.
type ComplianceResponse struct {
	Namespace    string `json:"namespace"`
	Workload     string `json:"workload"`
	WorkloadKind string `json:"workloadKind"`
	ControlID    string `json:"controlId"`
	ControlName  string `json:"controlName"`
	Severity     string `json:"severity"`
	Status       string `json:"status"`
}

// ComplianceSummaryResponse is the JSON representation of aggregated compliance counts.
type ComplianceSummaryResponse struct {
	Namespace    string                    `json:"namespace"`
	Workload     string                    `json:"workload"`
	WorkloadKind string                    `json:"workloadKind"`
	Counts       []ComplianceSeverityCount `json:"counts"`
}

// ComplianceSeverityCount holds a count of compliance results for a given severity and status.
type ComplianceSeverityCount struct {
	Severity string `json:"severity"`
	Status   string `json:"status"`
	Count    int    `json:"count"`
}

// listCompliance handles GET /api/v1/compliance.
// Query params: namespace, workload, severity, status (passed/failed).
func (s *Server) listCompliance(w http.ResponseWriter, r *http.Request) {
	qNamespace := r.URL.Query().Get("namespace")
	qWorkload := r.URL.Query().Get("workload")
	qSeverity := strings.ToLower(r.URL.Query().Get("severity"))
	qStatus := strings.ToLower(r.URL.Query().Get("status"))

	compliance := s.store.GetAllCompliance()
	results := make([]ComplianceResponse, 0)

	for _, cd := range compliance {
		if qNamespace != "" && cd.Key.Namespace != qNamespace {
			continue
		}
		if qWorkload != "" && cd.Key.WorkloadName != qWorkload {
			continue
		}

		for _, ctrl := range cd.Controls {
			if qSeverity != "" && strings.ToLower(ctrl.Severity) != qSeverity {
				continue
			}
			if qStatus != "" && strings.ToLower(ctrl.Status) != qStatus {
				continue
			}

			results = append(results, ComplianceResponse{
				Namespace:    cd.Key.Namespace,
				Workload:     cd.Key.WorkloadName,
				WorkloadKind: cd.Key.WorkloadKind,
				ControlID:    ctrl.ID,
				ControlName:  ctrl.Name,
				Severity:     ctrl.Severity,
				Status:       ctrl.Status,
			})
		}
	}

	writeJSON(w, http.StatusOK, results)
}

// complianceSummary handles GET /api/v1/compliance/summary.
// Query params: namespace.
func (s *Server) complianceSummary(w http.ResponseWriter, r *http.Request) {
	qNamespace := r.URL.Query().Get("namespace")
	compliance := s.store.GetAllCompliance()

	type groupKey struct {
		Namespace    string
		Workload     string
		WorkloadKind string
	}
	type countKey struct {
		Severity string
		Status   string
	}

	grouped := make(map[groupKey]map[countKey]int)

	for _, cd := range compliance {
		if qNamespace != "" && cd.Key.Namespace != qNamespace {
			continue
		}

		gk := groupKey{
			Namespace:    cd.Key.Namespace,
			Workload:     cd.Key.WorkloadName,
			WorkloadKind: cd.Key.WorkloadKind,
		}
		if grouped[gk] == nil {
			grouped[gk] = make(map[countKey]int)
		}

		for _, ctrl := range cd.Controls {
			ck := countKey{
				Severity: ctrl.Severity,
				Status:   ctrl.Status,
			}
			grouped[gk][ck]++
		}
	}

	results := make([]ComplianceSummaryResponse, 0, len(grouped))
	for gk, counts := range grouped {
		var severityCounts []ComplianceSeverityCount
		for ck, count := range counts {
			severityCounts = append(severityCounts, ComplianceSeverityCount{
				Severity: ck.Severity,
				Status:   ck.Status,
				Count:    count,
			})
		}
		results = append(results, ComplianceSummaryResponse{
			Namespace:    gk.Namespace,
			Workload:     gk.Workload,
			WorkloadKind: gk.WorkloadKind,
			Counts:       severityCounts,
		})
	}

	writeJSON(w, http.StatusOK, results)
}
