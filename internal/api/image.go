package api

import (
	"net/http"

	"github.com/bl4ko/kubescape-exporter/internal/store"
)

// ImageSummaryResponse is the JSON representation of an image with aggregated counts.
type ImageSummaryResponse struct {
	Name      string          `json:"name"`
	Tag       string          `json:"tag"`
	Counts    []SeverityCount `json:"counts"`
	TotalCVEs int             `json:"totalCVEs"`
}

// ImageDetailResponse is the JSON representation of an image with per-CVE details.
type ImageDetailResponse struct {
	Name string        `json:"name"`
	Tag  string        `json:"tag"`
	CVEs []CVEResponse `json:"cves"`
}

func imageSeverityCounts(cves []store.CVE) []SeverityCount {
	type countKey struct {
		Severity string
		Fixable  bool
	}
	counts := make(map[countKey]int)
	for _, cve := range cves {
		ck := countKey{
			Severity: cve.Severity,
			Fixable:  cve.FixState == "fixed",
		}
		counts[ck]++
	}

	result := make([]SeverityCount, 0, len(counts))
	for ck, count := range counts {
		result = append(result, SeverityCount{
			Severity: ck.Severity,
			Fixable:  ck.Fixable,
			Count:    count,
		})
	}
	return result
}

// listImages handles GET /api/v1/images.
func (s *Server) listImages(w http.ResponseWriter, _ *http.Request) {
	images := s.store.GetAllImages()

	results := make([]ImageSummaryResponse, 0, len(images))
	for _, img := range images {
		results = append(results, ImageSummaryResponse{
			Name:      img.Name,
			Tag:       img.Tag,
			Counts:    imageSeverityCounts(img.CVEs),
			TotalCVEs: len(img.CVEs),
		})
	}

	writeJSON(w, http.StatusOK, results)
}

// getImage handles GET /api/v1/images/{name}.
func (s *Server) getImage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "image name is required"})
		return
	}

	images := s.store.GetAllImages()

	img, ok := images[name]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "image not found"})
		return
	}

	cves := make([]CVEResponse, 0, len(img.CVEs))
	for _, cve := range img.CVEs {
		cves = append(cves, cveToResponse(cve))
	}

	writeJSON(w, http.StatusOK, ImageDetailResponse{
		Name: img.Name,
		Tag:  img.Tag,
		CVEs: cves,
	})
}
