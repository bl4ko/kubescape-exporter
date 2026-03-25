package store

import "time"

// CVE represents a single vulnerability finding.
type CVE struct {
	ID             string
	Severity       string // Critical, High, Medium, Low, Negligible, Unknown
	Description    string
	FixState       string // fixed, not-fixed, unknown, wont-fix
	FixVersions    []string
	CVSSScore      float64
	PackageName    string
	PackageVersion string
	PackageType    string // go-module, deb, rpm, etc.
}

// ImageData holds vulnerability data for a container image.
type ImageData struct {
	Name      string // manifest name, e.g. "docker-io-grafana-mimir"
	Tag       string // full image ref, e.g. "docker.io/grafana/mimir:3.0.4"
	CVEs      []CVE
	UpdatedAt time.Time
}

// WorkloadKey uniquely identifies a workload container.
type WorkloadKey struct {
	Namespace    string
	WorkloadKind string
	WorkloadName string
	Container    string
}

// WorkloadData holds vulnerability data for a specific workload container.
type WorkloadData struct {
	Key       WorkloadKey
	ImageTag  string
	CVEs      []CVE
	UpdatedAt time.Time
}

// ComplianceControl represents a single compliance control check result.
type ComplianceControl struct {
	ID       string
	Name     string
	Severity string
	Status   string // passed, failed
}

// ComplianceData holds compliance results for a specific workload.
type ComplianceData struct {
	Key       WorkloadKey
	Controls  []ComplianceControl
	UpdatedAt time.Time
}

// SeverityCounts holds counts grouped by severity and fixable status.
type SeverityCounts struct {
	Severity string
	Fixable  bool
	Count    int
}
