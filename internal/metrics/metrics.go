package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	vulnCountDesc = prometheus.NewDesc(
		"kubescape_vulnerability_count",
		"Number of vulnerabilities per workload by severity, fixability and context",
		[]string{"namespace", "workload", "workload_kind", "container", "severity", "fixable", "context"},
		nil,
	)
	imageVulnCountDesc = prometheus.NewDesc(
		"kubescape_image_vulnerability_count",
		"Number of vulnerabilities per image by severity and fixability",
		[]string{"image", "image_tag", "severity", "fixable"},
		nil,
	)
	complianceCountDesc = prometheus.NewDesc(
		"kubescape_compliance_control_count",
		"Number of compliance controls per workload by severity and status",
		[]string{"namespace", "workload", "workload_kind", "severity", "status"},
		nil,
	)
	exporterInfoDesc = prometheus.NewDesc(
		"kubescape_exporter_info",
		"Information about the kubescape-exporter",
		[]string{"version"},
		nil,
	)
	watchedResourcesDesc = prometheus.NewDesc(
		"kubescape_exporter_watched_resources",
		"Number of watched resources by type",
		[]string{"resource_type"},
		nil,
	)
	vulnDetailDesc = prometheus.NewDesc(
		"kubescape_vulnerability_info",
		"Per-CVE detail for runtime-relevant vulnerabilities (value is CVSS score)",
		[]string{"namespace", "workload", "workload_kind", "container", "image_tag", "cve_id", "severity", "fix_state", "fix_version", "package_name", "package_version"},
		nil,
	)
	complianceDetailDesc = prometheus.NewDesc(
		"kubescape_compliance_control_info",
		"Per-control compliance detail (value 1=failed, 0=passed)",
		[]string{"namespace", "workload", "workload_kind", "control_id", "control_name", "severity", "status"},
		nil,
	)
)
