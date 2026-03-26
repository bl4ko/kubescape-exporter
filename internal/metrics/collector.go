package metrics

import (
	"strconv"

	"github.com/bl4ko/kubescape-exporter/internal/store"
	"github.com/prometheus/client_golang/prometheus"
)

// Collector implements prometheus.Collector and exposes Kubescape metrics
// by reading from the in-memory store on each scrape.
type Collector struct {
	store   *store.Store
	version string
}

// NewCollector creates a new Collector that reads from the given store.
func NewCollector(s *store.Store, version string) *Collector {
	return &Collector{
		store:   s,
		version: version,
	}
}

// Describe sends all metric descriptors to the channel.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- vulnCountDesc
	ch <- imageVulnCountDesc
	ch <- complianceCountDesc
	ch <- exporterInfoDesc
	ch <- watchedResourcesDesc
	ch <- vulnDetailDesc
	ch <- complianceDetailDesc
}

// Collect gathers metrics from the store and sends them to the channel.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.MustNewConstMetric(exporterInfoDesc, prometheus.GaugeValue, 1, c.version)

	images := c.store.GetAllImages()
	seenImages := make(map[string]bool)
	for _, img := range images {
		imageKey := img.Name + "\x00" + img.Tag
		if seenImages[imageKey] {
			continue
		}
		seenImages[imageKey] = true
		c.collectImageMetrics(ch, img)
	}

	workloads := c.store.GetAllWorkloads()
	for _, wl := range workloads {
		c.collectWorkloadMetrics(ch, wl)
	}

	compliance := c.store.GetAllCompliance()
	for _, comp := range compliance {
		c.collectComplianceMetrics(ch, comp)
	}

	ch <- prometheus.MustNewConstMetric(watchedResourcesDesc, prometheus.GaugeValue,
		float64(len(images)), "images")
	ch <- prometheus.MustNewConstMetric(watchedResourcesDesc, prometheus.GaugeValue,
		float64(len(workloads)), "workloads")
	ch <- prometheus.MustNewConstMetric(watchedResourcesDesc, prometheus.GaugeValue,
		float64(len(compliance)), "compliance")
}

func (c *Collector) collectImageMetrics(ch chan<- prometheus.Metric, img *store.ImageData) {
	type key struct {
		severity string
		fixable  bool
	}
	counts := make(map[key]int)
	for _, cve := range img.CVEs {
		k := key{
			severity: cve.Severity,
			fixable:  cve.FixState == "fixed",
		}
		counts[k]++
	}

	for k, count := range counts {
		ch <- prometheus.MustNewConstMetric(imageVulnCountDesc, prometheus.GaugeValue,
			float64(count),
			img.Name,
			img.Tag,
			k.severity,
			strconv.FormatBool(k.fixable),
		)
	}
}

func (c *Collector) collectWorkloadMetrics(ch chan<- prometheus.Metric, wl *store.WorkloadData) {
	type key struct {
		severity string
		fixable  bool
	}
	counts := make(map[key]int)
	for _, cve := range wl.CVEs {
		k := key{
			severity: cve.Severity,
			fixable:  cve.FixState == "fixed",
		}
		counts[k]++
	}

	for k, count := range counts {
		ch <- prometheus.MustNewConstMetric(vulnCountDesc, prometheus.GaugeValue,
			float64(count),
			wl.Key.Namespace,
			wl.Key.WorkloadName,
			wl.Key.WorkloadKind,
			wl.Key.Container,
			k.severity,
			strconv.FormatBool(k.fixable),
			"relevant",
		)
	}

	type vulnKey struct {
		cveID, pkgName, pkgVersion string
	}
	seenVulns := make(map[vulnKey]bool)
	for _, cve := range wl.CVEs {
		vk := vulnKey{cve.ID, cve.PackageName, cve.PackageVersion}
		if seenVulns[vk] {
			continue
		}
		seenVulns[vk] = true
		fixVer := ""
		if len(cve.FixVersions) > 0 {
			fixVer = cve.FixVersions[0]
		}
		ch <- prometheus.MustNewConstMetric(vulnDetailDesc, prometheus.GaugeValue,
			cve.CVSSScore,
			wl.Key.Namespace,
			wl.Key.WorkloadName,
			wl.Key.WorkloadKind,
			wl.Key.Container,
			wl.ImageTag,
			cve.ID,
			cve.Severity,
			cve.FixState,
			fixVer,
			cve.PackageName,
			cve.PackageVersion,
		)
	}
}

func (c *Collector) collectComplianceMetrics(ch chan<- prometheus.Metric, comp *store.ComplianceData) {
	type key struct {
		severity string
		status   string
	}
	counts := make(map[key]int)
	for _, ctrl := range comp.Controls {
		k := key{
			severity: ctrl.Severity,
			status:   ctrl.Status,
		}
		counts[k]++
	}

	for k, count := range counts {
		ch <- prometheus.MustNewConstMetric(complianceCountDesc, prometheus.GaugeValue,
			float64(count),
			comp.Key.Namespace,
			comp.Key.WorkloadName,
			comp.Key.WorkloadKind,
			k.severity,
			k.status,
		)
	}

	type ctrlKey struct {
		id, workload string
	}
	seenCtrls := make(map[ctrlKey]bool)
	for _, ctrl := range comp.Controls {
		ck := ctrlKey{ctrl.ID, comp.Key.WorkloadName}
		if seenCtrls[ck] {
			continue
		}
		seenCtrls[ck] = true
		val := float64(0)
		if ctrl.Status == "failed" {
			val = 1
		}
		ch <- prometheus.MustNewConstMetric(complianceDetailDesc, prometheus.GaugeValue,
			val,
			comp.Key.Namespace,
			comp.Key.WorkloadName,
			comp.Key.WorkloadKind,
			ctrl.ID,
			ctrl.Name,
			ctrl.Severity,
			ctrl.Status,
		)
	}
}
