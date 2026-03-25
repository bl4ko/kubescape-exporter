package store

import (
	"sync"
	"sync/atomic"
)

// Store holds all vulnerability and compliance data in memory.
type Store struct {
	mu         sync.RWMutex
	images     map[string]*ImageData
	workloads  map[WorkloadKey]*WorkloadData
	compliance map[WorkloadKey]*ComplianceData

	vulnReady       atomic.Bool
	complianceReady atomic.Bool
}

// New creates a new empty Store.
func New() *Store {
	return &Store{
		images:     make(map[string]*ImageData),
		workloads:  make(map[WorkloadKey]*WorkloadData),
		compliance: make(map[WorkloadKey]*ComplianceData),
	}
}

// UpdateImage adds or updates image vulnerability data for the given manifest name.
func (s *Store) UpdateImage(manifestName string, data *ImageData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.images[manifestName] = data
}

// DeleteImage removes image vulnerability data for the given manifest name.
func (s *Store) DeleteImage(manifestName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.images, manifestName)
}

// UpdateWorkload adds or updates workload vulnerability data.
func (s *Store) UpdateWorkload(key WorkloadKey, data *WorkloadData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.workloads[key] = data
}

// DeleteWorkload removes workload vulnerability data.
func (s *Store) DeleteWorkload(key WorkloadKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.workloads, key)
}

// UpdateCompliance adds or updates compliance data for the given workload.
func (s *Store) UpdateCompliance(key WorkloadKey, data *ComplianceData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.compliance[key] = data
}

// DeleteCompliance removes compliance data for the given workload.
func (s *Store) DeleteCompliance(key WorkloadKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.compliance, key)
}

// GetAllImages returns a deep copy of all image vulnerability data.
func (s *Store) GetAllImages() map[string]*ImageData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]*ImageData, len(s.images))
	for k, v := range s.images {
		cp := *v
		cp.CVEs = make([]CVE, len(v.CVEs))
		copy(cp.CVEs, v.CVEs)
		out[k] = &cp
	}
	return out
}

// GetAllWorkloads returns a deep copy of all workload vulnerability data.
func (s *Store) GetAllWorkloads() map[WorkloadKey]*WorkloadData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[WorkloadKey]*WorkloadData, len(s.workloads))
	for k, v := range s.workloads {
		cp := *v
		cp.CVEs = make([]CVE, len(v.CVEs))
		copy(cp.CVEs, v.CVEs)
		out[k] = &cp
	}
	return out
}

// GetAllCompliance returns a deep copy of all compliance data.
func (s *Store) GetAllCompliance() map[WorkloadKey]*ComplianceData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[WorkloadKey]*ComplianceData, len(s.compliance))
	for k, v := range s.compliance {
		cp := *v
		cp.Controls = make([]ComplianceControl, len(v.Controls))
		copy(cp.Controls, v.Controls)
		out[k] = &cp
	}
	return out
}

// SetVulnReady marks the vulnerability data as ready.
func (s *Store) SetVulnReady() {
	s.vulnReady.Store(true)
}

// SetComplianceReady marks the compliance data as ready.
func (s *Store) SetComplianceReady() {
	s.complianceReady.Store(true)
}

// IsReady returns true when both vulnerability and compliance data have been loaded.
func (s *Store) IsReady() bool {
	return s.vulnReady.Load() && s.complianceReady.Load()
}
