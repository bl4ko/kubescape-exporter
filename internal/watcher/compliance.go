package watcher

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	v1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxclient "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"

	"github.com/bl4ko/kubescape-exporter/internal/store"
)

// ComplianceWatcher watches WorkloadConfigurationScanSummary CRDs and populates the store.
type ComplianceWatcher struct {
	client spdxclient.SpdxV1beta1Interface
	store  *store.Store
}

// NewComplianceWatcher creates a new ComplianceWatcher.
func NewComplianceWatcher(client spdxclient.SpdxV1beta1Interface, s *store.Store) *ComplianceWatcher {
	return &ComplianceWatcher{
		client: client,
		store:  s,
	}
}

// Start begins watching WorkloadConfigurationScanSummaries with automatic reconnection.
func (w *ComplianceWatcher) Start(ctx context.Context) {
	RunWithRetry(ctx, "compliance", w.run)
}

func (w *ComplianceWatcher) run(ctx context.Context) error {
	listOpts := metav1.ListOptions{
		ResourceVersion: "fullSpec",
	}

	list, err := w.client.WorkloadConfigurationScanSummaries("").List(ctx, listOpts)
	if err != nil {
		return fmt.Errorf("listing workload configuration scan summaries: %w", err)
	}

	slog.Info("listed workload configuration scan summaries", "count", len(list.Items))

	for i := range list.Items {
		w.processSummary(&list.Items[i])
	}
	w.store.SetComplianceReady()

	watchOpts := metav1.ListOptions{
		ResourceVersion: list.ResourceVersion,
	}

	watcher, err := w.client.WorkloadConfigurationScanSummaries("").Watch(ctx, watchOpts)
	if err != nil {
		return fmt.Errorf("starting compliance watch: %w", err)
	}
	defer watcher.Stop()

	slog.Info("watching workload configuration scan summaries", "resourceVersion", list.ResourceVersion)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return fmt.Errorf("compliance watch channel closed")
			}
			if err := w.handleEvent(event); err != nil {
				return err
			}
		}
	}
}

func (w *ComplianceWatcher) handleEvent(event watch.Event) error {
	switch event.Type {
	case watch.Added, watch.Modified:
		summary, ok := event.Object.(*v1beta1.WorkloadConfigurationScanSummary)
		if !ok {
			slog.Warn("unexpected object type in compliance watch event")
			return nil
		}
		w.processSummary(summary)

	case watch.Deleted:
		summary, ok := event.Object.(*v1beta1.WorkloadConfigurationScanSummary)
		if !ok {
			slog.Warn("unexpected object type in compliance watch delete event")
			return nil
		}
		w.deleteSummary(summary)

	case watch.Error:
		return fmt.Errorf("compliance watch error event: %v", event.Object)
	}
	return nil
}

func (w *ComplianceWatcher) processSummary(summary *v1beta1.WorkloadConfigurationScanSummary) {
	labels := summary.GetLabels()
	key := store.WorkloadKey{
		Namespace:    labels[labelWorkloadNS],
		WorkloadKind: labels[labelWorkloadKind],
		WorkloadName: labels[labelWorkloadName],
	}

	controls := parseComplianceControls(summary.Spec.Controls)

	w.store.UpdateCompliance(key, &store.ComplianceData{
		Key:       key,
		Controls:  controls,
		UpdatedAt: time.Now(),
	})

	slog.Debug("updated compliance data",
		"name", summary.GetName(),
		"namespace", key.Namespace,
		"workload", key.WorkloadName,
		"controls", len(controls))
}

func (w *ComplianceWatcher) deleteSummary(summary *v1beta1.WorkloadConfigurationScanSummary) {
	labels := summary.GetLabels()
	key := store.WorkloadKey{
		Namespace:    labels[labelWorkloadNS],
		WorkloadKind: labels[labelWorkloadKind],
		WorkloadName: labels[labelWorkloadName],
	}

	w.store.DeleteCompliance(key)
	slog.Debug("deleted compliance data",
		"name", summary.GetName(),
		"namespace", key.Namespace,
		"workload", key.WorkloadName)
}

func parseComplianceControls(controls map[string]v1beta1.ScannedControlSummary) []store.ComplianceControl {
	if controls == nil {
		return []store.ComplianceControl{}
	}

	result := make([]store.ComplianceControl, 0, len(controls))
	for id, ctrl := range controls {
		result = append(result, store.ComplianceControl{
			ID:       id,
			Name:     ctrl.ControlID,
			Severity: strings.ToLower(ctrl.Severity.Severity),
			Status:   strings.ToLower(ctrl.Status.Status),
		})
	}
	return result
}
