package client

import (
	"fmt"
	"log/slog"

	spdxclient "github.com/kubescape/storage/pkg/generated/clientset/versioned"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// ResourceVersionFullSpec is the resource version that tells the Kubescape
// storage server to return the full spec (not the summary).
const ResourceVersionFullSpec = "full"

// Client wraps the Kubescape typed clientset.
type Client struct {
	Clientset spdxclient.Interface
}

// New creates a new Client. It tries in-cluster config first, then falls back
// to the given kubeconfig path.
func New(kubeconfig string) (*Client, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		slog.Info("in-cluster config not available, falling back to kubeconfig", "path", kubeconfig)
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("building kubeconfig: %w", err)
		}
	}

	cs, err := spdxclient.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating kubescape clientset: %w", err)
	}

	return &Client{Clientset: cs}, nil
}

// FullSpecListOptions returns ListOptions that request the full spec from the
// Kubescape storage server.
func FullSpecListOptions() metav1.ListOptions {
	return metav1.ListOptions{
		ResourceVersion: ResourceVersionFullSpec,
	}
}
