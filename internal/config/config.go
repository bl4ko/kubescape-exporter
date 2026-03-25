package config

// Config holds all configuration for the kubescape-exporter.
type Config struct {
	Port       int
	Kubeconfig string
	LogLevel   string
	Namespace  string
}
