package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bl4ko/kubescape-exporter/internal/api"
	"github.com/bl4ko/kubescape-exporter/internal/client"
	"github.com/bl4ko/kubescape-exporter/internal/config"
	"github.com/bl4ko/kubescape-exporter/internal/metrics"
	"github.com/bl4ko/kubescape-exporter/internal/store"
	"github.com/bl4ko/kubescape-exporter/internal/watcher"
	"github.com/prometheus/client_golang/prometheus"
)

func main() {
	cfg := config.Config{}
	fs := flag.NewFlagSet("kubescape-exporter", flag.ExitOnError)
	fs.IntVar(&cfg.Port, "port", 9090, "HTTP server port")
	fs.StringVar(&cfg.Kubeconfig, "kubeconfig", "", "path to kubeconfig file (defaults to in-cluster)")
	fs.StringVar(&cfg.LogLevel, "log-level", "info", "log level (debug, info, warn, error)")
	fs.StringVar(&cfg.Namespace, "namespace", "kubescape", "namespace where VulnerabilityManifests live")
	fs.Parse(os.Args[1:])

	setupLogging(cfg.LogLevel)

	slog.Info("starting kubescape-exporter",
		"port", cfg.Port,
		"namespace", cfg.Namespace,
		"logLevel", cfg.LogLevel,
	)

	k8sClient, err := client.New(cfg.Kubeconfig)
	if err != nil {
		slog.Error("failed to create kubernetes client", "error", err)
		os.Exit(1)
	}

	s := store.New()

	spdxClient := k8sClient.Clientset.SpdxV1beta1()

	vulnWatcher := watcher.NewVulnerabilityWatcher(spdxClient, s, cfg.Namespace)
	compWatcher := watcher.NewComplianceWatcher(spdxClient, s)

	collector := metrics.NewCollector(s, "dev")
	prometheus.MustRegister(collector)

	srv := api.NewServer(s, cfg.Port)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go vulnWatcher.Start(ctx)
	go compWatcher.Start(ctx)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		slog.Info("received shutdown signal", "signal", sig)
	case err := <-errCh:
		slog.Error("server error", "error", err)
	}

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("failed to shutdown HTTP server", "error", err)
	}

	slog.Info("kubescape-exporter stopped")
}

func setupLogging(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(handler))
}
