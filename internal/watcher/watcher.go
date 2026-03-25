package watcher

import (
	"context"
	"log/slog"
	"time"
)

const (
	initialBackoff = 1 * time.Second
	maxBackoff     = 60 * time.Second
)

// RunWithRetry runs fn in a loop with exponential backoff on errors.
// On success (fn returns nil), backoff resets to initialBackoff.
// Respects ctx cancellation.
func RunWithRetry(ctx context.Context, name string, fn func(ctx context.Context) error) {
	backoff := initialBackoff

	for {
		select {
		case <-ctx.Done():
			slog.Info("watcher stopping", "name", name, "reason", ctx.Err())
			return
		default:
		}

		slog.Info("watcher starting", "name", name)
		err := fn(ctx)
		if err == nil {
			backoff = initialBackoff
			continue
		}

		if ctx.Err() != nil {
			slog.Info("watcher stopping", "name", name, "reason", ctx.Err())
			return
		}

		slog.Error("watcher error, will retry", "name", name, "error", err, "backoff", backoff)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
