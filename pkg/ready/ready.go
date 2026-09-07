// Package ready exposes Traefik's readiness endpoint.
package ready

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
)

// Handler is both the ready static-configuration section and ready@internal's
// HTTP handler.
type Handler struct {
	EntryPoint    string `description:"EntryPoint" json:"entryPoint,omitempty" toml:"entryPoint,omitempty" yaml:"entryPoint,omitempty" export:"true"`
	ManualRouting bool   `description:"Manual routing" json:"manualRouting,omitempty" toml:"manualRouting,omitempty" yaml:"manualRouting,omitempty" export:"true"`

	ready       atomic.Bool
	terminating atomic.Bool

	tracker *Tracker
}

func (h *Handler) SetDefaults() {
	h.EntryPoint = "traefik"
}

func (h *Handler) SetTracker(tracker *Tracker) {
	h.tracker = tracker
}

func (h *Handler) SetReady() {
	h.ready.Store(true)
}

// WithContext changes readiness to false when Traefik's signal-bound context
// is cancelled.
func (h *Handler) WithContext(ctx context.Context) {
	go func() {
		<-ctx.Done()
		h.terminating.Store(true)
	}()
}

type status struct {
	Ready       bool `json:"ready"`
	Terminating bool `json:"terminating,omitempty"`

	PendingProviders []string `json:"pendingProviders,omitempty"`
	PendingApply     []string `json:"pendingApply,omitempty"`
}

func (h *Handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	terminating := h.terminating.Load()

	st := status{
		Ready:       h.ready.Load() && !terminating,
		Terminating: terminating,
	}

	if !st.Ready && h.tracker != nil {
		st.PendingProviders, st.PendingApply = h.tracker.Pending()
	}

	statusCode := http.StatusOK
	if !st.Ready {
		statusCode = http.StatusServiceUnavailable
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(statusCode)

	if req.Method == http.MethodHead {
		return
	}

	_ = json.NewEncoder(rw).Encode(st)
}
