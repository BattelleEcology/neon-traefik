package ready

import (
	"sort"
	"sync"
)

type providerState struct {
	initialReceived bool
	requiresApply   bool
	initialApplied  bool
}

// Tracker tracks the initial configuration lifecycle.
//
// Readiness is latched: once every expected provider has completed its initial
// lifecycle, later configuration changes no longer affect readiness.
type Tracker struct {
	mu sync.RWMutex

	providers map[string]providerState

	ready   bool
	onReady func()
}

// NewTracker creates a readiness tracker.
//
// An empty expected-provider set intentionally never becomes ready. In normal
// operation this is defensive only because ready@internal makes the internal
// provider an expected provider.
func NewTracker(expectedProviders []string, onReady func()) *Tracker {
	providers := make(map[string]providerState, len(expectedProviders))

	for _, name := range expectedProviders {
		if name == "" {
			continue
		}

		providers[name] = providerState{}
	}

	return &Tracker{
		providers: providers,
		onReady:   onReady,
	}
}

// InitialConfiguration records the first configuration emitted by an expected
// provider.
//
// Receipt and requiresApply are deliberately one atomic transition. This
// prevents the final provider from satisfying readiness before Traefik knows
// whether its first snapshot must still pass through applyConfigurations.
func (t *Tracker) InitialConfiguration(name string, requiresApply bool) {
	var becameReady bool

	t.mu.Lock()

	if !t.ready {
		state, expected := t.providers[name]
		if expected && !state.initialReceived {
			state.initialReceived = true
			state.requiresApply = requiresApply

			t.providers[name] = state
			becameReady = t.refreshLocked()
		}
	}

	t.mu.Unlock()

	if becameReady && t.onReady != nil {
		t.onReady()
	}
}

// ConfigurationApplied records that a merged configuration containing these
// provider names has completed the entire ConfigurationWatcher listener loop.
func (t *Tracker) ConfigurationApplied(providerNames []string) {
	var becameReady bool

	t.mu.Lock()

	if !t.ready {
		for _, name := range providerNames {
			state, expected := t.providers[name]
			if !expected {
				continue
			}

			if !state.initialReceived || !state.requiresApply || state.initialApplied {
				continue
			}

			state.initialApplied = true
			t.providers[name] = state
		}

		becameReady = t.refreshLocked()
	}

	t.mu.Unlock()

	if becameReady && t.onReady != nil {
		t.onReady()
	}
}

func (t *Tracker) Ready() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	return t.ready
}

func (t *Tracker) Pending() (
	pendingProviders []string,
	pendingApply []string,
) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for name, state := range t.providers {
		switch {
		case !state.initialReceived:
			pendingProviders = append(pendingProviders, name)

		case state.requiresApply && !state.initialApplied:
			pendingApply = append(pendingApply, name)
		}
	}

	sort.Strings(pendingProviders)
	sort.Strings(pendingApply)

	return pendingProviders, pendingApply
}

// refreshLocked returns true only for the transition into ready.
// The caller must hold t.mu.
func (t *Tracker) refreshLocked() bool {
	if t.ready || len(t.providers) == 0 {
		return false
	}

	for _, state := range t.providers {
		if !state.initialReceived {
			return false
		}

		if state.requiresApply && !state.initialApplied {
			return false
		}
	}

	t.ready = true

	return true
}
