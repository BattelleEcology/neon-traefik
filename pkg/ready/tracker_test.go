package ready

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTrackerLifecycle(t *testing.T) {
	var latched atomic.Bool

	tracker := NewTracker(
		[]string{
			"internal",
			"kubernetes",
		},
		func() {
			latched.Store(true)
		},
	)
	tracker.InitialConfiguration("internal", true)
	assert.False(t, tracker.Ready())

	tracker.ConfigurationApplied([]string{"internal"})
	assert.False(t, tracker.Ready())

	tracker.InitialConfiguration("kubernetes", true)
	assert.False(
		t,
		tracker.Ready(),
		"received configuration must not satisfy readiness before apply",
	)

	tracker.ConfigurationApplied(
		[]string{
			"internal",
			"kubernetes",
		},
	)

	assert.True(t, tracker.Ready())
	assert.True(t, latched.Load())
}

func TestTrackerNonEmptyInitialCannotReadyBeforeApply(t *testing.T) {
	tracker := NewTracker([]string{"kubernetes"}, nil)

	tracker.InitialConfiguration("kubernetes", true)
	assert.False(t, tracker.Ready())

	tracker.ConfigurationApplied([]string{"kubernetes"})
	assert.True(t, tracker.Ready())
}

func TestTrackerEmptyInitialConfiguration(t *testing.T) {
	tracker := NewTracker([]string{"kubernetes"}, nil)
	tracker.InitialConfiguration("kubernetes", false)
	assert.True(t, tracker.Ready())
}

func TestTrackerForeignNameCannotSatisfyReadiness(t *testing.T) {
	tracker := NewTracker(
		[]string{
			"internal",
			"kubernetes",
		},
		nil,
	)
	tracker.InitialConfiguration("internal", true)

	tracker.ConfigurationApplied(
		[]string{
			"internal",
			"myresolver.acme",
		},
	)
	tracker.InitialConfiguration("myresolver.acme", true)
	assert.False(t, tracker.Ready())
	tracker.InitialConfiguration("kubernetes", true)

	tracker.ConfigurationApplied(
		[]string{
			"internal",
			"kubernetes",
			"myresolver.acme",
		},
	)

	assert.True(t, tracker.Ready())
}

func TestTrackerInitialClassificationIsImmutable(t *testing.T) {
	tracker := NewTracker([]string{"kubernetes"}, nil)
	tracker.InitialConfiguration("kubernetes", true)
	tracker.InitialConfiguration("kubernetes", false)
	assert.False(t, tracker.Ready())
	tracker.ConfigurationApplied([]string{"kubernetes"})
	assert.True(t, tracker.Ready())
}

func TestTrackerEmptyExpectedSetNeverReady(t *testing.T) {
	tracker := NewTracker(nil, nil)
	tracker.InitialConfiguration("kubernetes", false)
	tracker.ConfigurationApplied([]string{"kubernetes"})
	assert.False(t, tracker.Ready())
}

func TestTrackerPending(t *testing.T) {
	tracker := NewTracker(
		[]string{
			"internal",
			"kubernetes",
		},
		nil,
	)

	tracker.InitialConfiguration("internal", true)
	pendingProviders, pendingApply := tracker.Pending()

	assert.Equal(t, []string{"kubernetes"}, pendingProviders)
	assert.Equal(t, []string{"internal"}, pendingApply)
}
