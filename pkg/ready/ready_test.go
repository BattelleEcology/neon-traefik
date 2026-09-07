package ready

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandlerNotReadyWithPendingBody(t *testing.T) {
	handler := &Handler{}
	handler.SetDefaults()

	tracker := NewTracker([]string{"kubernetes"}, handler.SetReady)
	handler.SetTracker(tracker)

	rec := httptest.NewRecorder()

	handler.ServeHTTP(
		rec,
		httptest.NewRequest(
			http.MethodGet,
			"/ready",
			nil,
		),
	)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Contains(
		t,
		rec.Body.String(),
		`"pendingProviders":["kubernetes"]`,
	)
}

func TestHandlerReady(t *testing.T) {
	handler := &Handler{}
	handler.SetDefaults()
	handler.SetReady()

	rec := httptest.NewRecorder()

	handler.ServeHTTP(
		rec,
		httptest.NewRequest(
			http.MethodGet,
			"/ready",
			nil,
		),
	)

	require.Equal(t, http.StatusOK, rec.Code)

	assert.Contains(
		t,
		rec.Body.String(),
		`"ready":true`,
	)
}

func TestHandlerTerminationOverridesReady(t *testing.T) {
	handler := &Handler{}
	handler.SetDefaults()
	handler.SetReady()

	ctx, cancel := context.WithCancel(context.Background())
	handler.WithContext(ctx)
	cancel()
	require.Eventually(
		t,
		func() bool {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(
				rec,
				httptest.NewRequest(
					http.MethodHead,
					"/ready",
					nil,
				),
			)

			return rec.Code == http.StatusServiceUnavailable && rec.Body.Len() == 0
		},
		time.Second,
		10*time.Millisecond,
	)
}
