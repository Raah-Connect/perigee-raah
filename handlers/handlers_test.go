package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbes(t *testing.T) {
	rec := httptest.NewRecorder()
	LivenessProbe(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("liveness probe = %d, want %d", rec.Code, http.StatusOK)
	}

	rec = httptest.NewRecorder()
	ReadinessProbe(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	want := http.StatusServiceUnavailable
	if adminToken != "" {
		want = http.StatusOK
	}
	if rec.Code != want {
		t.Errorf("readiness probe = %d, want %d", rec.Code, want)
	}
}
