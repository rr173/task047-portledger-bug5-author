package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"task047-portledger/internal/registry"
)

func TestProbeTrailingJSONIsRejected(t *testing.T) {
	body := `{"host":"h","scanned_at":"2026-08-16T10:00:00Z","ports":[80]} {"host":"h"}`
	rr := httptest.NewRecorder()
	New(registry.New()).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/scans", strings.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", rr.Code, rr.Body.String())
	}
}
