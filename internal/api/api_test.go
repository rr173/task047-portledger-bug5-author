package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"task047-portledger/internal/registry"
)

// Each test builds a fresh registry and handler so state never leaks between
// tests.

func doPost(t *testing.T, h http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func doGet(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// hostStateJSON decodes the host state response into a struct so the boolean
// "scanned" field is read as a Go bool, not a generic float64.
type hostStateJSON struct {
	Host          string  `json:"host"`
	Scanned       bool    `json:"scanned"`
	CurrentPorts  []int   `json:"current_ports"`
	LastScannedAt *string `json:"last_scanned_at"`
	ScanCount     int     `json:"scan_count"`
}

type scanResponseJSON struct {
	Host      string       `json:"host"`
	Sequence  int          `json:"sequence"`
	ScannedAt string       `json:"scanned_at"`
	Ports     []int        `json:"ports"`
	Diff      diffResponse `json:"diff"`
}

func TestHealthz(t *testing.T) {
	h := New(registry.New())
	rr := doGet(t, h, "/healthz")
	if rr.Code != 200 {
		t.Fatalf("status = %d", rr.Code)
	}
	if rr.Body.String() != "ok" {
		t.Errorf("body = %q want ok", rr.Body.String())
	}
}

func TestSubmitScanFlow(t *testing.T) {
	h := New(registry.New())
	rr := doPost(t, h, "/scans", `{"host":"API.Example.COM.","scanned_at":"2026-08-16T10:00:00+08:00","ports":[443,22,80]}`)
	if rr.Code != 200 {
		t.Fatalf("submit status=%d body=%s", rr.Code, rr.Body.String())
	}
	var sr scanResponseJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &sr); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if sr.Host != "api.example.com" {
		t.Errorf("host=%q", sr.Host)
	}
	if sr.Sequence != 1 {
		t.Errorf("sequence=%d", sr.Sequence)
	}
	if !reflect.DeepEqual(sr.Ports, []int{22, 80, 443}) {
		t.Errorf("ports=%v", sr.Ports)
	}
	if !reflect.DeepEqual(sr.Diff.Added, []int{22, 80, 443}) {
		t.Errorf("added=%v", sr.Diff.Added)
	}
	if len(sr.Diff.Removed) != 0 {
		t.Errorf("removed=%v", sr.Diff.Removed)
	}
}

func TestGetHostUnknown(t *testing.T) {
	h := New(registry.New())
	rr := doGet(t, h, "/hosts/never.example")
	if rr.Code != 200 {
		t.Fatalf("status=%d", rr.Code)
	}
	var st hostStateJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if st.Scanned {
		t.Errorf("scanned=%v want false", st.Scanned)
	}
	if st.ScanCount != 0 {
		t.Errorf("scan_count=%d want 0", st.ScanCount)
	}
	if st.LastScannedAt != nil {
		t.Errorf("last_scanned_at=%v want nil", st.LastScannedAt)
	}
	if !reflect.DeepEqual(st.CurrentPorts, []int{}) {
		t.Errorf("current_ports=%v want []", st.CurrentPorts)
	}
}

func TestGetHostAfterScan(t *testing.T) {
	h := New(registry.New())
	doPost(t, h, "/scans", `{"host":"h","scanned_at":"2026-08-16T10:00:00+08:00","ports":[22,80]}`)
	rr := doGet(t, h, "/hosts/h")
	if rr.Code != 200 {
		t.Fatalf("status=%d", rr.Code)
	}
	var st hostStateJSON
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !st.Scanned {
		t.Errorf("scanned=%v want true", st.Scanned)
	}
	if st.ScanCount != 1 {
		t.Errorf("scan_count=%d want 1", st.ScanCount)
	}
	if !reflect.DeepEqual(st.CurrentPorts, []int{22, 80}) {
		t.Errorf("current_ports=%v want [22 80]", st.CurrentPorts)
	}
	if st.LastScannedAt == nil || *st.LastScannedAt == "" {
		t.Errorf("last_scanned_at empty")
	}
}

func TestEmptyPortsIsScanned(t *testing.T) {
	h := New(registry.New())
	doPost(t, h, "/scans", `{"host":"h","scanned_at":"2026-08-16T10:00:00+08:00","ports":[22]}`)
	rr := doPost(t, h, "/scans", `{"host":"h","scanned_at":"2026-08-16T11:00:00+08:00","ports":[]}`)
	if rr.Code != 200 {
		t.Fatalf("empty submit status=%d body=%s", rr.Code, rr.Body.String())
	}
	g := doGet(t, h, "/hosts/h")
	var st hostStateJSON
	json.Unmarshal(g.Body.Bytes(), &st)
	if !st.Scanned {
		t.Errorf("scanned=false after empty scan")
	}
	if st.ScanCount != 2 {
		t.Errorf("scan_count=%d want 2", st.ScanCount)
	}
	if !reflect.DeepEqual(st.CurrentPorts, []int{}) {
		t.Errorf("current_ports=%v want []", st.CurrentPorts)
	}
}

func TestMissingPortsTreatedAsEmpty(t *testing.T) {
	h := New(registry.New())
	rr := doPost(t, h, "/scans", `{"host":"h","scanned_at":"2026-08-16T10:00:00+08:00"}`)
	if rr.Code != 200 {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var sr scanResponseJSON
	json.Unmarshal(rr.Body.Bytes(), &sr)
	if !reflect.DeepEqual(sr.Ports, []int{}) {
		t.Errorf("ports=%v want []", sr.Ports)
	}
}

func TestOutOfOrderConflict(t *testing.T) {
	h := New(registry.New())
	doPost(t, h, "/scans", `{"host":"h","scanned_at":"2026-08-16T10:00:00+08:00","ports":[22]}`)
	rr := doPost(t, h, "/scans", `{"host":"h","scanned_at":"2026-08-16T10:00:00+08:00","ports":[80]}`)
	if rr.Code != 409 {
		t.Errorf("equal ts status=%d want 409", rr.Code)
	}
	var e map[string]string
	json.Unmarshal(rr.Body.Bytes(), &e)
	if e["error"] != "out-of-order scan" {
		t.Errorf("error=%q", e["error"])
	}
	// Subsequent valid submit still works.
	rr = doPost(t, h, "/scans", `{"host":"h","scanned_at":"2026-08-16T11:00:00+08:00","ports":[80]}`)
	if rr.Code != 200 {
		t.Errorf("later ts status=%d", rr.Code)
	}
}

func TestInvalidPortRejected(t *testing.T) {
	h := New(registry.New())
	rr := doPost(t, h, "/scans", `{"host":"h","scanned_at":"2026-08-16T10:00:00+08:00","ports":[70000]}`)
	if rr.Code != 400 {
		t.Errorf("status=%d want 400", rr.Code)
	}
}

func TestInvalidTimestampRejected(t *testing.T) {
	h := New(registry.New())
	rr := doPost(t, h, "/scans", `{"host":"h","scanned_at":"not-a-time","ports":[22]}`)
	if rr.Code != 400 {
		t.Errorf("status=%d want 400", rr.Code)
	}
}

func TestMissingHostRejected(t *testing.T) {
	h := New(registry.New())
	rr := doPost(t, h, "/scans", `{"scanned_at":"2026-08-16T10:00:00+08:00","ports":[22]}`)
	if rr.Code != 400 {
		t.Errorf("status=%d want 400", rr.Code)
	}
}

func TestHostHistory(t *testing.T) {
	h := New(registry.New())
	doPost(t, h, "/scans", `{"host":"h","scanned_at":"2026-08-16T10:00:00+08:00","ports":[22]}`)
	doPost(t, h, "/scans", `{"host":"h","scanned_at":"2026-08-16T11:00:00+08:00","ports":[22,80]}`)
	rr := doGet(t, h, "/hosts/h/history")
	if rr.Code != 200 {
		t.Fatalf("status=%d", rr.Code)
	}
	var hist []map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &hist); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(hist) != 2 {
		t.Fatalf("len=%d want 2", len(hist))
	}
	if seq, _ := hist[0]["sequence"].(float64); seq != 1 {
		t.Errorf("hist[0].sequence=%v want 1", hist[0]["sequence"])
	}
	if seq, _ := hist[1]["sequence"].(float64); seq != 2 {
		t.Errorf("hist[1].sequence=%v want 2", hist[1]["sequence"])
	}
}

func TestHostHistoryUnknownEmpty(t *testing.T) {
	h := New(registry.New())
	rr := doGet(t, h, "/hosts/nope/history")
	if rr.Code != 200 {
		t.Fatalf("status=%d", rr.Code)
	}
	var hist []map[string]any
	json.Unmarshal(rr.Body.Bytes(), &hist)
	if len(hist) != 0 {
		t.Errorf("len=%d want 0", len(hist))
	}
}

func TestPortHostsReflectsLatest(t *testing.T) {
	h := New(registry.New())
	doPost(t, h, "/scans", `{"host":"a","scanned_at":"2026-08-16T10:00:00+08:00","ports":[22,80]}`)
	doPost(t, h, "/scans", `{"host":"b","scanned_at":"2026-08-16T10:00:00+08:00","ports":[80,443]}`)
	doPost(t, h, "/scans", `{"host":"a","scanned_at":"2026-08-16T11:00:00+08:00","ports":[22]}`)

	rr := doGet(t, h, "/ports/80/hosts")
	if rr.Code != 200 {
		t.Fatalf("status=%d", rr.Code)
	}
	var resp map[string][]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if !reflect.DeepEqual(resp["hosts"], []string{"b"}) {
		t.Errorf("hosts(80)=%v want [b]", resp["hosts"])
	}
}

func TestPortHostsInvalid(t *testing.T) {
	h := New(registry.New())
	for _, p := range []string{"/ports/abc/hosts", "/ports/0/hosts", "/ports/70000/hosts"} {
		rr := doGet(t, h, p)
		if rr.Code != 400 {
			t.Errorf("%s status=%d want 400", p, rr.Code)
		}
	}
}

func TestStats(t *testing.T) {
	h := New(registry.New())
	doPost(t, h, "/scans", `{"host":"a","scanned_at":"2026-08-16T10:00:00+08:00","ports":[22,80]}`)
	doPost(t, h, "/scans", `{"host":"b","scanned_at":"2026-08-16T10:00:00+08:00","ports":[80,443]}`)
	doPost(t, h, "/scans", `{"host":"c","scanned_at":"2026-08-16T10:00:00+08:00","ports":[80]}`)

	rr := doGet(t, h, "/stats")
	if rr.Code != 200 {
		t.Fatalf("status=%d", rr.Code)
	}
	var s map[string]any
	json.Unmarshal(rr.Body.Bytes(), &s)
	if hosts, _ := s["hosts"].(float64); hosts != 3 {
		t.Errorf("hosts=%v want 3", s["hosts"])
	}
	if scans, _ := s["scans"].(float64); scans != 3 {
		t.Errorf("scans=%v want 3", s["scans"])
	}
	top, _ := s["top_ports"].([]any)
	if len(top) == 0 {
		t.Fatalf("top_ports empty")
	}
	first, _ := top[0].(map[string]any)
	if port, _ := first["port"].(float64); port != 80 {
		t.Errorf("top[0].port=%v want 80", first["port"])
	}
	if n, _ := first["hosts"].(float64); n != 3 {
		t.Errorf("top[0].hosts=%v want 3", first["hosts"])
	}
}
