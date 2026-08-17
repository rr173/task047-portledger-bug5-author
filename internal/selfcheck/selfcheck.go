// Package selfcheck runs an end-to-end verification of the port ledger. It is
// invoked by the --smoke-test flag and exits the process on completion.
//
// Each scenario uses a fresh registry (and, where relevant, a fresh httptest
// server) so global state never leaks across checks.
package selfcheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"time"

	"task047-portledger/internal/api"
	"task047-portledger/internal/registry"
)

// Run exercises the port ledger across isolated scenarios, returning nil if
// every behavior matches the specification.
func Run() error {
	scenarios := []struct {
		name string
		fn   func() error
	}{
		{"首次扫描 diff.added 为全集", scenarioFirstScan},
		{"第二次扫描 diff 反映增减", scenarioSecondScanDiff},
		{"空端口扫描区分于未扫描", scenarioEmptyIsScanned},
		{"乱序扫描拒绝且不污染数据", scenarioOutOfOrder},
		{"端口规范化去重升序", scenarioPortCanonical},
		{"host 规范化与跨形式合并", scenarioHostNormalize},
		{"最新端口集驱动端口查询与统计", scenarioLatestDriven},
		{"HTTP 层 JSON 形状与状态码", scenarioHTTPLayer},
		{"host 当前状态语义", scenarioHostState},
		{"历史拷贝隔离", scenarioHistoryCopy},
	}
	for _, sc := range scenarios {
		if err := sc.fn(); err != nil {
			return fmt.Errorf("%s: %w", sc.name, err)
		}
	}
	return nil
}

func mustTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func scenarioFirstScan() error {
	r := registry.New()
	res, err := r.Submit("h", mustTime("2026-08-16T10:00:00+08:00"), []int{443, 22, 80})
	if err != nil {
		return fmt.Errorf("submit: %w", err)
	}
	if res.Sequence != 1 {
		return fmt.Errorf("sequence=%d want 1", res.Sequence)
	}
	if !reflect.DeepEqual(res.Ports, []int{22, 80, 443}) {
		return fmt.Errorf("ports=%v", res.Ports)
	}
	if !reflect.DeepEqual(res.Diff.Added, []int{22, 80, 443}) {
		return fmt.Errorf("added=%v want full set", res.Diff.Added)
	}
	if len(res.Diff.Removed) != 0 {
		return fmt.Errorf("removed=%v want empty", res.Diff.Removed)
	}
	return nil
}

func scenarioSecondScanDiff() error {
	r := registry.New()
	r.Submit("h", mustTime("2026-08-16T10:00:00+08:00"), []int{22, 80, 443})
	res, err := r.Submit("h", mustTime("2026-08-16T11:00:00+08:00"), []int{80, 8080})
	if err != nil {
		return fmt.Errorf("submit: %w", err)
	}
	if !reflect.DeepEqual(res.Diff.Added, []int{8080}) {
		return fmt.Errorf("added=%v want [8080]", res.Diff.Added)
	}
	if !reflect.DeepEqual(res.Diff.Removed, []int{22, 443}) {
		return fmt.Errorf("removed=%v want [22 443]", res.Diff.Removed)
	}
	if !reflect.DeepEqual(res.Ports, []int{80, 8080}) {
		return fmt.Errorf("ports=%v want [80 8080]", res.Ports)
	}
	return nil
}

func scenarioEmptyIsScanned() error {
	r := registry.New()
	r.Submit("h", mustTime("2026-08-16T10:00:00+08:00"), []int{22, 80})
	if _, err := r.Submit("h", mustTime("2026-08-16T11:00:00+08:00"), []int{}); err != nil {
		return fmt.Errorf("empty submit: %w", err)
	}
	st := r.State("h")
	if !st.Scanned {
		return fmt.Errorf("scanned=false want true (empty != never)")
	}
	if st.ScanCount != 2 {
		return fmt.Errorf("scan_count=%d want 2", st.ScanCount)
	}
	if len(st.CurrentPorts) != 0 {
		return fmt.Errorf("current_ports=%v want empty", st.CurrentPorts)
	}
	// unknown host must differ from empty-scanned.
	unk := r.State("never")
	if unk.Scanned {
		return fmt.Errorf("unknown host scanned=true")
	}
	if unk.LastScannedAt != nil {
		return fmt.Errorf("unknown host last_scanned_at non-nil")
	}
	return nil
}

func scenarioOutOfOrder() error {
	r := registry.New()
	r.Submit("h", mustTime("2026-08-16T10:00:00+08:00"), []int{22})
	if _, err := r.Submit("h", mustTime("2026-08-16T10:00:00+08:00"), []int{80}); err == nil {
		return fmt.Errorf("equal ts accepted (want out-of-order)")
	}
	if _, err := r.Submit("h", mustTime("2026-08-16T09:00:00+08:00"), []int{80}); err == nil {
		return fmt.Errorf("earlier ts accepted (want out-of-order)")
	}
	if _, err := r.Submit("h", mustTime("2026-08-16T11:00:00+08:00"), []int{80}); err != nil {
		return fmt.Errorf("later ts rejected: %w", err)
	}
	if r.State("h").ScanCount != 2 {
		return fmt.Errorf("scan_count=%d want 2 (out-of-order not stored)", r.State("h").ScanCount)
	}
	return nil
}

func scenarioPortCanonical() error {
	r := registry.New()
	res, err := r.Submit("h", mustTime("2026-08-16T10:00:00+08:00"), []int{443, 22, 22, 80, 443})
	if err != nil {
		return fmt.Errorf("submit: %w", err)
	}
	if !reflect.DeepEqual(res.Ports, []int{22, 80, 443}) {
		return fmt.Errorf("ports=%v want [22 80 443] (dedup+sort)", res.Ports)
	}
	if _, err := r.Submit("h2", mustTime("2026-08-16T10:00:00+08:00"), []int{0}); err == nil {
		return fmt.Errorf("port 0 accepted (want invalid)")
	}
	if _, err := r.Submit("h3", mustTime("2026-08-16T10:00:00+08:00"), []int{65536}); err == nil {
		return fmt.Errorf("port 65536 accepted (want invalid)")
	}
	return nil
}

func scenarioHostNormalize() error {
	r := registry.New()
	r.Submit("API.Example.COM.", mustTime("2026-08-16T10:00:00+08:00"), []int{22})
	res, err := r.Submit("  host.example.com  ", mustTime("2026-08-16T11:00:00+08:00"), []int{22, 80})
	if err != nil {
		return fmt.Errorf("submit: %w", err)
	}
	if res.Host != "host.example.com" {
		return fmt.Errorf("host=%q want host.example.com", res.Host)
	}
	// two distinct hosts
	st1 := r.State("api.example.com")
	st2 := r.State("host.example.com")
	if st1.ScanCount != 1 {
		return fmt.Errorf("api scan_count=%d want 1", st1.ScanCount)
	}
	if st2.ScanCount != 1 {
		return fmt.Errorf("host scan_count=%d want 1", st2.ScanCount)
	}
	// trailing-dot form must merge with bare form
	r.Submit("host.example.com.", mustTime("2026-08-16T12:00:00+08:00"), []int{80})
	if r.State("host.example.com").ScanCount != 2 {
		return fmt.Errorf("trailing-dot not merged: scan_count=%d want 2", r.State("host.example.com").ScanCount)
	}
	return nil
}

func scenarioLatestDriven() error {
	r := registry.New()
	r.Submit("a", mustTime("2026-08-16T10:00:00+08:00"), []int{22, 80})
	r.Submit("b", mustTime("2026-08-16T10:00:00+08:00"), []int{80, 443})
	r.Submit("c", mustTime("2026-08-16T10:00:00+08:00"), []int{80})
	// a drops 80 in scan 2
	r.Submit("a", mustTime("2026-08-16T11:00:00+08:00"), []int{22})

	hosts, ok := r.HostsForPort(80)
	if !ok {
		return fmt.Errorf("HostsForPort(80) ok=false")
	}
	if !reflect.DeepEqual(hosts, []string{"b", "c"}) {
		return fmt.Errorf("hosts(80)=%v want [b c] (a dropped 80)", hosts)
	}
	st, top := r.Snapshot(5)
	if st.Hosts != 3 {
		return fmt.Errorf("hosts=%d want 3", st.Hosts)
	}
	if st.Scans != 4 {
		return fmt.Errorf("scans=%d want 4", st.Scans)
	}
	if len(top) == 0 || top[0].Port != 80 || top[0].Hosts != 2 {
		return fmt.Errorf("top[0]=%+v want port=80 hosts=2", top)
	}
	return nil
}

func scenarioHTTPLayer() error {
	// Fresh registry + fresh httptest server for this HTTP scenario.
	reg := registry.New()
	mux := api.New(reg)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// POST first scan.
	body := []byte(`{"host":"API.Example.COM.","scanned_at":"2026-08-16T10:00:00+08:00","ports":[443,22,80]}`)
	resp, err := http.Post(srv.URL+"/scans", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("post status=%d want 200", resp.StatusCode)
	}
	var sr struct {
		Host     string `json:"host"`
		Sequence int    `json:"sequence"`
		Ports    []int  `json:"ports"`
		Diff     struct {
			Added   []int `json:"added"`
			Removed []int `json:"removed"`
		} `json:"diff"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	if sr.Host != "api.example.com" {
		return fmt.Errorf("http host=%q", sr.Host)
	}
	if !reflect.DeepEqual(sr.Ports, []int{22, 80, 443}) {
		return fmt.Errorf("http ports=%v", sr.Ports)
	}
	if !reflect.DeepEqual(sr.Diff.Added, []int{22, 80, 443}) {
		return fmt.Errorf("http added=%v", sr.Diff.Added)
	}

	// GET unknown host: scanned=false as a JSON bool, not a number.
	gresp, err := http.Get(srv.URL + "/hosts/never.example")
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	defer gresp.Body.Close()
	var st struct {
		Scanned      bool  `json:"scanned"`
		ScanCount    int   `json:"scan_count"`
		CurrentPorts []int `json:"current_ports"`
	}
	if err := json.NewDecoder(gresp.Body).Decode(&st); err != nil {
		return fmt.Errorf("decode state: %w", err)
	}
	if st.Scanned {
		return fmt.Errorf("unknown host scanned=true")
	}
	if st.ScanCount != 0 {
		return fmt.Errorf("unknown host scan_count=%d", st.ScanCount)
	}
	if !reflect.DeepEqual(st.CurrentPorts, []int{}) {
		return fmt.Errorf("unknown host current_ports=%v", st.CurrentPorts)
	}

	// out-of-order over HTTP -> 409
	oobody := []byte(`{"host":"h","scanned_at":"2026-08-16T10:00:00+08:00","ports":[22]}`)
	http.Post(srv.URL+"/scans", "application/json", bytes.NewReader(oobody))
	dup := []byte(`{"host":"h","scanned_at":"2026-08-16T10:00:00+08:00","ports":[80]}`)
	dresp, err := http.Post(srv.URL+"/scans", "application/json", bytes.NewReader(dup))
	if err != nil {
		return fmt.Errorf("dup post: %w", err)
	}
	defer dresp.Body.Close()
	if dresp.StatusCode != 409 {
		return fmt.Errorf("dup status=%d want 409", dresp.StatusCode)
	}

	// invalid port over HTTP -> 400
	bad := []byte(`{"host":"h","scanned_at":"2026-08-16T11:00:00+08:00","ports":[70000]}`)
	bresp, err := http.Post(srv.URL+"/scans", "application/json", bytes.NewReader(bad))
	if err != nil {
		return fmt.Errorf("bad post: %w", err)
	}
	defer bresp.Body.Close()
	if bresp.StatusCode != 400 {
		return fmt.Errorf("bad port status=%d want 400", bresp.StatusCode)
	}
	return nil
}

func scenarioHostState() error {
	reg := registry.New()
	mux := api.New(reg)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	http.Post(srv.URL+"/scans", "application/json",
		bytes.NewReader([]byte(`{"host":"h","scanned_at":"2026-08-16T10:00:00+08:00","ports":[22,80]}`)))
	// empty second scan
	http.Post(srv.URL+"/scans", "application/json",
		bytes.NewReader([]byte(`{"host":"h","scanned_at":"2026-08-16T11:00:00+08:00","ports":[]}`)))

	gresp, err := http.Get(srv.URL + "/hosts/h")
	if err != nil {
		return fmt.Errorf("get: %w", err)
	}
	defer gresp.Body.Close()
	var st struct {
		Scanned       bool    `json:"scanned"`
		ScanCount     int     `json:"scan_count"`
		CurrentPorts  []int   `json:"current_ports"`
		LastScannedAt *string `json:"last_scanned_at"`
	}
	json.NewDecoder(gresp.Body).Decode(&st)
	if !st.Scanned {
		return fmt.Errorf("scanned=false want true")
	}
	if st.ScanCount != 2 {
		return fmt.Errorf("scan_count=%d want 2", st.ScanCount)
	}
	if len(st.CurrentPorts) != 0 {
		return fmt.Errorf("current_ports=%v want empty", st.CurrentPorts)
	}
	if st.LastScannedAt == nil || *st.LastScannedAt == "" {
		return fmt.Errorf("last_scanned_at empty")
	}
	return nil
}

func scenarioHistoryCopy() error {
	r := registry.New()
	r.Submit("h", mustTime("2026-08-16T10:00:00+08:00"), []int{22, 80})
	hist := r.History("h")
	if len(hist) != 1 {
		return fmt.Errorf("len=%d", len(hist))
	}
	hist[0].Ports[0] = 9999
	if got := r.History("h")[0].Ports[0]; got != 22 {
		return fmt.Errorf("internal state mutated: %d", got)
	}
	return nil
}
