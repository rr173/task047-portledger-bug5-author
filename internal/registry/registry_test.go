package registry

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func mustTime(t string) time.Time {
	tt, err := time.Parse(time.RFC3339, t)
	if err != nil {
		panic(err)
	}
	return tt
}

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"API.Example.COM.", "api.example.com", true},
		{"  Host.Example.com  ", "host.example.com", true},
		{"lower.example.com", "lower.example.com", true},
		{"", "", false},
		{"   ", "", false},
		{".", "", false},
		{"..", "", false}, // single trailing dot stripped -> "."
		{"a.example.com..", "a.example.com.", true}, // only one trailing dot stripped
	}
	for _, c := range cases {
		got, ok := NormalizeHost(c.in)
		if ok != c.ok {
			t.Errorf("NormalizeHost(%q) ok=%v want %v", c.in, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("NormalizeHost(%q) = %q want %q", c.in, got, c.want)
		}
	}
}

func TestCanonicalPorts(t *testing.T) {
	cases := []struct {
		name string
		in   []int
		want []int
		ok   bool
	}{
		{"unordered dups", []int{443, 22, 80, 22, 443}, []int{22, 80, 443}, true},
		{"empty", []int{}, []int{}, true},
		{"single", []int{80}, []int{80}, true},
		{"zero", []int{0}, nil, false},
		{"negative", []int{-1}, nil, false},
		{"too big", []int{65536}, nil, false},
		{"valid max", []int{65535}, []int{65535}, true},
		{"mix valid invalid", []int{80, 70000}, nil, false},
	}
	for _, c := range cases {
		got, ok := CanonicalPorts(c.in)
		if ok != c.ok {
			t.Errorf("%s: ok=%v want %v", c.name, ok, c.ok)
			continue
		}
		if ok && !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestSubmitFirstScan(t *testing.T) {
	r := New()
	res, err := r.Submit("API.Example.COM.", mustTime("2026-08-16T10:00:00+08:00"), []int{443, 22, 80})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.Host != "api.example.com" {
		t.Errorf("host = %q", res.Host)
	}
	if res.Sequence != 1 {
		t.Errorf("sequence = %d want 1", res.Sequence)
	}
	if !reflect.DeepEqual(res.Ports, []int{22, 80, 443}) {
		t.Errorf("ports = %v", res.Ports)
	}
	if !reflect.DeepEqual(res.Diff.Added, []int{22, 80, 443}) {
		t.Errorf("diff.added = %v", res.Diff.Added)
	}
	if len(res.Diff.Removed) != 0 {
		t.Errorf("diff.removed = %v want empty", res.Diff.Removed)
	}
}

func TestSubmitDiffSecondScan(t *testing.T) {
	r := New()
	r.Submit("h", mustTime("2026-08-16T10:00:00+08:00"), []int{22, 80, 443})
	res, err := r.Submit("h", mustTime("2026-08-16T11:00:00+08:00"), []int{80, 8080})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.Sequence != 2 {
		t.Errorf("sequence = %d want 2", res.Sequence)
	}
	if !reflect.DeepEqual(res.Diff.Added, []int{8080}) {
		t.Errorf("added = %v want [8080]", res.Diff.Added)
	}
	if !reflect.DeepEqual(res.Diff.Removed, []int{22, 443}) {
		t.Errorf("removed = %v want [22 443]", res.Diff.Removed)
	}
}

func TestSubmitEmptyPortsIsScan(t *testing.T) {
	r := New()
	r.Submit("h", mustTime("2026-08-16T10:00:00+08:00"), []int{22, 80})
	_, err := r.Submit("h", mustTime("2026-08-16T11:00:00+08:00"), []int{})
	if err != nil {
		t.Fatalf("submit empty: %v", err)
	}
	st := r.State("h")
	if !st.Scanned {
		t.Errorf("scanned = false want true")
	}
	if st.ScanCount != 2 {
		t.Errorf("scan_count = %d want 2", st.ScanCount)
	}
	if len(st.CurrentPorts) != 0 {
		t.Errorf("current_ports = %v want empty", st.CurrentPorts)
	}
	if st.LastScannedAt == nil {
		t.Errorf("last_scanned_at = nil")
	}
	// diff vs previous should show all previous ports removed.
	res, _ := r.Submit("h", mustTime("2026-08-16T12:00:00+08:00"), []int{22})
	if !reflect.DeepEqual(res.Diff.Added, []int{22}) {
		t.Errorf("after-empty added = %v want [22]", res.Diff.Added)
	}
}

func TestSubmitOutOfOrder(t *testing.T) {
	r := New()
	r.Submit("h", mustTime("2026-08-16T10:00:00+08:00"), []int{22})
	// Equal timestamp -> out of order.
	_, err := r.Submit("h", mustTime("2026-08-16T10:00:00+08:00"), []int{80})
	if !errors.Is(err, ErrOutOfOrder) {
		t.Errorf("equal ts: err=%v want ErrOutOfOrder", err)
	}
	// Earlier timestamp -> out of order.
	_, err = r.Submit("h", mustTime("2026-08-16T09:00:00+08:00"), []int{80})
	if !errors.Is(err, ErrOutOfOrder) {
		t.Errorf("earlier ts: err=%v want ErrOutOfOrder", err)
	}
	// Later timestamp -> ok.
	_, err = r.Submit("h", mustTime("2026-08-16T11:00:00+08:00"), []int{80})
	if err != nil {
		t.Errorf("later ts: err=%v", err)
	}
	if r.State("h").ScanCount != 2 {
		t.Errorf("scan_count = %d want 2 (out-of-order not stored)", r.State("h").ScanCount)
	}
}

func TestSubmitInvalid(t *testing.T) {
	r := New()
	_, err := r.Submit("", mustTime("2026-08-16T10:00:00+08:00"), []int{22})
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("empty host: err=%v want ErrInvalid", err)
	}
	_, err = r.Submit("h", mustTime("2026-08-16T10:00:00+08:00"), []int{70000})
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("bad port: err=%v want ErrInvalid", err)
	}
	_, err = r.Submit("h", time.Time{}, []int{22})
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("zero time: err=%v want ErrInvalid", err)
	}
}

func TestStateUnknownHost(t *testing.T) {
	r := New()
	st := r.State("never.scanned.example")
	if st.Scanned {
		t.Errorf("unknown host scanned = true")
	}
	if st.ScanCount != 0 {
		t.Errorf("unknown host scan_count = %d", st.ScanCount)
	}
	if len(st.CurrentPorts) != 0 {
		t.Errorf("unknown host current_ports = %v", st.CurrentPorts)
	}
	if st.LastScannedAt != nil {
		t.Errorf("unknown host last_scanned_at = non-nil")
	}
}

func TestHistoryCopyIsolation(t *testing.T) {
	r := New()
	r.Submit("h", mustTime("2026-08-16T10:00:00+08:00"), []int{22, 80})
	hist := r.History("h")
	if len(hist) != 1 {
		t.Fatalf("len = %d", len(hist))
	}
	hist[0].Ports[0] = 9999 // mutate returned copy
	if got := r.History("h")[0].Ports[0]; got != 22 {
		t.Errorf("internal state mutated via returned slice: %d", got)
	}
}

func TestHostsForPortReflectsLatest(t *testing.T) {
	r := New()
	r.Submit("a", mustTime("2026-08-16T10:00:00+08:00"), []int{22, 80})
	r.Submit("b", mustTime("2026-08-16T10:00:00+08:00"), []int{80, 443})
	// a drops 80 in its second scan.
	r.Submit("a", mustTime("2026-08-16T11:00:00+08:00"), []int{22})

	hosts, ok := r.HostsForPort(80)
	if !ok {
		t.Fatalf("HostsForPort ok=false")
	}
	if !reflect.DeepEqual(hosts, []string{"b"}) {
		t.Errorf("HostsForPort(80) = %v want [b]", hosts)
	}
	hosts, _ = r.HostsForPort(22)
	if !reflect.DeepEqual(hosts, []string{"a"}) {
		t.Errorf("HostsForPort(22) = %v want [a]", hosts)
	}
	if _, ok := r.HostsForPort(0); ok {
		t.Errorf("HostsForPort(0) should be invalid")
	}
	if _, ok := r.HostsForPort(70000); ok {
		t.Errorf("HostsForPort(70000) should be invalid")
	}
}

func TestSnapshotTopPorts(t *testing.T) {
	r := New()
	r.Submit("a", mustTime("2026-08-16T10:00:00+08:00"), []int{22, 80})
	r.Submit("b", mustTime("2026-08-16T10:00:00+08:00"), []int{80, 443})
	r.Submit("c", mustTime("2026-08-16T10:00:00+08:00"), []int{80, 8080})

	st, top := r.Snapshot(5)
	if st.Hosts != 3 {
		t.Errorf("hosts = %d want 3", st.Hosts)
	}
	if st.Scans != 3 {
		t.Errorf("scans = %d want 3", st.Scans)
	}
	// port 80 on 3 hosts; 22/443/8080 on 1 each -> 80 first, then ascending.
	wantTop := []PortCount{{Port: 80, Hosts: 3}, {Port: 22, Hosts: 1}, {Port: 443, Hosts: 1}, {Port: 8080, Hosts: 1}}
	if !reflect.DeepEqual(top, wantTop) {
		t.Errorf("top = %v want %v", top, wantTop)
	}
	// topN=2 truncates.
	_, top2 := r.Snapshot(2)
	if len(top2) != 2 || top2[0].Port != 80 || top2[1].Port != 22 {
		t.Errorf("top2 = %v", top2)
	}
}

func TestSnapshotDedupWithinScan(t *testing.T) {
	r := New()
	r.Submit("a", mustTime("2026-08-16T10:00:00+08:00"), []int{80, 80, 80})
	_, top := r.Snapshot(5)
	if len(top) != 1 || top[0].Port != 80 || top[0].Hosts != 1 {
		t.Errorf("dedup within scan failed: %v", top)
	}
}

func TestHostNormalizationDedup(t *testing.T) {
	// Same host submitted under different casing/trailing-dot forms must
	// merge into one history.
	r := New()
	r.Submit("Host.Example.com.", mustTime("2026-08-16T10:00:00+08:00"), []int{22})
	res, err := r.Submit("HOST.example.com", mustTime("2026-08-16T11:00:00+08:00"), []int{22, 80})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.Sequence != 2 {
		t.Errorf("sequence = %d want 2 (hosts should merge)", res.Sequence)
	}
	st := r.State("host.example.com")
	if st.ScanCount != 2 {
		t.Errorf("scan_count = %d want 2", st.ScanCount)
	}
}
