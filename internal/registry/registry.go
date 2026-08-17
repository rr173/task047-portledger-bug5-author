// Package registry implements the in-memory host port inventory and change
// detection engine.
//
// A scan record describes the open ports a scanner observed on a host at a
// given instant. The registry keeps, per normalized host, a strictly
// time-ordered history of scans and exposes the change (added/removed ports)
// of each new scan relative to the immediately preceding one.
//
// The registry is safe for concurrent use.
package registry

import (
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
)

// Errors returned by the registry. Callers may distinguish a malformed scan
// (ErrInvalid) from an out-of-order one (ErrOutOfOrder).
var (
	ErrInvalid    = errors.New("registry: invalid scan")
	ErrOutOfOrder = errors.New("registry: out-of-order scan")
)

// Scan is a single observation of a host's open ports at a point in time.
type Scan struct {
	Sequence  int       // 1-based index within the host's history
	Host      string    // normalized host
	ScannedAt time.Time // scan completion time
	Ports     []int     // canonical: ascending, deduplicated
}

// Diff is the port-set change of a scan relative to the previous one.
type Diff struct {
	Added   []int // ports present now but absent before
	Removed []int // ports present before but absent now
}

// SubmitResult is returned when a scan is accepted.
type SubmitResult struct {
	Host      string
	Sequence  int
	ScannedAt time.Time
	Ports     []int
	Diff      Diff
}

// HostState is the current view of a host.
type HostState struct {
	Host          string
	Scanned       bool
	CurrentPorts  []int
	LastScannedAt *time.Time
	ScanCount     int
}

// Stats is a global snapshot.
type Stats struct {
	Hosts int
	Scans int
}

// Registry is the in-memory port inventory.
type Registry struct {
	mu    sync.Mutex
	hosts map[string][]Scan // host -> scans ordered by ScannedAt ascending
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{hosts: make(map[string][]Scan)}
}

// NormalizeHost canonicalizes a host identifier: it trims surrounding white
// space, lowercases, and strips a single trailing dot (the FQDN marker). It
// returns false for empty input, or when the result contains no character
// other than dots (e.g. "." or "..").
func NormalizeHost(raw string) (string, bool) {
	h := strings.TrimSpace(raw)
	if h == "" {
		return "", false
	}
	h = strings.ToLower(h)
	h = strings.TrimSuffix(h, ".")
	if strings.Trim(h, ".") == "" {
		return "", false
	}
	return h, true
}

// CanonicalPorts validates and canonicalizes a port list: every element must
// be in [1,65535]. The result is ascending and deduplicated. Returns false if
// any element is out of range.
func CanonicalPorts(ports []int) ([]int, bool) {
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return nil, false
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Ints(out)
	return out, true
}

// Submit accepts a new scan for a host. host is the raw identifier; scannedAt
// is the scan completion time; ports are the observed open ports (raw, possibly
// unordered/duplicated). It enforces strictly-increasing scannedAt per host.
// On success it returns the canonicalized scan and its diff. On a malformed
// scan it returns ErrInvalid; on an out-of-order timestamp it returns
// ErrOutOfOrder.
func (r *Registry) Submit(host string, scannedAt time.Time, ports []int) (SubmitResult, error) {
	h, ok := NormalizeHost(host)
	if !ok {
		return SubmitResult{}, ErrInvalid
	}
	cp, ok := CanonicalPorts(ports)
	if !ok {
		return SubmitResult{}, ErrInvalid
	}
	if scannedAt.IsZero() {
		return SubmitResult{}, ErrInvalid
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	history := r.hosts[h]
	if len(history) > 0 {
		last := history[len(history)-1].ScannedAt
		if !scannedAt.After(last) {
			return SubmitResult{}, ErrOutOfOrder
		}
	}

	var diff Diff
	if len(history) == 0 {
		diff = Diff{Added: append([]int(nil), cp...), Removed: []int{}}
	} else {
		prev := history[len(history)-1].Ports
		diff = computeDiff(prev, cp)
	}

	seq := len(history) + 1
	scan := Scan{
		Sequence:  seq,
		Host:      h,
		ScannedAt: scannedAt,
		Ports:     append([]int(nil), cp...),
	}
	r.hosts[h] = append(history, scan)

	return SubmitResult{
		Host:      h,
		Sequence:  seq,
		ScannedAt: scannedAt,
		Ports:     append([]int(nil), cp...),
		Diff:      diff,
	}, nil
}

// computeDiff returns the added/removed port sets of next relative to prev.
// Both inputs are assumed canonical (ascending, deduplicated).
func computeDiff(prev, next []int) Diff {
	added, removed := []int{}, []int{}
	i, j := 0, 0
	for i < len(prev) && j < len(next) {
		if prev[i] < next[j] {
			removed = append(removed, prev[i])
			i++
		} else if prev[i] > next[j] {
			added = append(added, next[j])
			j++
		} else {
			i++
			j++
		}
	}
	for ; i < len(prev); i++ {
		removed = append(removed, prev[i])
	}
	for ; j < len(next); j++ {
		added = append(added, next[j])
	}
	return Diff{Added: added, Removed: removed}
}

// State returns the current view of a host. It never returns an error; an
// unknown host yields a zero-scanned state.
func (r *Registry) State(host string) HostState {
	h, _ := NormalizeHost(host)

	r.mu.Lock()
	defer r.mu.Unlock()

	history := r.hosts[h]
	if len(history) == 0 {
		return HostState{Host: h, Scanned: false, CurrentPorts: []int{}, ScanCount: 0}
	}
	last := history[len(history)-1]
	return HostState{
		Host:          h,
		Scanned:       true,
		CurrentPorts:  last.Ports,
		LastScannedAt: &last.ScannedAt,
		ScanCount:     len(history),
	}
}

// History returns a copy of a host's scans ordered by time ascending.
func (r *Registry) History(host string) []Scan {
	h, _ := NormalizeHost(host)

	r.mu.Lock()
	defer r.mu.Unlock()

	src := r.hosts[h]
	out := make([]Scan, len(src))
	copy(out, src)
	for i := range out {
		out[i].Ports = append([]int(nil), src[i].Ports...)
	}
	return out
}

// HostsForPort returns the hosts whose most recent scan opened the given port,
// sorted ascending. port must be in [1,65535]; otherwise it returns nil,false.
func (r *Registry) HostsForPort(port int) ([]string, bool) {
	if port < 1 || port > 65535 {
		return nil, false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	var hosts []string
	for h, history := range r.hosts {
		if len(history) == 0 {
			continue
		}
		last := history[len(history)-1].Ports
		// last is sorted; binary search would also work, but linear is fine.
		for _, p := range last {
			if p == port {
				hosts = append(hosts, h)
				break
			}
		}
	}
	sort.Strings(hosts)
	return hosts, true
}

// Snapshot returns global statistics and the top-N ports by current host count.
// topN limits the returned port ranking.
func (r *Registry) Snapshot(topN int) (Stats, []PortCount) {
	count := map[int]int{}
	hostCount := 0
	scanCount := 0
	for _, history := range r.hosts {
		hostCount++
		scanCount += len(history)
		if len(history) == 0 {
			continue
		}
		last := history[len(history)-1].Ports
		seen := map[int]struct{}{}
		for _, p := range last {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			count[p]++
		}
	}

	ranked := make([]PortCount, 0, len(count))
	for p, n := range count {
		ranked = append(ranked, PortCount{Port: p, Hosts: n})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].Hosts != ranked[j].Hosts {
			return ranked[i].Hosts > ranked[j].Hosts
		}
		return ranked[i].Port < ranked[j].Port
	})
	if topN >= 0 && len(ranked) > topN {
		ranked = ranked[:topN]
	}
	return Stats{Hosts: hostCount, Scans: scanCount}, ranked
}

// PortCount pairs a port with the number of hosts currently opening it.
type PortCount struct {
	Port  int
	Hosts int
}
