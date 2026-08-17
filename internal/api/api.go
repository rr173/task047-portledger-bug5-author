// Package api implements the HTTP layer of the port ledger service.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"task047-portledger/internal/registry"
)

// New returns the HTTP handler serving the port ledger API over r.
func New(r *registry.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/scans", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		handleSubmitScan(w, req, r)
	})
	mux.HandleFunc("/hosts/", func(w http.ResponseWriter, req *http.Request) {
		handleHosts(w, req, r)
	})
	mux.HandleFunc("/ports/", func(w http.ResponseWriter, req *http.Request) {
		handlePortHosts(w, req, r)
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		handleStats(w, r)
	})
	return mux
}

// scanRequest is the JSON body of POST /scans.
type scanRequest struct {
	Host      string `json:"host"`
	ScannedAt string `json:"scanned_at"`
	Ports     []int  `json:"ports"`
}

// scanResponse is the success body of POST /scans.
type scanResponse struct {
	Host      string       `json:"host"`
	Sequence  int          `json:"sequence"`
	ScannedAt string       `json:"scanned_at"`
	Ports     []int        `json:"ports"`
	Diff      diffResponse `json:"diff"`
}

type diffResponse struct {
	Added   []int `json:"added"`
	Removed []int `json:"removed"`
}

func handleSubmitScan(w http.ResponseWriter, req *http.Request, r *registry.Registry) {
	var body scanRequest
	dec := json.NewDecoder(req.Body)
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Host == "" {
		writeError(w, http.StatusBadRequest, "host is required")
		return
	}
	if body.ScannedAt == "" {
		writeError(w, http.StatusBadRequest, "scanned_at is required")
		return
	}
	if body.Ports == nil {
		// A missing/null ports field is treated as "scanned, nothing open",
		// matching the empty-is-legal boundary. An explicit empty array
		// behaves identically.
		body.Ports = []int{}
	}
	t, err := time.Parse(time.RFC3339, body.ScannedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "scanned_at must be ISO 8601 / RFC3339")
		return
	}

	res, err := r.Submit(body.Host, t, body.Ports)
	if err != nil {
		switch {
		case errors.Is(err, registry.ErrInvalid):
			writeError(w, http.StatusBadRequest, "invalid scan")
		case errors.Is(err, registry.ErrOutOfOrder):
			writeError(w, http.StatusConflict, "out-of-order scan")
		default:
			writeError(w, http.StatusInternalServerError, "internal error")
		}
		return
	}

	resp := scanResponse{
		Host:      res.Host,
		Sequence:  res.Sequence,
		ScannedAt: res.ScannedAt.Format(time.RFC3339),
		Ports:     ensureSlice(res.Ports),
		Diff: diffResponse{
			Added:   ensureSlice(res.Diff.Added),
			Removed: ensureSlice(res.Diff.Removed),
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleHosts routes /hosts/{host} and /hosts/{host}/history.
func handleHosts(w http.ResponseWriter, req *http.Request, r *registry.Registry) {
	if req.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rest := strings.TrimPrefix(req.URL.Path, "/hosts/")
	if rest == "" {
		writeError(w, http.StatusNotFound, "host required")
		return
	}
	var host, sub string
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		host = rest[:i]
		sub = rest[i+1:]
	} else {
		host = rest
	}
	if host == "" {
		writeError(w, http.StatusNotFound, "host required")
		return
	}
	switch sub {
	case "":
		st := r.State(host)
		writeJSON(w, http.StatusOK, hostStateResponse(st))
	case "history":
		hist := r.History(host)
		writeJSON(w, http.StatusOK, historyResponse(hist))
	default:
		writeError(w, http.StatusNotFound, "unknown path")
	}
}

func handlePortHosts(w http.ResponseWriter, req *http.Request, r *registry.Registry) {
	if req.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	rest := strings.TrimPrefix(req.URL.Path, "/ports/")
	if rest == "" {
		writeError(w, http.StatusNotFound, "port required")
		return
	}
	var portStr, sub string
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		portStr = rest[:i]
		sub = rest[i+1:]
	} else {
		portStr = rest
	}
	if sub != "" && sub != "hosts" {
		writeError(w, http.StatusNotFound, "unknown path")
		return
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "port must be an integer")
		return
	}
	hosts, ok := r.HostsForPort(port)
	if !ok {
		writeError(w, http.StatusBadRequest, "port out of range 1-65535")
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"hosts": hosts})
}

func handleStats(w http.ResponseWriter, r *registry.Registry) {
	st, top := r.Snapshot(5)
	type portCountJSON struct {
		Port  int `json:"port"`
		Hosts int `json:"hosts"`
	}
	topJSON := make([]portCountJSON, 0, len(top))
	for _, p := range top {
		topJSON = append(topJSON, portCountJSON{Port: p.Port, Hosts: p.Hosts})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hosts":     st.Hosts,
		"scans":     st.Scans,
		"top_ports": topJSON,
	})
}

// hostStateResponse builds the JSON view of a HostState, emitting null for a
// nil LastScannedAt and [] for empty port slices.
func hostStateResponse(st registry.HostState) map[string]any {
	var last any
	if st.LastScannedAt != nil {
		last = st.LastScannedAt.Format(time.RFC3339)
	}
	return map[string]any{
		"host":            st.Host,
		"scanned":         st.Scanned,
		"current_ports":   ensureSlice(st.CurrentPorts),
		"last_scanned_at": last,
		"scan_count":      st.ScanCount,
	}
}

func historyResponse(hist []registry.Scan) []map[string]any {
	out := make([]map[string]any, 0, len(hist))
	for _, s := range hist {
		out = append(out, map[string]any{
			"sequence":   s.Sequence,
			"scanned_at": s.ScannedAt.Format(time.RFC3339),
			"ports":      ensureSlice(s.Ports),
		})
	}
	return out
}

// ensureSlice returns a non-nil slice so JSON encodes [] rather than null.
func ensureSlice(s []int) []int {
	if s == nil {
		return []int{}
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
