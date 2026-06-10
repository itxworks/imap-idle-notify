package e2e

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// fakeNotifier is an in-process HTTP server that stands in for a Gotify/ntfy
// endpoint and captures the raw requests the daemon sends. It lets tests assert
// on the exact wire bytes (headers, path, query, body) — things a real server
// would consume but not expose. For round-trip fidelity against a real
// implementation, see the Gotify/ntfy container harnesses instead.

type capturedReq struct {
	Path     string
	RawQuery string
	Header   http.Header
	Body     string
}

type fakeNotifier struct {
	mu     sync.Mutex
	reqs   []capturedReq
	server *httptest.Server
}

func newFakeNotifier(t *testing.T) *fakeNotifier {
	t.Helper()
	r := &fakeNotifier{}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body := make([]byte, req.ContentLength)
		_, _ = req.Body.Read(body)
		r.mu.Lock()
		r.reqs = append(r.reqs, capturedReq{Path: req.URL.Path, RawQuery: req.URL.RawQuery, Header: req.Header.Clone(), Body: string(body)})
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *fakeNotifier) url() string { return r.server.URL }

// ntfyEnv configures the daemon to notify via the fake notifier as an ntfy
// server, merging in any extra overrides.
func ntfyEnv(rec *fakeNotifier, extra map[string]string) map[string]string {
	env := map[string]string{
		"NOTIFIER_TYPE": "ntfy",
		"NTFY_URL":      rec.url(),
		"NTFY_TOPIC":    "t",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

func (r *fakeNotifier) waitFor(t *testing.T, contains string) capturedReq {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		for _, req := range r.reqs {
			if containsStr(req.Body, contains) {
				r.mu.Unlock()
				return req
			}
		}
		r.mu.Unlock()
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no notification containing %q within timeout", contains)
	return capturedReq{}
}

func (r *fakeNotifier) assertNone(t *testing.T, contains string, settle time.Duration) {
	t.Helper()
	time.Sleep(settle)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, req := range r.reqs {
		if containsStr(req.Body, contains) {
			t.Fatalf("unexpected notification containing %q: %s", contains, req.Body)
		}
	}
}

func (r *fakeNotifier) count(contains string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, req := range r.reqs {
		if containsStr(req.Body, contains) {
			n++
		}
	}
	return n
}
