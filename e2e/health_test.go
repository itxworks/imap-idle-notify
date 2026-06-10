package e2e

import (
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

// freePort reserves and releases a TCP port, returning it for the daemon's
// health server. Each daemon binds HEALTH_PORT, so tests must not share one.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer l.Close()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

// getHealth issues a single GET /healthz and returns the status code.
func getHealth(t *testing.T, port string) int {
	t.Helper()
	resp, err := http.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// waitHealthStatus polls /healthz until it returns want or the deadline passes.
func waitHealthStatus(t *testing.T, port string, want int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if getHealth(t, port) == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("health endpoint never returned %d within %s (last=%d)", want, within, getHealth(t, port))
}

// runProbe runs the binary in -healthcheck mode against the given port and
// returns its exit code, mirroring how Docker's HEALTHCHECK invokes it.
func runProbe(t *testing.T, port string) int {
	t.Helper()
	cmd := exec.Command(binPath, "-healthcheck")
	cmd.Env = append(os.Environ(), "HEALTH_PORT="+port)
	err := cmd.Run()
	if err == nil {
		return 0
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return exit.ExitCode()
	}
	t.Fatalf("probe run error: %v", err)
	return -1
}

// TestHealthyWhenConnected: once the daemon logs in and selects INBOX it stamps
// itself healthy, so /healthz returns 200 and the -healthcheck probe exits 0.
func TestHealthyWhenConnected(t *testing.T) {
	port := freePort(t)
	runDaemon(t, map[string]string{
		"NOTIFY_ALL_EMAILS": "true",
		"HEALTH_PORT":       port,
	})

	waitHealthStatus(t, port, http.StatusOK, 15*time.Second)
	if code := runProbe(t, port); code != 0 {
		t.Errorf("expected probe exit 0 when healthy, got %d", code)
	}
}

// TestUnhealthyWhenDisconnected: pointed at a dead IMAP port, the daemon never
// stamps healthy and its failure counter climbs, so /healthz returns 503 and
// the probe exits 1. HEALTH_MAX_FAILURES=1 makes the failure path trip fast.
func TestUnhealthyWhenDisconnected(t *testing.T) {
	port := freePort(t)
	runDaemon(t, map[string]string{
		"NOTIFY_ALL_EMAILS":   "true",
		"HEALTH_PORT":         port,
		"IMAP_PORT":           freePort(t), // nothing is listening here
		"HEALTH_MAX_FAILURES": "1",
	})

	waitHealthStatus(t, port, http.StatusServiceUnavailable, 15*time.Second)
	if code := runProbe(t, port); code != 1 {
		t.Errorf("expected probe exit 1 when unhealthy, got %d", code)
	}
}

// TestProbeFailsWithNoServer: with no daemon (nothing listening), the probe
// cannot reach /healthz and exits non-zero, so a dead container is reported
// unhealthy rather than hanging.
func TestProbeFailsWithNoServer(t *testing.T) {
	if code := runProbe(t, freePort(t)); code != 1 {
		t.Errorf("expected probe exit 1 with no server, got %d", code)
	}
}
