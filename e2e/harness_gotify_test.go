package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Real Gotify server in a container: proves the daemon's request is accepted by
// a real implementation and the message it produced can be read back through
// Gotify's own API.

// startGotify boots a real Gotify server and returns its base URL.
func startGotify(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Started: true,
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "gotify/server:2.6.3",
			ExposedPorts: []string{"80/tcp"},
			WaitingFor:   wait.ForHTTP("/health").WithPort("80/tcp").WithStartupTimeout(60 * time.Second),
		},
	})
	must(err)
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	host, err := c.Host(ctx)
	must(err)
	return fmt.Sprintf("http://%s:%s", host, mappedPort(ctx, c, "80"))
}

// createGotifyApp registers an application (default admin:admin credentials)
// and returns its token, which the daemon uses as GOTIFY_TOKEN.
func createGotifyApp(t *testing.T, base string) string {
	t.Helper()
	req, err := http.NewRequest("POST", base+"/application", strings.NewReader(`{"name":"e2e"}`))
	must(err)
	req.SetBasicAuth("admin", "admin")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	must(err)
	defer resp.Body.Close()
	var app struct {
		Token string `json:"token"`
	}
	must(json.NewDecoder(resp.Body).Decode(&app))
	if app.Token == "" {
		t.Fatalf("gotify returned no application token (status %s)", resp.Status)
	}
	return app.Token
}

type gotifyMsg struct {
	Title    string `json:"title"`
	Message  string `json:"message"`
	Priority int    `json:"priority"`
}

// waitForGotifyMessage polls Gotify's /message API (admin auth) until a message
// whose body contains the token appears.
func waitForGotifyMessage(t *testing.T, base, contains string) gotifyMsg {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		req, err := http.NewRequest("GET", base+"/message", nil)
		must(err)
		req.SetBasicAuth("admin", "admin")
		resp, err := http.DefaultClient.Do(req)
		must(err)
		var page struct {
			Messages []gotifyMsg `json:"messages"`
		}
		must(json.NewDecoder(resp.Body).Decode(&page))
		resp.Body.Close()
		for _, m := range page.Messages {
			if containsStr(m.Message, contains) {
				return m
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no gotify message containing %q within timeout", contains)
	return gotifyMsg{}
}
