package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Real ntfy server in a container: proves the daemon's published notification
// is accepted by a real implementation and can be read back from the topic's
// cached stream.

// startNtfy boots a real ntfy server (anonymous publish/read allowed by
// default) and returns its base URL.
func startNtfy(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Started: true,
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "binwiederhier/ntfy:v2.11.0",
			Cmd:          []string{"serve"},
			Env:          map[string]string{"NTFY_BASE_URL": "http://localhost", "NTFY_LISTEN_HTTP": ":80"},
			ExposedPorts: []string{"80/tcp"},
			WaitingFor:   wait.ForHTTP("/v1/health").WithPort("80/tcp").WithStartupTimeout(60 * time.Second),
		},
	})
	must(err)
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	host, err := c.Host(ctx)
	must(err)
	return fmt.Sprintf("http://%s:%s", host, mappedPort(ctx, c, "80"))
}

type ntfyMsg struct {
	Event    string `json:"event"`
	Title    string `json:"title"`
	Message  string `json:"message"`
	Priority int    `json:"priority"`
}

// waitForNtfyMessage polls the topic's cached JSON stream until a message whose
// body contains the token appears.
func waitForNtfyMessage(t *testing.T, base, topic, contains string) ntfyMsg {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/" + topic + "/json?poll=1&since=all")
		must(err)
		dec := json.NewDecoder(resp.Body)
		for {
			var m ntfyMsg
			if err := dec.Decode(&m); err != nil {
				break
			}
			if m.Event == "message" && containsStr(m.Message, contains) {
				resp.Body.Close()
				return m
			}
		}
		resp.Body.Close()
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("no ntfy message containing %q within timeout", contains)
	return ntfyMsg{}
}
