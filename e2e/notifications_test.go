package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestMultipartBodySelection: for a multipart/alternative mail the text/plain
// part is preferred and the HTML alternative is not used for the body.
func TestMultipartBodySelection(t *testing.T) {
	purgeMailbox(t)
	rec := newFakeNotifier(t)
	sendAlternativeMail(t, "multi@example.com", "Alt body",
		"plain-token-pick-me",
		"<html><body><p>html-token-ignore-me</p></body></html>")
	runDaemon(t, ntfyEnv(rec, map[string]string{"NOTIFY_ALL_EMAILS": "true"}))

	req := rec.waitFor(t, "plain-token-pick-me")
	if strings.Contains(req.Body, "html-token-ignore-me") {
		t.Errorf("HTML alternative leaked into body: %q", req.Body)
	}
}

// TestHTMLBodyStripsScriptAndStyle: for an HTML-only mail the daemon converts
// the markup to text for the notification body, dropping <style> and <script>
// contents so inline CSS and tracking JavaScript never reach the user, while the
// visible text is preserved.
func TestHTMLBodyStripsScriptAndStyle(t *testing.T) {
	purgeMailbox(t)
	rec := newFakeNotifier(t)
	sendHTMLMail(t, "html@example.com", "HTML body",
		"<html><head><style>.secret{color:css-token-leak}</style></head>"+
			"<body><script>var s='js-token-leak';</script>"+
			"<p>visible-token-keep</p></body></html>")
	runDaemon(t, ntfyEnv(rec, map[string]string{"NOTIFY_ALL_EMAILS": "true"}))

	req := rec.waitFor(t, "visible-token-keep")
	if strings.Contains(req.Body, "css-token-leak") {
		t.Errorf("CSS leaked into notification body: %q", req.Body)
	}
	if strings.Contains(req.Body, "js-token-leak") {
		t.Errorf("JavaScript leaked into notification body: %q", req.Body)
	}
}

// Regression for commits ad72d63 (token in X-Gotify-Key header, not the URL)
// and b0e3a41 (GOTIFY_PRIORITY honoured).
func TestGotifyTokenAndPriority(t *testing.T) {
	purgeMailbox(t)
	rec := newFakeNotifier(t)
	sendMail(t, "gotify@example.com", "Gotify hi", "body-token-gotify")
	runDaemon(t, map[string]string{
		"NOTIFIER_TYPE": "gotify", "GOTIFY_URL": rec.url(),
		"GOTIFY_TOKEN": "secret-gotify-token", "GOTIFY_PRIORITY": "7",
		"FROM_FILTER": "gotify@example.com", "CHECK_FROM": "true",
	})

	req := rec.waitFor(t, "body-token-gotify")
	if req.Path != "/message" {
		t.Errorf("request path was %q, want /message", req.Path)
	}
	// The token must travel in the header, never in the URL (path or query).
	if strings.Contains(req.RawQuery, "secret-gotify-token") {
		t.Errorf("token leaked into URL query: %q", req.RawQuery)
	}
	if got := req.Header.Get("X-Gotify-Key"); got != "secret-gotify-token" {
		t.Errorf("X-Gotify-Key was %q", got)
	}
	var payload struct {
		Priority int `json:"priority"`
	}
	must(json.Unmarshal([]byte(req.Body), &payload))
	if payload.Priority != 7 {
		t.Errorf("priority was %d, want 7", payload.Priority)
	}
}

// TestGotifyLiveServer drives the daemon against a real Gotify server: an app
// token is minted, the notification is posted, and the message is read back
// through Gotify's own API with the expected title and priority. This proves
// the request the daemon emits is actually accepted, beyond the wire-format
// assertions in TestGotifyTokenAndPriority.
func TestGotifyLiveServer(t *testing.T) {
	purgeMailbox(t)
	base := startGotify(t)
	token := createGotifyApp(t, base)
	sendMail(t, "gotify@example.com", "Real gotify", "body-token-realgotify")
	runDaemon(t, map[string]string{
		"NOTIFIER_TYPE": "gotify", "GOTIFY_URL": base,
		"GOTIFY_TOKEN": token, "GOTIFY_PRIORITY": "7",
		"FROM_FILTER": "gotify@example.com", "CHECK_FROM": "true",
	})

	msg := waitForGotifyMessage(t, base, "body-token-realgotify")
	if !strings.Contains(msg.Title, "Email from gotify@example.com") {
		t.Errorf("title was %q", msg.Title)
	}
	if !strings.Contains(msg.Message, "Subject: Real gotify") {
		t.Errorf("subject missing from message: %q", msg.Message)
	}
	if msg.Priority != 7 {
		t.Errorf("priority was %d, want 7", msg.Priority)
	}
}

// TestNtfyLiveServer drives the daemon against a real ntfy server and reads the
// published message back from the topic's cached stream, confirming the title
// and priority headers the daemon sets are honoured by a real implementation.
func TestNtfyLiveServer(t *testing.T) {
	purgeMailbox(t)
	base := startNtfy(t)
	const topic = "t"
	sendMail(t, "ntfy@example.com", "Real ntfy", "body-token-realntfy")
	runDaemon(t, map[string]string{
		"NOTIFIER_TYPE": "ntfy", "NTFY_URL": base, "NTFY_TOPIC": topic,
		"NTFY_PRIORITY": "4",
		"FROM_FILTER":   "ntfy@example.com", "CHECK_FROM": "true",
	})

	msg := waitForNtfyMessage(t, base, topic, "body-token-realntfy")
	if !strings.Contains(msg.Title, "Email from ntfy@example.com") {
		t.Errorf("title was %q", msg.Title)
	}
	if !strings.Contains(msg.Message, "Subject: Real ntfy") {
		t.Errorf("subject missing from message: %q", msg.Message)
	}
	if msg.Priority != 4 {
		t.Errorf("priority was %d, want 4", msg.Priority)
	}
}

// Regression for commit 08b2833: deletion is scoped to the processed message
// via UID EXPUNGE. A bystander message already flagged \Deleted must survive,
// since an unscoped Expunge would wrongly remove it too.
func TestScopedExpunge(t *testing.T) {
	purgeMailbox(t)
	rec := newFakeNotifier(t)

	// A pre-existing \Deleted message that the daemon must NOT expunge.
	sendMail(t, "bystander@example.com", "Bystander", "bystander-token")
	markDeleted(t, "bystander-token")

	sendMail(t, "deleteme@example.com", "Delete", "delete-token")
	runDaemon(t, ntfyEnv(rec, map[string]string{
		"FROM_FILTER": "deleteme@example.com", "CHECK_FROM": "true",
		"DELETE_AFTER_PROCESSING": "true",
	}))

	rec.waitFor(t, "delete-token")
	deadline := time.Now().Add(15 * time.Second)
	for mailboxHas(t, "delete-token") && time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
	}
	if mailboxHas(t, "delete-token") {
		t.Error("processed message was not expunged")
	}
	if !mailboxHas(t, "bystander-token") {
		t.Error("bystander \\Deleted message was wrongly expunged (deletion not scoped)")
	}
}
