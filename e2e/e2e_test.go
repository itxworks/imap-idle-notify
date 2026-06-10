package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ntfyEnv configures the daemon to notify via the recorder as an ntfy server.
func ntfyEnv(rec *recorder, extra map[string]string) map[string]string {
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

// TestExactSenderFilter: an allowed sender is notified (title, subject, no
// duplicate), and a non-allowed sender is ignored. Case-folding and HTML→text
// are pure functions covered by unit tests in the daemon package.
func TestExactSenderFilter(t *testing.T) {
	t.Run("allowed sender produces one notification", func(t *testing.T) {
		purgeMailbox(t)
		rec := newRecorder(t)
		sendMail(t, "alice@example.com", "Exact hello", "body-token-exact")
		runDaemon(t, ntfyEnv(rec, map[string]string{
			"FROM_FILTER": "alice@example.com", "CHECK_FROM": "true",
		}))

		req := rec.waitFor(t, "body-token-exact")
		if got := req.Header.Get("Title"); !strings.Contains(got, "Email from alice@example.com") {
			t.Errorf("title was %q", got)
		}
		if !strings.Contains(req.Body, "Subject: Exact hello") {
			t.Errorf("subject missing from body: %q", req.Body)
		}
		if n := rec.count("body-token-exact"); n != 1 {
			t.Errorf("expected exactly one notification, got %d", n)
		}
	})

	t.Run("non-allowed sender is ignored", func(t *testing.T) {
		purgeMailbox(t)
		rec := newRecorder(t)
		runDaemon(t, ntfyEnv(rec, map[string]string{
			"FROM_FILTER": "alice@example.com", "CHECK_FROM": "true",
		}))
		sendMail(t, "bob@example.com", "Filtered out", "body-token-bob")
		rec.assertNone(t, "body-token-bob", 4*time.Second)
	})
}

// TestLiveIdleDelivery: mail that arrives while the daemon is already idling
// (delivered after startup, not present at the initial fetch) is picked up via
// the IMAP IDLE push and notified. This exercises the daemon's core loop.
func TestLiveIdleDelivery(t *testing.T) {
	purgeMailbox(t)
	rec := newRecorder(t)
	runDaemon(t, ntfyEnv(rec, map[string]string{"NOTIFY_ALL_EMAILS": "true"}))

	// Give the daemon time to log in, run its empty initial fetch, and enter IDLE.
	time.Sleep(2 * time.Second)
	sendMail(t, "live@example.com", "Pushed", "body-token-idle")
	rec.waitFor(t, "body-token-idle")
}

// TestCcFilter: CHECK_CC matches on the Cc header, so a mail that carbon-copies
// the configured address is notified even when the From address does not match.
func TestCcFilter(t *testing.T) {
	purgeMailbox(t)
	rec := newRecorder(t)
	sendMailWithCc(t, "stranger@nowhere.net", mailbox, "Cc match", "body-token-cc")
	runDaemon(t, ntfyEnv(rec, map[string]string{
		"FROM_FILTER": mailbox, "CHECK_FROM": "false", "CHECK_CC": "true",
	}))
	rec.waitFor(t, "body-token-cc")
}

// TestMultipartBodySelection: for a multipart/alternative mail the text/plain
// part is preferred and the HTML alternative is not used for the body.
func TestMultipartBodySelection(t *testing.T) {
	purgeMailbox(t)
	rec := newRecorder(t)
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
	rec := newRecorder(t)
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

// TestDomainFilter: a sender matching an @domain pattern is notified with the
// configured NTFY_PRIORITY and NTFY_CLICK_ACTION, and a sender outside the
// domain is ignored.
func TestDomainFilter(t *testing.T) {
	t.Run("any sender in the domain is notified with priority and click", func(t *testing.T) {
		purgeMailbox(t)
		rec := newRecorder(t)
		sendMail(t, "carol@example.com", "Domain hello", "body-token-domain")
		runDaemon(t, ntfyEnv(rec, map[string]string{
			"FROM_FILTER": "@example.com", "CHECK_FROM": "true",
			"NTFY_PRIORITY": "4", "NTFY_CLICK_ACTION": "https://mail.example.com/",
		}))
		req := rec.waitFor(t, "body-token-domain")
		if got := req.Header.Get("Priority"); got != "4" {
			t.Errorf("priority header was %q, want 4", got)
		}
		if got := req.Header.Get("Click"); got != "https://mail.example.com/" {
			t.Errorf("click header was %q", got)
		}
	})

	t.Run("sender outside the domain is ignored", func(t *testing.T) {
		purgeMailbox(t)
		rec := newRecorder(t)
		runDaemon(t, ntfyEnv(rec, map[string]string{
			"FROM_FILTER": "@example.com", "CHECK_FROM": "true",
		}))
		sendMail(t, "dave@other.org", "Wrong domain", "body-token-otherdomain")
		rec.assertNone(t, "body-token-otherdomain", 4*time.Second)
	})
}

// TestRecipientFilter: CHECK_TO matches on the recipient address, so a mail to
// the mailbox is notified regardless of its sender.
func TestRecipientFilter(t *testing.T) {
	purgeMailbox(t)
	rec := newRecorder(t)
	sendMail(t, "stranger@nowhere.net", "To match", "body-token-tomatch")
	runDaemon(t, ntfyEnv(rec, map[string]string{
		"FROM_FILTER": mailbox, "CHECK_FROM": "false", "CHECK_TO": "true",
	}))
	rec.waitFor(t, "body-token-tomatch")
}

// TestNotifyAll: NOTIFY_ALL_EMAILS notifies regardless of sender or recipient.
func TestNotifyAll(t *testing.T) {
	purgeMailbox(t)
	rec := newRecorder(t)
	sendMail(t, "random@anywhere.io", "Catch all", "body-token-all")
	runDaemon(t, ntfyEnv(rec, map[string]string{"NOTIFY_ALL_EMAILS": "true"}))
	rec.waitFor(t, "body-token-all")
}

// Regression for commits ad72d63 (token in X-Gotify-Key header, not the URL)
// and b0e3a41 (GOTIFY_PRIORITY honoured).
func TestGotifyTokenAndPriority(t *testing.T) {
	purgeMailbox(t)
	rec := newRecorder(t)
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
	rec := newRecorder(t)

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
