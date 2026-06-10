package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap-idle"
	"github.com/emersion/go-imap-uidplus"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message/mail"
	"github.com/k3a/html2text"
)

// --- ENV Helpers ---
func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envList(key, def string) []string {
	val := os.Getenv(key)
	if val == "" {
		val = def
	}
	parts := strings.Split(val, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envBool(key string, def bool) bool {
	val := strings.ToLower(os.Getenv(key))
	if val == "" {
		return def
	}
	return val == "1" || val == "true" || val == "yes"
}

// initLogger honours LOG_LEVEL (debug|info|warn|error) and LOG_JSON.
func initLogger() {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler = slog.NewTextHandler(os.Stderr, opts)
	if envBool("LOG_JSON", false) {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
}

// --- Config ---
var (
	IMAPHost = env("IMAP_HOST", "imap.example.com")
	IMAPPort = envInt("IMAP_PORT", 993)
	IMAPUser = env("IMAP_USER", "username@example.com")
	IMAPPass = env("IMAP_PASS", "password")

	IMAPCACert = env("IMAP_CA_CERT", "")
	IMAPCert   = env("IMAP_CLIENT_CERT", "")
	IMAPKey    = env("IMAP_CLIENT_KEY", "")

	FromFilter            = envList("FROM_FILTER", "user@gmail.com,test@example.com")
	DeleteAfterProcessing = envBool("DELETE_AFTER_PROCESSING", false)
	IMAPFlag = env("IMAP_FLAG", "\\Seen")

	CheckFrom = envBool("CHECK_FROM", true)
	CheckCc   = envBool("CHECK_CC", false)
	CheckBcc  = envBool("CHECK_BCC", false)
	CheckTo   = envBool("CHECK_TO", false)

	NotifyAllEmails = envBool("NOTIFY_ALL_EMAILS", false)

	NotifierType   = env("NOTIFIER_TYPE", "gotify") // gotify or ntfy
	GotifyURL      = env("GOTIFY_URL", "")
	GotifyToken    = env("GOTIFY_TOKEN", "")
	GotifyPriority = envInt("GOTIFY_PRIORITY", 5)
	NtfyUrl        = env("NTFY_URL", "https://ntfy.sh")
	NtfyTopic      = env("NTFY_TOPIC", "")
	NtfyAuthToken  = env("NTFY_AUTH_TOKEN", "")
	NtfyPriority   = envInt("NTFY_PRIORITY", 5)
	NtfyClickAction = env("NTFY_CLICK_ACTION", "")

	SendMessageBody = envBool("SEND_MESSAGE_BODY", true)

	AllowedFrom = make(map[string]bool)
)

// shared HTTP client (connection reuse + single timeout)
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	},
}

// --- Health tracking ---
//
// idleRefresh is the longest normal gap between health stamps on a quiet
// mailbox, so healthTimeout must exceed it (plus slack) to avoid flapping.
// Keep them coupled: if idleRefresh changes, healthTimeout follows.
const (
	idleRefresh   = 29 * time.Minute
	healthSlack   = 2 * time.Minute
	healthTimeout = idleRefresh + healthSlack
)

var (
	HealthPort  = envInt("HEALTH_PORT", 8080)
	MaxFailures = int64(envInt("HEALTH_MAX_FAILURES", 5))
)

// lastHealthyUnixNano catches silent death (wedged/deaf-but-open socket);
// consecutiveFailures catches loud, fast death (auth rejected, refused).
var health struct {
	lastHealthyUnixNano atomic.Int64
	consecutiveFailures atomic.Int64
}

func markHealthy() {
	health.lastHealthyUnixNano.Store(time.Now().UnixNano())
	health.consecutiveFailures.Store(0)
}

func markFailure() {
	health.consecutiveFailures.Add(1)
}

func healthy() bool {
	last := health.lastHealthyUnixNano.Load()
	if last == 0 || time.Since(time.Unix(0, last)) > healthTimeout {
		return false
	}
	return health.consecutiveFailures.Load() < MaxFailures
}

// startHealthServer serves GET /healthz on localhost for the HEALTHCHECK probe
// (same network namespace, so 127.0.0.1 is reachable).
func startHealthServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if healthy() {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok\n")
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "unhealthy\n")
	})
	addr := fmt.Sprintf("127.0.0.1:%d", HealthPort)
	go func() {
		slog.Debug("health endpoint listening", "addr", addr+"/healthz")
		if err := http.ListenAndServe(addr, mux); err != nil {
			slog.Error("health server stopped", "err", err)
		}
	}()
}

// runHealthProbe is the -healthcheck mode: probe /healthz and exit 0/1.
func runHealthProbe() int {
	url := fmt.Sprintf("http://127.0.0.1:%d/healthz", HealthPort)
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		slog.Error("health probe failed", "err", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return 0
	}
	slog.Error("health probe unhealthy", "status", resp.StatusCode)
	return 1
}

// --- TLS Loader ---
func loadTLSConfig() (*tls.Config, error) {
	slog.Debug("loading TLS configuration")
	tlsConfig := &tls.Config{InsecureSkipVerify: false}

	if IMAPCACert != "" {
		caCert, err := os.ReadFile(IMAPCACert)
		if err != nil {
			return nil, fmt.Errorf("read CA cert: %w", err)
		}
		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to append CA cert")
		}
		tlsConfig.RootCAs = caPool
	}

	if IMAPCert != "" && IMAPKey != "" {
		cert, err := tls.LoadX509KeyPair(IMAPCert, IMAPKey)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// --- HTML to text ---
// htmlToText extracts the visible text from an HTML body. It drops <script>
// and <style> contents so inline CSS and tracking JavaScript never reach the
// notification.
func htmlToText(htmlStr string) string {
	return strings.TrimSpace(html2text.HTML2Text(htmlStr))
}

// --- Notifiers ---

// headerSafe strips control characters from email-derived values so a
// crafted sender/subject cannot make the notification HTTP request fail
func headerSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

func sendGotify(sender, subject, body string) {
	payload := map[string]interface{}{
		"title":    fmt.Sprintf("Email from %s", sender),
		"message":  fmt.Sprintf("Subject: %s\n\n%s", subject, body),
		"priority": GotifyPriority,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		slog.Error("gotify marshal failed", "err", err)
		return
	}
	url := fmt.Sprintf("%s/message", GotifyURL)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		slog.Error("gotify request creation failed", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// Token in a header keeps it out of access logs and proxies
	req.Header.Set("X-Gotify-Key", GotifyToken)

	resp, err := httpClient.Do(req)
	if err != nil {
		slog.Error("gotify send failed", "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		slog.Debug("gotify notification sent")
	} else {
		slog.Error("gotify server rejected notification", "status", resp.Status)
	}
}

func sendNtfy(sender, subject, body string) {
	url := fmt.Sprintf("%s/%s", NtfyUrl, NtfyTopic)
	message := fmt.Sprintf("From: %s\nSubject: %s\n\n%s", sender, subject, body)

	req, err := http.NewRequest("POST", url, strings.NewReader(message))
	if err != nil {
		slog.Error("ntfy request creation failed", "err", err)
		return
	}

	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Title", headerSafe(fmt.Sprintf("Email from %s", sender)))
	req.Header.Set("Priority", strconv.Itoa(NtfyPriority))
	if NtfyAuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+NtfyAuthToken)
	}
	if NtfyClickAction != "" {
		req.Header.Set("Click", NtfyClickAction)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		slog.Error("ntfy send failed", "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		slog.Debug("ntfy notification sent")
	} else {
		slog.Error("ntfy server rejected notification", "status", resp.Status)
	}
}

func sendNotification(sender, subject, body string) {
	switch NotifierType {
	case "ntfy":
		sendNtfy(sender, subject, body)
	default:
		sendGotify(sender, subject, body)
	}
}

// --- Enhanced address checker --- to check against allowed patterns like *@example.com
func check(addrs []*imap.Address) bool {
	for _, addr := range addrs {
		email := strings.ToLower(addr.MailboxName + "@" + addr.HostName)

		// Check against all allowed patterns
		for allowed := range AllowedFrom {
			// If pattern starts with @, it's a domain pattern
			if strings.HasPrefix(allowed, "@") {
				if strings.HasSuffix(email, allowed) {
					return true
				}
			} else {
				// Otherwise, it's an exact email match
				if email == allowed {
					return true
				}
			}
		}
	}
	return false
}

type addressCheck struct {
	enabled bool
	addrs   func(*imap.Envelope) []*imap.Address
}

// addressChecks lists every envelope field that can be filtered on.
func addressChecks() []addressCheck {
	return []addressCheck{
		{CheckFrom, func(e *imap.Envelope) []*imap.Address { return e.From }},
		{CheckCc, func(e *imap.Envelope) []*imap.Address { return e.Cc }},
		{CheckBcc, func(e *imap.Envelope) []*imap.Address { return e.Bcc }},
		{CheckTo, func(e *imap.Envelope) []*imap.Address { return e.To }},
	}
}

func shouldNotify(env *imap.Envelope) bool {
	if NotifyAllEmails {
		return true
	}
	for _, c := range addressChecks() {
		if c.enabled && check(c.addrs(env)) {
			return true
		}
	}
	return false
}

// validateConfig rejects configurations that could never produce a notification.
func validateConfig() error {
	if NotifyAllEmails {
		return nil
	}
	for _, c := range addressChecks() {
		if c.enabled {
			return nil
		}
	}
	return fmt.Errorf("no notifications possible: set NOTIFY_ALL_EMAILS=true or enable at least one CHECK_* filter")
}

// --- Message Processing ---
func processMessage(c *client.Client, msg *imap.Message, section *imap.BodySectionName) {
	if msg == nil || msg.Envelope == nil {
		slog.Warn("skipping message with no envelope")
		return
	}
	slog.Debug("processing message", "subject", msg.Envelope.Subject)

	if !shouldNotify(msg.Envelope) {
		slog.Debug("message did not match filters, skipping", "subject", msg.Envelope.Subject)
		return
	}
	var bodyText string
	if SendMessageBody {
		r := msg.GetBody(section)
		if r == nil {
			slog.Warn("message body not returned by server", "subject", msg.Envelope.Subject)
			return
		}

		mr, err := mail.CreateReader(r)
		if err != nil {
			slog.Error("mail read failed", "err", err)
			return
		}

		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				slog.Error("mail part read failed", "err", err)
				break
			}

			switch h := p.Header.(type) {
			case *mail.InlineHeader:
				ct, _, _ := h.ContentType()
				data, _ := io.ReadAll(io.LimitReader(p.Body, 10240))
				if strings.HasPrefix(ct, "text/plain") {
					bodyText = string(data)
					goto SEND
				} else if strings.HasPrefix(ct, "text/html") && bodyText == "" {
					bodyText = htmlToText(string(data))
				}
			}
		}
	}

SEND:
	subject := ""
	if msg.Envelope != nil {
		subject = msg.Envelope.Subject
	}
	sender := ""
	if len(msg.Envelope.From) > 0 {
		sender = strings.ToLower(msg.Envelope.From[0].MailboxName + "@" + msg.Envelope.From[0].HostName)
	}

	sendNotification(sender, subject, bodyText)

	// add flag
	seqset := new(imap.SeqSet)
	seqset.AddNum(msg.SeqNum)
	flags := []interface{}{IMAPFlag}
	if err := c.Store(seqset, imap.FormatFlagsOp(imap.AddFlags, true), flags, nil); err != nil {
		slog.Error("failed to add flag", "flag", IMAPFlag, "err", err)
	}

	if DeleteAfterProcessing {
		if err := c.Store(seqset, imap.FormatFlagsOp(imap.AddFlags, true), []interface{}{imap.DeletedFlag}, nil); err != nil {
			slog.Error("failed to mark message deleted", "err", err)
			return
		}
		slog.Debug("message marked for deletion")
		// Expunge only this message via UID EXPUNGE (UIDPLUS) so other
		// \Deleted messages in the mailbox are left untouched.
		uidClient := uidplus.NewClient(c)
		if supported, err := uidClient.SupportUidPlus(); err == nil && supported && msg.Uid != 0 {
			uidSet := new(imap.SeqSet)
			uidSet.AddNum(msg.Uid)
			if err := uidClient.UidExpunge(uidSet, nil); err != nil {
				slog.Error("failed to expunge message", "err", err)
			} else {
				slog.Debug("message deleted from server")
			}
		} else {
			slog.Warn("server lacks UIDPLUS; message stays flagged \\Deleted until next expunge")
		}
	}
}

// --- Fetch Unseen ---
func fetchUnseen(c *client.Client, section *imap.BodySectionName) {
	slog.Debug("fetching unseen messages")
	criteria := imap.NewSearchCriteria()
	criteria.WithoutFlags = []string{IMAPFlag, imap.SeenFlag}
	ids, err := c.Search(criteria)
	if err != nil {
		slog.Error("search for unseen messages failed", "err", err)
		return
	}
	markHealthy()
	if len(ids) == 0 {
		return
	}

	seqset := new(imap.SeqSet)
	seqset.AddNum(ids...)
	messages := make(chan *imap.Message, 5)
	done := make(chan error, 1)
	go func() {
		done <- c.Fetch(seqset, []imap.FetchItem{imap.FetchEnvelope, imap.FetchUid, section.FetchItem()}, messages)
	}()
	for msg := range messages {
		processMessage(c, msg, section)
	}
	if err := <-done; err != nil {
		slog.Error("fetch failed", "err", err)
	}
}

// --- Single IMAP session ---
func runIMAPSession() error {
	tlsConfig, err := loadTLSConfig()
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", IMAPHost, IMAPPort)
	slog.Debug("connecting to IMAP server", "addr", addr)
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("IMAP connection error: %w", err)
	}
	c, err := client.New(conn)
	if err != nil {
		return fmt.Errorf("IMAP client error: %w", err)
	}
	defer func() {
		_ = c.Logout()
	}()

	if err := c.Login(IMAPUser, IMAPPass); err != nil {
		return fmt.Errorf("IMAP login error: %w", err)
	}
	slog.Debug("logged in successfully")

	if _, err = c.Select("INBOX", false); err != nil {
		return fmt.Errorf("Select INBOX error: %w", err)
	}
	markHealthy() // login + mailbox round-trip succeeded

	// Use PEEK to avoid setting \Seen during fetch
	section := &imap.BodySectionName{Peek: true}
	idleClient := idle.NewClient(c)

	// Initial fetch
	fetchUnseen(c, section)

	updates := make(chan client.Update, 16)
	c.Updates = updates
	for {
		stopIdle := make(chan struct{})
		idleDone := make(chan error, 1)

		markHealthy() // actively (re)entering IDLE

		go func() {
			idleDone <- idleClient.Idle(stopIdle)
		}()

		select {
		case <-updates:
			// New updates; stop IDLE, handle unseen, resume
			close(stopIdle)
			if err := <-idleDone; err != nil {
				return fmt.Errorf("idle ended with error: %w", err)
			}
			fetchUnseen(c, section)

		case err := <-idleDone:
			// Idle ended unexpectedly (likely disconnect)
			if err != nil {
				return fmt.Errorf("idle error: %w", err)
			}
			// No error: loop will start IDLE again
		case <-time.After(idleRefresh):
			// RFC: break IDLE periodically to send a command
			close(stopIdle)
			if err := <-idleDone; err != nil {
				return fmt.Errorf("idle ended with error: %w", err)
			}
			// Loop to start IDLE again
		}
	}
}

// --- MAIN ---
func main() {
	probe := flag.Bool("healthcheck", false, "probe the local /healthz endpoint and exit 0/1")
	flag.Parse()
	initLogger()
	if *probe {
		os.Exit(runHealthProbe())
	}

	if err := validateConfig(); err != nil {
		slog.Error("invalid configuration", "err", err)
		os.Exit(1)
	}

	slog.Info("starting IMAP notifier")

	for _, addr := range FromFilter {
		AllowedFrom[addr] = true
		slog.Debug("allowed sender", "addr", addr)
	}

	startHealthServer()

	backoff := 2 * time.Second
	const maxBackoff = 1 * time.Minute

	for {
		if err := runIMAPSession(); err != nil {
			slog.Error("session ended with error", "err", err)
			markFailure()
		} else {
			return // graceful exit (unlikely in normal runs)
		}

		slog.Warn("reconnecting after backoff", "backoff", backoff)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
