package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap-idle"
	"github.com/emersion/go-imap/client"
	"github.com/emersion/go-message/mail"
	"golang.org/x/net/html"
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
	GotifyPriority = envInt("GOTify_PRIORITY", 5)
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

// --- TLS Loader ---
func loadTLSConfig() (*tls.Config, error) {
	log.Println("Loading TLS configuration...")
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
func htmlToText(htmlStr string) string {
	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		return htmlStr
	}
	var buf bytes.Buffer
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.TextNode {
			buf.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return strings.TrimSpace(buf.String())
}

// --- Notifiers ---
func sendGotify(sender, subject, body string) {
	payload := map[string]interface{}{
		"title":    fmt.Sprintf("Email from %s", sender),
		"message":  fmt.Sprintf("Subject: %s\n\n%s", subject, body),
		"priority": GotifyPriority,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Println("[Gotify] Marshal error:", err)
		return
	}
	url := fmt.Sprintf("%s/message?token=%s", GotifyURL, GotifyToken)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Println("[Gotify] Request creation error:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Println("[Gotify] Send error:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Println("[Gotify] Notification sent")
	} else {
		log.Println("[Gotify] Server returned:", resp.Status)
	}
}

func sendNtfy(sender, subject, body string) {
	url := fmt.Sprintf("%s/%s", NtfyUrl, NtfyTopic)
	message := fmt.Sprintf("From: %s\nSubject: %s\n\n%s", sender, subject, body)

	req, err := http.NewRequest("POST", url, strings.NewReader(message))
	if err != nil {
		log.Println("[ntfy] Request creation error:", err)
		return
	}

	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Title", fmt.Sprintf("Email from %s", sender))
	req.Header.Set("Priority", strconv.Itoa(NtfyPriority))
	if NtfyAuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+NtfyAuthToken)
	}
	if NtfyClickAction != "" {
		req.Header.Set("Click", NtfyClickAction)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Println("[ntfy] Send error:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		log.Println("[ntfy] Notification sent")
	} else {
		log.Println("[ntfy] Server returned:", resp.Status)
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

// --- Message Processing ---
func processMessage(c *client.Client, msg *imap.Message, section *imap.BodySectionName) {
	log.Println("Processing message...")
	if msg == nil || msg.Envelope == nil {
		return
	}

	// If NOTIFY_ALL_EMAILS is false, apply filtering
	if !NotifyAllEmails {
		matched := false

		if CheckFrom && check(msg.Envelope.From) {
			matched = true
		} else if CheckCc && check(msg.Envelope.Cc) {
			matched = true
		} else if CheckBcc && check(msg.Envelope.Bcc) {
			matched = true
		} else if CheckTo && check(msg.Envelope.To) {
			matched = true
		}

		if !matched {
			return
		}
	}
	var bodyText string
	if SendMessageBody {
		r := msg.GetBody(section)
		if r == nil {
			return
		}

		mr, err := mail.CreateReader(r)
		if err != nil {
			log.Println("Mail read error:", err)
			return
		}

		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Println("Part read error:", err)
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
		log.Println("Failed to add flag:", err)
	}

	if DeleteAfterProcessing {
		// mark as deleted
		if err := c.Store(seqset, imap.FormatFlagsOp(imap.AddFlags, true), []interface{}{imap.DeletedFlag}, nil); err != nil {
			log.Println("Failed to mark deleted:", err)
		} else {
			log.Println("Message marked for deletion")
			// permanently remove it
			if err := c.Expunge(nil); err != nil {
				log.Println("Failed to expunge:", err)
			} else {
				log.Println("Message deleted from server")
			}
		}
	}

}

// --- Fetch Unseen ---
func fetchUnseen(c *client.Client, section *imap.BodySectionName) {
	log.Println("Fetching unseen messages...")
	criteria := imap.NewSearchCriteria()
	criteria.WithoutFlags = []string{IMAPFlag, imap.SeenFlag}
	ids, err := c.Search(criteria)
	if err != nil || len(ids) == 0 {
		return
	}

	seqset := new(imap.SeqSet)
	seqset.AddNum(ids...)
	messages := make(chan *imap.Message, 5)
	done := make(chan error, 1)
	go func() {
		done <- c.Fetch(seqset, []imap.FetchItem{imap.FetchEnvelope, section.FetchItem()}, messages)
	}()
	for msg := range messages {
		processMessage(c, msg, section)
	}
	<-done
}

// --- Single IMAP session ---
func runIMAPSession() error {
	tlsConfig, err := loadTLSConfig()
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", IMAPHost, IMAPPort)
	log.Println("Connecting to IMAP server:", addr)
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
	log.Println("Logged in successfully")

	if _, err = c.Select("INBOX", false); err != nil {
		return fmt.Errorf("Select INBOX error: %w", err)
	}

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
		case <-time.After(29 * time.Minute):
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
	log.Println("Starting IMAP notifier...")

	for _, addr := range FromFilter {
		AllowedFrom[addr] = true
		log.Println("Allowed sender:", addr)
	}

	// Reconnect loop with exponential backoff
	backoff := 2 * time.Second
	const maxBackoff = 1 * time.Minute

	for {
		if err := runIMAPSession(); err != nil {
			log.Println("Session error:", err)
		} else {
			// graceful exit (unlikely in normal runs)
			return
		}

		log.Printf("Reconnecting in %s...\n", backoff)
		time.Sleep(backoff)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
