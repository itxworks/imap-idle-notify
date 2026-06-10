package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"software.sslmate.com/src/go-pkcs12"
)

// Shared fixtures, built once in TestMain.
var (
	greenmail  testcontainers.Container
	imapHost   string
	imapPort   string
	smtpAddr   string
	caCertPath string
	tlsRootCAs *x509.CertPool
	binPath    string
)

const (
	imapUser = "testuser"
	imapPass = "testpass"
	mailbox  = "testuser@localhost"
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	tmp, err := os.MkdirTemp("", "imap-e2e")
	must(err)
	defer os.RemoveAll(tmp)

	keystore := filepath.Join(tmp, "keystore.p12")
	caCertPath = filepath.Join(tmp, "ca.crt")
	genCertAndKeystore(keystore, caCertPath)

	greenmail = startGreenmail(ctx, keystore)
	imapHost = "127.0.0.1"
	imapPort = mappedPort(ctx, greenmail, "3993")
	smtpAddr = "127.0.0.1:" + mappedPort(ctx, greenmail, "3025")

	binPath = filepath.Join(tmp, "daemon")
	buildDaemon(binPath)

	code := m.Run()

	_ = greenmail.Terminate(ctx)
	os.Exit(code)
}

// --- fixtures --------------------------------------------------------------

func genCertAndKeystore(keystorePath, caPath string) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	must(err)
	cert, err := x509.ParseCertificate(der)
	must(err)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	must(os.WriteFile(caPath, caPEM, 0o644))

	tlsRootCAs = x509.NewCertPool()
	tlsRootCAs.AppendCertsFromPEM(caPEM)

	// Legacy PKCS12 (3DES/SHA1) for maximum JVM compatibility.
	pfx, err := pkcs12.Legacy.Encode(priv, cert, nil, "changeit")
	must(err)
	must(os.WriteFile(keystorePath, pfx, 0o644))
}

func startGreenmail(ctx context.Context, keystorePath string) testcontainers.Container {
	opts := "-Dgreenmail.setup.test.smtp -Dgreenmail.setup.test.imaps " +
		"-Dgreenmail.hostname=0.0.0.0 " +
		"-Dgreenmail.users=testuser:testpass@localhost " +
		"-Dgreenmail.tls.keystore.file=/certs/keystore.p12 " +
		"-Dgreenmail.tls.keystore.password=changeit"

	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		Started: true,
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "greenmail/standalone:2.1.3",
			ExposedPorts: []string{"3025/tcp", "3993/tcp"},
			Env:          map[string]string{"GREENMAIL_OPTS": opts},
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      keystorePath,
				ContainerFilePath: "/certs/keystore.p12",
				FileMode:          0o644,
			}},
			WaitingFor: wait.ForAll(
				wait.ForListeningPort("3993/tcp"),
				wait.ForListeningPort("3025/tcp"),
			).WithDeadline(60 * time.Second),
		},
	})
	must(err)
	return c
}

func mappedPort(ctx context.Context, c testcontainers.Container, port string) string {
	p, err := c.MappedPort(ctx, port+"/tcp")
	must(err)
	return p.Port()
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func containsStr(s, sub string) bool { return strings.Contains(s, sub) }

func readAll(r io.Reader) string {
	b, _ := io.ReadAll(r)
	return string(b)
}


func buildDaemon(out string) {
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = ".." // the app module lives in the repo root
	if outBytes, err := cmd.CombinedOutput(); err != nil {
		panic(fmt.Sprintf("build daemon: %v\n%s", err, outBytes))
	}
}

// --- daemon under test -----------------------------------------------------

// runDaemon starts the built binary with the base IMAP config plus the given
// overrides, and returns a stop function. Mail already in the mailbox is
// processed by the daemon's initial fetch, so scenarios deliver first.
func runDaemon(t *testing.T, env map[string]string) {
	t.Helper()
	base := map[string]string{
		"IMAP_HOST":   imapHost,
		"IMAP_PORT":   imapPort,
		"IMAP_USER":   imapUser,
		"IMAP_PASS":   imapPass,
		"IMAP_CA_CERT": caCertPath,
	}
	for k, v := range env {
		base[k] = v
	}
	cmd := exec.Command(binPath)
	cmd.Env = os.Environ()
	for k, v := range base {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	if testing.Verbose() {
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	}
	must(cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
}

// --- fake notifier ---------------------------------------------------------

type capturedReq struct {
	Path   string
	Header http.Header
	Body   string
}

type recorder struct {
	mu     sync.Mutex
	reqs   []capturedReq
	server *httptest.Server
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	r := &recorder{}
	r.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body := make([]byte, req.ContentLength)
		_, _ = req.Body.Read(body)
		r.mu.Lock()
		r.reqs = append(r.reqs, capturedReq{Path: req.URL.Path, Header: req.Header.Clone(), Body: string(body)})
		r.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(r.server.Close)
	return r
}

func (r *recorder) url() string { return r.server.URL }

func (r *recorder) waitFor(t *testing.T, contains string) capturedReq {
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

func (r *recorder) assertNone(t *testing.T, contains string, settle time.Duration) {
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

func (r *recorder) count(contains string) int {
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

// --- mail + mailbox --------------------------------------------------------

func sendMail(t *testing.T, from, subject, body string) {
	t.Helper()
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s\r\n", from, mailbox, subject, body)
	must(smtp.SendMail(smtpAddr, nil, from, []string{mailbox}, []byte(msg)))
}

// sendMailWithCc delivers a mail whose Cc header carries cc; the envelope
// recipient is still the mailbox so GreenMail accepts it.
func sendMailWithCc(t *testing.T, from, cc, subject, body string) {
	t.Helper()
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nCc: %s\r\nSubject: %s\r\n\r\n%s\r\n",
		from, mailbox, cc, subject, body)
	must(smtp.SendMail(smtpAddr, nil, from, []string{mailbox}, []byte(msg)))
}

// sendAlternativeMail delivers a multipart/alternative mail with both a
// text/plain and a text/html representation of the same message.
func sendAlternativeMail(t *testing.T, from, subject, plain, htmlBody string) {
	t.Helper()
	const b = "alt-boundary-xyz"
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n"+
		"MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=%q\r\n\r\n"+
		"--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n"+
		"--%s\r\nContent-Type: text/html; charset=utf-8\r\n\r\n%s\r\n"+
		"--%s--\r\n",
		from, mailbox, subject, b, b, plain, b, htmlBody, b)
	must(smtp.SendMail(smtpAddr, nil, from, []string{mailbox}, []byte(msg)))
}

func imapDo(t *testing.T, fn func(c *client.Client)) {
	t.Helper()
	c, err := client.DialTLS(imapHost+":"+imapPort, &tls.Config{RootCAs: tlsRootCAs, ServerName: imapHost})
	must(err)
	defer c.Logout()
	must(c.Login(imapUser, imapPass))
	fn(c)
}

func purgeMailbox(t *testing.T) {
	t.Helper()
	imapDo(t, func(c *client.Client) {
		if _, err := c.Select("INBOX", false); err != nil {
			return
		}
		crit := imap.NewSearchCriteria()
		ids, err := c.Search(crit)
		must(err)
		if len(ids) == 0 {
			return
		}
		set := new(imap.SeqSet)
		set.AddNum(ids...)
		must(c.Store(set, imap.FormatFlagsOp(imap.AddFlags, true), []interface{}{imap.DeletedFlag}, nil))
		must(c.Expunge(nil))
	})
}

func mailboxHas(t *testing.T, token string) bool {
	t.Helper()
	found := false
	imapDo(t, func(c *client.Client) {
		_, err := c.Select("INBOX", false)
		must(err)
		crit := imap.NewSearchCriteria()
		crit.Body = []string{token}
		ids, err := c.Search(crit)
		must(err)
		found = len(ids) > 0
	})
	return found
}
