package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func buildDaemon(out string) {
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = ".." // the app module lives in the repo root
	if outBytes, err := cmd.CombinedOutput(); err != nil {
		panic(fmt.Sprintf("build daemon: %v\n%s", err, outBytes))
	}
}

// --- daemon under test -----------------------------------------------------

// runDaemon starts the built binary with the base IMAP config plus the given
// overrides. Mail already in the mailbox is processed by the daemon's initial
// fetch, so scenarios deliver first.
func runDaemon(t *testing.T, env map[string]string) {
	t.Helper()
	base := map[string]string{
		"IMAP_HOST":    imapHost,
		"IMAP_PORT":    imapPort,
		"IMAP_USER":    imapUser,
		"IMAP_PASS":    imapPass,
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

// runDaemonExit starts the binary with only the given env and waits for it to
// exit on its own, returning whether it failed and its combined output.
func runDaemonExit(t *testing.T, env map[string]string, timeout time.Duration) (failed bool, output string) {
	t.Helper()
	cmd := exec.Command(binPath)
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	must(cmd.Start())

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err != nil, buf.String()
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("daemon did not exit within %s; output:\n%s", timeout, buf.String())
		return false, buf.String()
	}
}
