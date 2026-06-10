package e2e

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"testing"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

// --- mail delivery ---------------------------------------------------------

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

// sendHTMLMail delivers an HTML-only mail (single text/html part) whose markup
// includes <style> and <script> blocks, so tests can assert that inline CSS and
// JavaScript never reach the notification body.
func sendHTMLMail(t *testing.T, from, subject, htmlBody string) {
	t.Helper()
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n"+
		"MIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n%s\r\n",
		from, mailbox, subject, htmlBody)
	must(smtp.SendMail(smtpAddr, nil, from, []string{mailbox}, []byte(msg)))
}

// --- mailbox inspection ----------------------------------------------------

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

// markDeleted flags the message containing token as \Deleted without
// expunging it, so it stays in the mailbox as a bystander deleted message.
func markDeleted(t *testing.T, token string) {
	t.Helper()
	imapDo(t, func(c *client.Client) {
		_, err := c.Select("INBOX", false)
		must(err)
		crit := imap.NewSearchCriteria()
		crit.Body = []string{token}
		ids, err := c.Search(crit)
		must(err)
		if len(ids) == 0 {
			t.Fatalf("message %q not found to mark deleted", token)
		}
		set := new(imap.SeqSet)
		set.AddNum(ids...)
		must(c.Store(set, imap.FormatFlagsOp(imap.AddFlags, true), []interface{}{imap.DeletedFlag}, nil))
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
