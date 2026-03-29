package pflog_test

import (
	"strings"
	"testing"
	"time"

	"github.com/chrj/pflog"
)

// ---- helpers ----------------------------------------------------------------

func mustParse(t *testing.T, line string) *pflog.Record {
	t.Helper()
	r, err := pflog.Parse(line)
	if err != nil {
		t.Fatalf("Parse(%q): %v", line, err)
	}
	return r
}

// assertTime checks the time components of a parsed timestamp, ignoring the
// year (which is set to the current year by Parse).
func assertTime(t *testing.T, got time.Time, month time.Month, day, hour, min, sec int) {
	t.Helper()
	if got.Month() != month {
		t.Errorf("Time.Month = %v, want %v", got.Month(), month)
	}
	if got.Day() != day {
		t.Errorf("Time.Day = %d, want %d", got.Day(), day)
	}
	if got.Hour() != hour {
		t.Errorf("Time.Hour = %d, want %d", got.Hour(), hour)
	}
	if got.Minute() != min {
		t.Errorf("Time.Minute = %d, want %d", got.Minute(), min)
	}
	if got.Second() != sec {
		t.Errorf("Time.Second = %d, want %d", got.Second(), sec)
	}
	if got.Location() != time.UTC {
		t.Errorf("Time.Location = %v, want UTC", got.Location())
	}
}

// ---- invalid input ----------------------------------------------------------

func TestParse_InvalidFormat(t *testing.T) {
	cases := []string{
		"",
		"not a syslog line",
		"Jan 1 00:00:00 hostname",
		"random garbage data",
		"Jan 29 12:34:56 host", // missing process[pid]
	}
	for _, line := range cases {
		_, err := pflog.Parse(line)
		if err == nil {
			t.Errorf("Parse(%q) error = nil, want an error", line)
		}
	}
}

// ---- syslog header ----------------------------------------------------------

func TestParse_Header_DoubleDigitDay(t *testing.T) {
	line := `Mar 29 12:34:56 mail.example.com postfix/smtpd[1234]: connect from host[1.2.3.4]`
	r := mustParse(t, line)

	if r.Hostname != "mail.example.com" {
		t.Errorf("Hostname = %q, want %q", r.Hostname, "mail.example.com")
	}
	if r.Process != "smtpd" {
		t.Errorf("Process = %q, want %q", r.Process, "smtpd")
	}
	if r.PID != 1234 {
		t.Errorf("PID = %d, want %d", r.PID, 1234)
	}
	assertTime(t, r.Time, time.March, 29, 12, 34, 56)
}

func TestParse_Header_SingleDigitDay(t *testing.T) {
	line := `Jan  1 00:00:00 mx1 postfix/qmgr[42]: ABC12300AB: removed`
	r := mustParse(t, line)

	assertTime(t, r.Time, time.January, 1, 0, 0, 0)
	if r.Hostname != "mx1" {
		t.Errorf("Hostname = %q, want %q", r.Hostname, "mx1")
	}
	if r.Process != "qmgr" {
		t.Errorf("Process = %q, want %q", r.Process, "qmgr")
	}
	if r.PID != 42 {
		t.Errorf("PID = %d, want %d", r.PID, 42)
	}
}

// TestParse_Header_PlainProcess checks a process name with no slash.
func TestParse_Header_PlainProcess(t *testing.T) {
	line := `Dec 31 23:59:59 relay master[1]: terminating on signal 15`
	r := mustParse(t, line)
	if r.Process != "master" {
		t.Errorf("Process = %q, want %q", r.Process, "master")
	}
	assertTime(t, r.Time, time.December, 31, 23, 59, 59)
}

// ---- queue ID extraction ----------------------------------------------------

func TestParse_QueueID_Present(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/qmgr[99]: ABCDEF1234: removed`
	r := mustParse(t, line)
	if r.QueueID != "ABCDEF1234" {
		t.Errorf("QueueID = %q, want %q", r.QueueID, "ABCDEF1234")
	}
	if _, ok := r.Message.(pflog.Removed); !ok {
		t.Errorf("Message type = %T, want Removed", r.Message)
	}
}

func TestParse_QueueID_NOQUEUE(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtpd[1]: NOQUEUE: reject: RCPT from unknown[10.0.0.1]: 550 5.1.1 <x@y.z>: Recipient address rejected`
	r := mustParse(t, line)
	if r.QueueID != "NOQUEUE" {
		t.Errorf("QueueID = %q, want %q", r.QueueID, "NOQUEUE")
	}
	if _, ok := r.Message.(pflog.Reject); !ok {
		t.Errorf("Message type = %T, want Reject", r.Message)
	}
}

func TestParse_QueueID_Absent(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtpd[1]: connect from unknown[10.0.0.1]`
	r := mustParse(t, line)
	if r.QueueID != "" {
		t.Errorf("QueueID = %q, want empty string", r.QueueID)
	}
}

// ---- Connect ----------------------------------------------------------------

func TestParse_Connect(t *testing.T) {
	cases := []struct {
		line     string
		hostname string
		ip       string
	}{
		{
			`Mar 29 12:34:56 host postfix/smtpd[1]: connect from unknown[192.168.1.1]`,
			"unknown", "192.168.1.1",
		},
		{
			`Mar 29 12:34:56 host postfix/smtpd[1]: connect from mail.example.com[203.0.113.10]`,
			"mail.example.com", "203.0.113.10",
		},
		{
			// IPv6 address
			`Mar 29 12:34:56 host postfix/smtpd[1]: connect from host[2001:db8::1]`,
			"host", "2001:db8::1",
		},
	}
	for _, tc := range cases {
		r := mustParse(t, tc.line)
		conn, ok := r.Message.(pflog.Connect)
		if !ok {
			t.Errorf("Parse(%q) Message type = %T, want Connect", tc.line, r.Message)
			continue
		}
		if conn.Hostname != tc.hostname {
			t.Errorf("Connect.Hostname = %q, want %q", conn.Hostname, tc.hostname)
		}
		if conn.IP != tc.ip {
			t.Errorf("Connect.IP = %q, want %q", conn.IP, tc.ip)
		}
	}
}

// ---- Disconnect -------------------------------------------------------------

func TestParse_Disconnect_WithStats(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtpd[1]: disconnect from unknown[10.0.0.1] ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5`
	r := mustParse(t, line)

	disc, ok := r.Message.(pflog.Disconnect)
	if !ok {
		t.Fatalf("Message type = %T, want Disconnect", r.Message)
	}
	if disc.Hostname != "unknown" {
		t.Errorf("Disconnect.Hostname = %q, want %q", disc.Hostname, "unknown")
	}
	if disc.IP != "10.0.0.1" {
		t.Errorf("Disconnect.IP = %q, want %q", disc.IP, "10.0.0.1")
	}
	wantStats := map[string]int{
		"ehlo":     1,
		"mail":     1,
		"rcpt":     1,
		"data":     1,
		"quit":     1,
		"commands": 5,
	}
	for k, want := range wantStats {
		if got := disc.Stats[k]; got != want {
			t.Errorf("Disconnect.Stats[%q] = %d, want %d", k, got, want)
		}
	}
}

func TestParse_Disconnect_NoStats(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtpd[1]: disconnect from mail.example.com[198.51.100.1]`
	r := mustParse(t, line)

	disc, ok := r.Message.(pflog.Disconnect)
	if !ok {
		t.Fatalf("Message type = %T, want Disconnect", r.Message)
	}
	if disc.Hostname != "mail.example.com" {
		t.Errorf("Disconnect.Hostname = %q, want %q", disc.Hostname, "mail.example.com")
	}
	if len(disc.Stats) != 0 {
		t.Errorf("Disconnect.Stats = %v, want empty map", disc.Stats)
	}
}

// ---- Queued (qmgr) ----------------------------------------------------------

func TestParse_Queued(t *testing.T) {
	cases := []struct {
		line  string
		from  string
		size  int
		nrcpt int
	}{
		{
			`Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: from=<sender@example.com>, size=12345, nrcpt=1 (queue active)`,
			"sender@example.com", 12345, 1,
		},
		{
			// empty sender (bounce message)
			`Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: from=<>, size=500, nrcpt=2 (queue active)`,
			"", 500, 2,
		},
	}
	for _, tc := range cases {
		r := mustParse(t, tc.line)
		q, ok := r.Message.(pflog.Queued)
		if !ok {
			t.Errorf("Parse(%q) Message type = %T, want Queued", tc.line, r.Message)
			continue
		}
		if q.From != tc.from {
			t.Errorf("Queued.From = %q, want %q", q.From, tc.from)
		}
		if q.Size != tc.size {
			t.Errorf("Queued.Size = %d, want %d", q.Size, tc.size)
		}
		if q.NRcpt != tc.nrcpt {
			t.Errorf("Queued.NRcpt = %d, want %d", q.NRcpt, tc.nrcpt)
		}
	}
}

// ---- Removed (qmgr) ---------------------------------------------------------

func TestParse_Removed(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: removed`
	r := mustParse(t, line)

	if _, ok := r.Message.(pflog.Removed); !ok {
		t.Errorf("Message type = %T, want Removed", r.Message)
	}
}

// ---- Cleanup ----------------------------------------------------------------

func TestParse_Cleanup(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/cleanup[1]: ABCDE12345: message-id=<unique@mail.example.com>`
	r := mustParse(t, line)

	c, ok := r.Message.(pflog.Cleanup)
	if !ok {
		t.Fatalf("Message type = %T, want Cleanup", r.Message)
	}
	if c.MessageID != "unique@mail.example.com" {
		t.Errorf("Cleanup.MessageID = %q, want %q", c.MessageID, "unique@mail.example.com")
	}
}

// ---- Delivery ---------------------------------------------------------------

func TestParse_Delivery_Sent(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtp[1]: ABCDE12345: to=<user@example.com>, relay=mail.example.com[203.0.113.1]:25, delay=0.5, delays=0.1/0.0/0.1/0.3, dsn=2.0.0, status=sent (250 2.0.0 OK)`
	r := mustParse(t, line)

	d, ok := r.Message.(pflog.Delivery)
	if !ok {
		t.Fatalf("Message type = %T, want Delivery", r.Message)
	}
	if d.To != "user@example.com" {
		t.Errorf("Delivery.To = %q, want %q", d.To, "user@example.com")
	}
	if d.Relay != "mail.example.com[203.0.113.1]:25" {
		t.Errorf("Delivery.Relay = %q, want %q", d.Relay, "mail.example.com[203.0.113.1]:25")
	}
	if d.Delay != "0.5" {
		t.Errorf("Delivery.Delay = %q, want %q", d.Delay, "0.5")
	}
	if d.Delays != "0.1/0.0/0.1/0.3" {
		t.Errorf("Delivery.Delays = %q, want %q", d.Delays, "0.1/0.0/0.1/0.3")
	}
	if d.DSN != "2.0.0" {
		t.Errorf("Delivery.DSN = %q, want %q", d.DSN, "2.0.0")
	}
	if d.Status != pflog.StatusSent {
		t.Errorf("Delivery.Status = %q, want %q", d.Status, pflog.StatusSent)
	}
	if d.Detail != "250 2.0.0 OK" {
		t.Errorf("Delivery.Detail = %q, want %q", d.Detail, "250 2.0.0 OK")
	}
}

func TestParse_Delivery_Deferred(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtp[1]: ABCDE12345: to=<user@example.com>, relay=mail.example.com[203.0.113.1]:25, delay=30, delays=0.1/0.0/29/0.4, dsn=4.1.1, status=deferred (connect to mail.example.com[203.0.113.1]:25: Connection refused)`
	r := mustParse(t, line)

	d, ok := r.Message.(pflog.Delivery)
	if !ok {
		t.Fatalf("Message type = %T, want Delivery", r.Message)
	}
	if d.Status != pflog.StatusDeferred {
		t.Errorf("Delivery.Status = %q, want %q", d.Status, pflog.StatusDeferred)
	}
	if d.Detail != "connect to mail.example.com[203.0.113.1]:25: Connection refused" {
		t.Errorf("Delivery.Detail = %q", d.Detail)
	}
}

func TestParse_Delivery_Bounced(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtp[1]: ABCDE12345: to=<nouser@example.com>, relay=mail.example.com[203.0.113.1]:25, delay=1.2, delays=0.1/0.0/0.3/0.8, dsn=5.1.1, status=bounced (host mail.example.com[203.0.113.1] said: 550 5.1.1 Unknown user)`
	r := mustParse(t, line)

	d, ok := r.Message.(pflog.Delivery)
	if !ok {
		t.Fatalf("Message type = %T, want Delivery", r.Message)
	}
	if d.Status != pflog.StatusBounced {
		t.Errorf("Delivery.Status = %q, want %q", d.Status, pflog.StatusBounced)
	}
}

func TestParse_Delivery_LocalRelay(t *testing.T) {
	// Local delivery uses relay=none.
	line := `Mar 29 12:34:56 host postfix/local[1]: ABCDE12345: to=<localuser@example.com>, relay=local, delay=0.1, delays=0.1/0.0/0.0/0.0, dsn=2.0.0, status=sent (delivered to mailbox)`
	r := mustParse(t, line)

	d, ok := r.Message.(pflog.Delivery)
	if !ok {
		t.Fatalf("Message type = %T, want Delivery", r.Message)
	}
	if d.Relay != "local" {
		t.Errorf("Delivery.Relay = %q, want %q", d.Relay, "local")
	}
	if d.Status != pflog.StatusSent {
		t.Errorf("Delivery.Status = %q, want %q", d.Status, pflog.StatusSent)
	}
	if d.Detail != "delivered to mailbox" {
		t.Errorf("Delivery.Detail = %q, want %q", d.Detail, "delivered to mailbox")
	}
}

// ---- Reject -----------------------------------------------------------------

func TestParse_Reject(t *testing.T) {
	cases := []struct {
		line           string
		stage          string
		clientHostname string
		clientIP       string
		code           int
		detail         string
	}{
		{
			`Mar 29 12:34:56 host postfix/smtpd[1]: NOQUEUE: reject: RCPT from unknown[10.0.0.1]: 550 5.1.1 <x@y.z>: Recipient address rejected`,
			"RCPT", "unknown", "10.0.0.1", 550, "5.1.1 <x@y.z>: Recipient address rejected",
		},
		{
			`Mar 29 12:34:56 host postfix/smtpd[1]: ABCDEF1234: reject: DATA from mail.example.com[198.51.100.1]: 552 5.3.4 Message size exceeds fixed limit`,
			"DATA", "mail.example.com", "198.51.100.1", 552, "5.3.4 Message size exceeds fixed limit",
		},
	}
	for _, tc := range cases {
		r := mustParse(t, tc.line)
		rej, ok := r.Message.(pflog.Reject)
		if !ok {
			t.Errorf("Parse(%q) Message type = %T, want Reject", tc.line, r.Message)
			continue
		}
		if rej.Stage != tc.stage {
			t.Errorf("Reject.Stage = %q, want %q", rej.Stage, tc.stage)
		}
		if rej.ClientHostname != tc.clientHostname {
			t.Errorf("Reject.ClientHostname = %q, want %q", rej.ClientHostname, tc.clientHostname)
		}
		if rej.ClientIP != tc.clientIP {
			t.Errorf("Reject.ClientIP = %q, want %q", rej.ClientIP, tc.clientIP)
		}
		if rej.Code != tc.code {
			t.Errorf("Reject.Code = %d, want %d", rej.Code, tc.code)
		}
		if rej.Detail != tc.detail {
			t.Errorf("Reject.Detail = %q, want %q", rej.Detail, tc.detail)
		}
	}
}

// ---- BounceNotification -----------------------------------------------------

func TestParse_BounceNotification(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/bounce[1]: ABCDE12345: sender non-delivery notification: F0123456789`
	r := mustParse(t, line)

	bn, ok := r.Message.(pflog.BounceNotification)
	if !ok {
		t.Fatalf("Message type = %T, want BounceNotification", r.Message)
	}
	if bn.BounceQueueID != "F0123456789" {
		t.Errorf("BounceNotification.BounceQueueID = %q, want %q", bn.BounceQueueID, "F0123456789")
	}
}

// ---- Warning ----------------------------------------------------------------

func TestParse_Warning(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/cleanup[1]: ABCDE12345: warning: header Subject: spam? from local; from=<x@y.z>`
	r := mustParse(t, line)

	w, ok := r.Message.(pflog.Warning)
	if !ok {
		t.Fatalf("Message type = %T, want Warning", r.Message)
	}
	want := "header Subject: spam? from local; from=<x@y.z>"
	if w.Text != want {
		t.Errorf("Warning.Text = %q, want %q", w.Text, want)
	}
}

// ---- Unknown ----------------------------------------------------------------

func TestParse_Unknown(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtpd[1]: some unparsed smtpd message text`
	r := mustParse(t, line)

	u, ok := r.Message.(pflog.Unknown)
	if !ok {
		t.Fatalf("Message type = %T, want Unknown", r.Message)
	}
	if u.Text == "" {
		t.Error("Unknown.Text is empty, want non-empty text")
	}
}

func TestParse_Unknown_AfterQueueID(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtpd[1]: ABCDE12345: some unrecognized payload`
	r := mustParse(t, line)

	u, ok := r.Message.(pflog.Unknown)
	if !ok {
		t.Fatalf("Message type = %T, want Unknown", r.Message)
	}
	if u.Text != "some unrecognized payload" {
		t.Errorf("Unknown.Text = %q, want %q", u.Text, "some unrecognized payload")
	}
}

// ---- Scanner ----------------------------------------------------------------

func TestScanner_MultipleParsedLines(t *testing.T) {
	input := strings.Join([]string{
		`Mar 29 12:34:56 host postfix/smtpd[1]: connect from unknown[10.0.0.1]`,
		`Mar 29 12:34:57 host postfix/qmgr[2]: ABCDE12345: from=<s@example.com>, size=100, nrcpt=1 (queue active)`,
		`Mar 29 12:34:58 host postfix/smtp[3]: ABCDE12345: to=<r@example.com>, relay=mx[10.0.0.2]:25, delay=0.1, delays=0/0/0/0.1, dsn=2.0.0, status=sent (250 OK)`,
		`Mar 29 12:34:59 host postfix/qmgr[2]: ABCDE12345: removed`,
	}, "\n")

	s := pflog.NewScanner(strings.NewReader(input))

	var records []*pflog.Record
	for s.Scan() {
		records = append(records, s.Record())
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Scanner.Err() = %v, want nil", err)
	}
	if len(records) != 4 {
		t.Fatalf("scanned %d records, want 4", len(records))
	}

	if _, ok := records[0].Message.(pflog.Connect); !ok {
		t.Errorf("records[0].Message type = %T, want Connect", records[0].Message)
	}
	if _, ok := records[1].Message.(pflog.Queued); !ok {
		t.Errorf("records[1].Message type = %T, want Queued", records[1].Message)
	}
	if _, ok := records[2].Message.(pflog.Delivery); !ok {
		t.Errorf("records[2].Message type = %T, want Delivery", records[2].Message)
	}
	if _, ok := records[3].Message.(pflog.Removed); !ok {
		t.Errorf("records[3].Message type = %T, want Removed", records[3].Message)
	}
}

func TestScanner_SkipsInvalidLines(t *testing.T) {
	input := strings.Join([]string{
		`this is not a syslog line`,
		``,
		`Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: removed`,
		`another garbage line`,
		`Mar 29 12:34:57 host postfix/smtpd[2]: connect from unknown[1.2.3.4]`,
	}, "\n")

	s := pflog.NewScanner(strings.NewReader(input))

	var count int
	for s.Scan() {
		count++
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Scanner.Err() = %v", err)
	}
	if count != 2 {
		t.Errorf("scanned %d records, want 2", count)
	}
}

func TestScanner_Empty(t *testing.T) {
	s := pflog.NewScanner(strings.NewReader(""))
	if s.Scan() {
		t.Error("Scan() = true on empty input, want false")
	}
	if err := s.Err(); err != nil {
		t.Errorf("Err() = %v, want nil", err)
	}
}

// ---- Benchmarks -------------------------------------------------------------

var benchLines = []string{
	`Mar 29 12:34:56 host postfix/smtpd[1]: connect from mail.example.com[203.0.113.10]`,
	`Mar 29 12:34:56 host postfix/smtpd[1]: disconnect from unknown[10.0.0.1] ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5`,
	`Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: from=<sender@example.com>, size=12345, nrcpt=1 (queue active)`,
	`Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: removed`,
	`Mar 29 12:34:56 host postfix/cleanup[1]: ABCDE12345: message-id=<unique@mail.example.com>`,
	`Mar 29 12:34:56 host postfix/smtp[1]: ABCDE12345: to=<user@example.com>, relay=mail.example.com[203.0.113.1]:25, delay=0.5, delays=0.1/0.0/0.1/0.3, dsn=2.0.0, status=sent (250 2.0.0 OK)`,
	`Mar 29 12:34:56 host postfix/smtpd[1]: NOQUEUE: reject: RCPT from unknown[10.0.0.1]: 550 5.1.1 <x@y.z>: Recipient address rejected`,
	`Mar 29 12:34:56 host postfix/bounce[1]: ABCDE12345: sender non-delivery notification: F0123456789`,
	`Mar 29 12:34:56 host postfix/cleanup[1]: ABCDE12345: warning: header Subject: spam? from local; from=<x@y.z>`,
	`Mar 29 12:34:56 host postfix/smtpd[1]: some unparsed smtpd message text`,
}

func BenchmarkParse_Connect(b *testing.B) {
	line := `Mar 29 12:34:56 host postfix/smtpd[1]: connect from mail.example.com[203.0.113.10]`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pflog.Parse(line) //nolint:errcheck
	}
}

func BenchmarkParse_Disconnect(b *testing.B) {
	line := `Mar 29 12:34:56 host postfix/smtpd[1]: disconnect from unknown[10.0.0.1] ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pflog.Parse(line) //nolint:errcheck
	}
}

func BenchmarkParse_Queued(b *testing.B) {
	line := `Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: from=<sender@example.com>, size=12345, nrcpt=1 (queue active)`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pflog.Parse(line) //nolint:errcheck
	}
}

func BenchmarkParse_Delivery(b *testing.B) {
	line := `Mar 29 12:34:56 host postfix/smtp[1]: ABCDE12345: to=<user@example.com>, relay=mail.example.com[203.0.113.1]:25, delay=0.5, delays=0.1/0.0/0.1/0.3, dsn=2.0.0, status=sent (250 2.0.0 OK)`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pflog.Parse(line) //nolint:errcheck
	}
}

func BenchmarkParse_Reject(b *testing.B) {
	line := `Mar 29 12:34:56 host postfix/smtpd[1]: NOQUEUE: reject: RCPT from unknown[10.0.0.1]: 550 5.1.1 <x@y.z>: Recipient address rejected`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pflog.Parse(line) //nolint:errcheck
	}
}

func BenchmarkParse_Unknown(b *testing.B) {
	line := `Mar 29 12:34:56 host postfix/smtpd[1]: some unparsed smtpd message text`
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pflog.Parse(line) //nolint:errcheck
	}
}

func BenchmarkScanner(b *testing.B) {
	input := strings.Join(benchLines, "\n")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := pflog.NewScanner(strings.NewReader(input))
		for s.Scan() {
		}
	}
}

// ---- DeliveryStatus constants -----------------------------------------------

func TestDeliveryStatusConstants(t *testing.T) {
	cases := []struct {
		status pflog.DeliveryStatus
		want   string
	}{
		{pflog.StatusSent, "sent"},
		{pflog.StatusBounced, "bounced"},
		{pflog.StatusDeferred, "deferred"},
		{pflog.StatusExpired, "expired"},
	}
	for _, tc := range cases {
		if string(tc.status) != tc.want {
			t.Errorf("DeliveryStatus %q, want %q", tc.status, tc.want)
		}
	}
}
