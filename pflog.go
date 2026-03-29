// Package pflog parses Postfix mail log entries.
//
// It supports the standard BSD syslog format used by Postfix:
//
//	Jan  1 00:00:00 hostname postfix/process[pid]: message
//
// Use [Parse] to parse individual log lines, or [Scanner] to iterate over
// records from an [io.Reader].
//
// Each parsed entry is returned as a [Record] whose [Record.Message] field
// contains one of the concrete message types:
// [Connect], [Disconnect], [Queued], [Removed], [Cleanup], [Delivery],
// [Reject], [BounceNotification], [Warning], or [Unknown].
package pflog

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DeliveryStatus is the final disposition of a delivery attempt.
type DeliveryStatus string

const (
	// StatusSent indicates the message was successfully delivered.
	StatusSent DeliveryStatus = "sent"
	// StatusBounced indicates the message was returned to the sender.
	StatusBounced DeliveryStatus = "bounced"
	// StatusDeferred indicates delivery was temporarily deferred.
	StatusDeferred DeliveryStatus = "deferred"
	// StatusExpired indicates the message exceeded the maximum queue lifetime.
	StatusExpired DeliveryStatus = "expired"
)

// Record is a parsed Postfix log entry.
type Record struct {
	// Time is the log entry timestamp. Because the BSD syslog format omits the
	// year, it is set to the current UTC year at parse time. Logs that span a
	// year boundary (e.g., December entries parsed in January) will receive an
	// incorrect year.
	Time time.Time
	// Hostname is the name of the host that produced the log entry.
	Hostname string
	// Process is the Postfix daemon that produced the entry (e.g., "smtpd",
	// "smtp", "qmgr").
	Process string
	// PID is the process identifier.
	PID int
	// QueueID is the Postfix message queue ID, if present.
	QueueID string
	// Message is the parsed message payload. Use a type switch or type
	// assertion to access the concrete type.
	Message Message
}

// Message is the interface implemented by all specific log message types.
// Use a type switch to distinguish between concrete types.
type Message interface {
	isMessage()
}

// Connect is produced by smtpd when a client connects.
type Connect struct {
	// Hostname is the connecting client's reported hostname (may be "unknown").
	Hostname string
	// IP is the connecting client's IP address.
	IP string
}

func (Connect) isMessage() {}

// Disconnect is produced by smtpd when a client disconnects.
type Disconnect struct {
	// Hostname is the client's reported hostname (may be "unknown").
	Hostname string
	// IP is the client's IP address.
	IP string
	// Stats contains per-command counts reported at disconnect
	// (e.g., {"ehlo": 1, "mail": 1, "rcpt": 1, "commands": 3}).
	Stats map[string]int
}

func (Disconnect) isMessage() {}

// Queued is produced by qmgr when a message enters the active queue.
type Queued struct {
	// From is the envelope sender address (empty for bounce messages).
	From string
	// Size is the message size in bytes.
	Size int
	// NRcpt is the number of recipients.
	NRcpt int
}

func (Queued) isMessage() {}

// Removed is produced by qmgr when a message is removed from the queue.
type Removed struct{}

func (Removed) isMessage() {}

// Cleanup is produced by the cleanup daemon and carries the Message-Id header.
type Cleanup struct {
	// MessageID is the value of the Message-Id header (without angle brackets).
	MessageID string
}

func (Cleanup) isMessage() {}

// Delivery is produced by smtp, local, virtual, lmtp, or pipe for each
// recipient delivery attempt.
type Delivery struct {
	// To is the recipient envelope address.
	To string
	// Relay is the relay host used for delivery (e.g., "mail.example.com[1.2.3.4]:25",
	// "local", or "none").
	Relay string
	// Delay is the total message delay as reported by Postfix.
	Delay string
	// Delays is the per-stage delay breakdown (queuing/connection/setup/data).
	Delays string
	// DSN is the delivery status notification code (e.g., "2.0.0").
	DSN string
	// Status is the delivery outcome.
	Status DeliveryStatus
	// Detail is the SMTP response or error detail.
	Detail string
}

func (Delivery) isMessage() {}

// Reject is produced when a message or connection is rejected.
type Reject struct {
	// Stage is the SMTP stage where rejection occurred (e.g., "RCPT", "DATA").
	Stage string
	// ClientHostname is the rejecting client's hostname (may be "unknown").
	ClientHostname string
	// ClientIP is the rejecting client's IP address.
	ClientIP string
	// Code is the SMTP rejection code (e.g., 550).
	Code int
	// Detail is the full rejection reason.
	Detail string
}

func (Reject) isMessage() {}

// BounceNotification is produced by the bounce daemon when a non-delivery
// report is generated.
type BounceNotification struct {
	// BounceQueueID is the queue ID of the bounce notification message.
	BounceQueueID string
}

func (BounceNotification) isMessage() {}

// Warning is a generic warning entry from any Postfix daemon.
type Warning struct {
	// Text is the warning message text.
	Text string
}

func (Warning) isMessage() {}

// Unknown represents a log message that could not be parsed into a specific
// type. The raw message text is preserved in Text.
type Unknown struct {
	// Text is the raw message text after any queue ID prefix.
	Text string
}

func (Unknown) isMessage() {}

// compiled regular expressions used by Parse.
var (
	// syslogRe matches the BSD syslog header produced by Postfix:
	//   "Jan  1 00:00:00 hostname postfix/daemon[pid]: message"
	syslogRe = regexp.MustCompile(
		`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([\w./-]+)\[(\d+)\]:\s+(.*)$`,
	)

	// queueIDRe matches an optional Postfix queue ID prefix:
	//   "QUEUEID: rest"  or  "NOQUEUE: rest"
	queueIDRe = regexp.MustCompile(`^([0-9A-F]{6,20}|NOQUEUE):\s+(.*)$`)

	// connectRe matches: "connect from hostname[ip]"
	connectRe = regexp.MustCompile(`^connect from (\S+)\[([^\]]+)\]$`)

	// disconnectRe matches: "disconnect from hostname[ip] [stats…]"
	disconnectRe = regexp.MustCompile(`^disconnect from (\S+)\[([^\]]+)\](.*)$`)

	// queuedRe matches the qmgr active-queue entry:
	//   "from=<addr>, size=N, nrcpt=N (queue active)"
	queuedRe = regexp.MustCompile(`^from=<([^>]*)>,\s+size=(\d+),\s+nrcpt=(\d+)\s+\(`)

	// removedRe matches the qmgr removal message.
	removedRe = regexp.MustCompile(`^removed$`)

	// cleanupRe matches: "message-id=<value>"
	cleanupRe = regexp.MustCompile(`^message-id=<([^>]*)>$`)

	// deliveryRe matches smtp/local/virtual/lmtp/pipe delivery lines:
	//   "to=<addr>, relay=host, delay=N, delays=N, dsn=N, status=word (detail)"
	deliveryRe = regexp.MustCompile(
		`^to=<([^>]*)>,\s+relay=([^,]+),\s+delay=([^,]+),\s+delays=([^,]+),\s+dsn=([^,]+),\s+status=(\w+)\s+\((.+)\)$`,
	)

	// rejectRe matches rejection messages:
	//   "reject: STAGE from hostname[ip]: code detail"
	rejectRe = regexp.MustCompile(`^reject:\s+(\w+)\s+from\s+(\S+)\[([^\]]+)\]:\s+(\d+)\s+(.+)$`)

	// bounceRe matches the bounce daemon notification:
	//   "sender non-delivery notification: QUEUEID"
	bounceRe = regexp.MustCompile(`^sender non-delivery notification:\s+([0-9A-F]+)$`)

	// warningRe matches: "warning: text"
	warningRe = regexp.MustCompile(`^warning:\s+(.+)$`)
)

// Parse parses a single Postfix log line and returns a [Record].
//
// The line must be in the standard BSD syslog format:
//
//	Jan  1 00:00:00 hostname postfix/process[pid]: message
//
// An error is returned when the line does not match the expected syslog
// header. If the message body cannot be parsed into a specific type, the
// [Record.Message] field is set to [Unknown] and no error is returned.
func Parse(line string) (*Record, error) {
	m := syslogRe.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("pflog: invalid syslog format: %q", line)
	}

	ts, err := parseTimestamp(m[1])
	if err != nil {
		return nil, fmt.Errorf("pflog: invalid timestamp %q: %w", m[1], err)
	}

	pid, err := strconv.Atoi(m[4])
	if err != nil {
		return nil, fmt.Errorf("pflog: invalid PID %q: %w", m[4], err)
	}

	// Extract the daemon name from "postfix/daemon" or a plain name.
	process := m[3]
	if idx := strings.LastIndex(process, "/"); idx >= 0 {
		process = process[idx+1:]
	}

	r := &Record{
		Time:     ts,
		Hostname: m[2],
		Process:  process,
		PID:      pid,
	}

	msg := m[5]

	// Extract the queue ID prefix when present.
	if qm := queueIDRe.FindStringSubmatch(msg); qm != nil {
		r.QueueID = qm[1]
		msg = qm[2]
	}

	r.Message = parseMessage(msg)
	return r, nil
}

// parseTimestamp parses a BSD syslog timestamp ("Jan  1 00:00:00") and
// returns a time.Time in UTC with the current year applied.
func parseTimestamp(s string) (time.Time, error) {
	t, err := time.Parse("Jan _2 15:04:05", s)
	if err != nil {
		return time.Time{}, err
	}
	now := time.Now().UTC()
	return time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.UTC), nil
}

// parseMessage tries each known pattern in turn and returns the first match.
// It falls back to Unknown when nothing matches.
func parseMessage(msg string) Message {
	if m := connectRe.FindStringSubmatch(msg); m != nil {
		return Connect{Hostname: m[1], IP: m[2]}
	}

	if m := disconnectRe.FindStringSubmatch(msg); m != nil {
		return Disconnect{
			Hostname: m[1],
			IP:       m[2],
			Stats:    parseStats(strings.TrimSpace(m[3])),
		}
	}

	if removedRe.MatchString(msg) {
		return Removed{}
	}

	if m := cleanupRe.FindStringSubmatch(msg); m != nil {
		return Cleanup{MessageID: m[1]}
	}

	if m := queuedRe.FindStringSubmatch(msg); m != nil {
		size, _ := strconv.Atoi(m[2])
		nrcpt, _ := strconv.Atoi(m[3])
		return Queued{From: m[1], Size: size, NRcpt: nrcpt}
	}

	if m := deliveryRe.FindStringSubmatch(msg); m != nil {
		return Delivery{
			To:     m[1],
			Relay:  strings.TrimSpace(m[2]),
			Delay:  strings.TrimSpace(m[3]),
			Delays: strings.TrimSpace(m[4]),
			DSN:    strings.TrimSpace(m[5]),
			Status: DeliveryStatus(m[6]),
			Detail: m[7],
		}
	}

	if m := rejectRe.FindStringSubmatch(msg); m != nil {
		code, _ := strconv.Atoi(m[4])
		return Reject{
			Stage:          m[1],
			ClientHostname: m[2],
			ClientIP:       m[3],
			Code:           code,
			Detail:         m[5],
		}
	}

	if m := bounceRe.FindStringSubmatch(msg); m != nil {
		return BounceNotification{BounceQueueID: m[1]}
	}

	if m := warningRe.FindStringSubmatch(msg); m != nil {
		return Warning{Text: m[1]}
	}

	return Unknown{Text: msg}
}

// parseStats parses space-separated "key=value" pairs such as
// "ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5".
// Non-integer values are silently ignored.
func parseStats(s string) map[string]int {
	stats := make(map[string]int)
	if s == "" {
		return stats
	}
	for _, part := range strings.Fields(s) {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			if v, err := strconv.Atoi(kv[1]); err == nil {
				stats[kv[0]] = v
			}
		}
	}
	return stats
}

// Scanner reads Postfix log [Record]s from an [io.Reader] one line at a time.
// Lines that do not match the expected syslog format are silently skipped,
// making it safe to use on mixed syslog files.
//
// Usage:
//
//	s := pflog.NewScanner(r)
//	for s.Scan() {
//	    rec := s.Record()
//	    // process rec…
//	}
//	if err := s.Err(); err != nil {
//	    log.Fatal(err)
//	}
type Scanner struct {
	s      *bufio.Scanner
	record *Record
	err    error
}

// NewScanner returns a new Scanner that reads from r.
func NewScanner(r io.Reader) *Scanner {
	return &Scanner{s: bufio.NewScanner(r)}
}

// Scan advances the scanner to the next record and returns true if one is
// available. It returns false at the end of input or on a read error. Lines
// that cannot be parsed as Postfix entries are silently skipped.
func (s *Scanner) Scan() bool {
	for s.s.Scan() {
		line := s.s.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		r, err := Parse(line)
		if err != nil {
			continue
		}
		s.record = r
		return true
	}
	s.err = s.s.Err()
	return false
}

// Record returns the most recent record parsed by [Scanner.Scan].
// The returned pointer is valid until the next call to [Scanner.Scan].
func (s *Scanner) Record() *Record {
	return s.record
}

// Err returns the first non-EOF read error encountered by the Scanner.
func (s *Scanner) Err() error {
	return s.err
}
