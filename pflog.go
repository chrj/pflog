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

// monthNames maps 0–11 to the BSD syslog month abbreviations used by Postfix.
var monthNames = [12]string{
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
}

// FormatError is returned by [Parse] when the input line does not conform to
// the expected BSD syslog format.
type FormatError struct {
	// Line is the full input line that failed to parse.
	Line string
	// Reason is a short description of what part of the format was not
	// recognised (e.g., "line too short", "missing hostname",
	// "missing PID bracket", "missing message separator").
	Reason string
}

func (e *FormatError) Error() string {
	return fmt.Sprintf("pflog: invalid syslog format (%s): %q", e.Reason, e.Line)
}

// TimestampError is returned by [Parse] when the timestamp portion of the
// input line cannot be parsed. The underlying parse error is accessible via
// [errors.Unwrap].
type TimestampError struct {
	// Timestamp is the raw timestamp string that failed to parse.
	Timestamp string
	// Err is the underlying parse error.
	Err error
}

func (e *TimestampError) Error() string {
	return fmt.Sprintf("pflog: invalid timestamp %q: %s", e.Timestamp, e.Err)
}

// Unwrap returns the underlying timestamp parse error.
func (e *TimestampError) Unwrap() error { return e.Err }

// PIDError is returned by [Parse] when the PID field cannot be parsed as an
// integer. The underlying parse error is accessible via [errors.Unwrap].
type PIDError struct {
	// PID is the raw PID string that failed to parse.
	PID string
	// Err is the underlying parse error.
	Err error
}

func (e *PIDError) Error() string {
	return fmt.Sprintf("pflog: invalid PID %q: %s", e.PID, e.Err)
}

// Unwrap returns the underlying PID parse error.
func (e *PIDError) Unwrap() error { return e.Err }

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
	// The BSD syslog timestamp is always exactly 15 characters: "Mmm _D HH:MM:SS"
	const tsLen = 15
	if len(line) <= tsLen || line[tsLen] != ' ' {
		return nil, &FormatError{Line: line, Reason: "line too short"}
	}

	ts, err := parseTimestamp(line[:tsLen])
	if err != nil {
		return nil, &TimestampError{Timestamp: line[:tsLen], Err: err}
	}

	rest := line[tsLen+1:]

	// hostname is the next space-delimited token.
	spaceIdx := strings.IndexByte(rest, ' ')
	if spaceIdx < 0 {
		return nil, &FormatError{Line: line, Reason: "missing hostname"}
	}
	hostname := rest[:spaceIdx]
	rest = rest[spaceIdx+1:]

	// process[pid]: — find the "[" that opens the PID.
	bracketIdx := strings.IndexByte(rest, '[')
	if bracketIdx < 0 {
		return nil, &FormatError{Line: line, Reason: "missing PID bracket"}
	}
	processField := rest[:bracketIdx]
	rest = rest[bracketIdx+1:]

	// Find "]: " to delimit the PID and the message body.
	colonIdx := strings.Index(rest, "]: ")
	if colonIdx < 0 {
		return nil, &FormatError{Line: line, Reason: "missing message separator"}
	}
	pid, err := strconv.Atoi(rest[:colonIdx])
	if err != nil {
		return nil, &PIDError{PID: rest[:colonIdx], Err: err}
	}
	msg := rest[colonIdx+3:]

	// Extract the daemon name from "postfix/daemon" or a plain name.
	process := processField
	if idx := strings.LastIndexByte(processField, '/'); idx >= 0 {
		process = processField[idx+1:]
	}

	r := &Record{
		Time:     ts,
		Hostname: hostname,
		Process:  process,
		PID:      pid,
	}

	// Extract the queue ID prefix when present.
	if queueID, remainder, ok := extractQueueID(msg); ok {
		r.QueueID = queueID
		msg = remainder
	}

	r.Message = parseMessage(msg)
	return r, nil
}

// parseTimestamp parses a 15-character BSD syslog timestamp ("Jan  1 00:00:00")
// and returns a time.Time in UTC with the current year applied.
func parseTimestamp(s string) (time.Time, error) {
	if len(s) != 15 {
		return time.Time{}, fmt.Errorf("wrong length")
	}

	// Month: s[0:3]
	var month time.Month
	for i, name := range monthNames {
		if s[0] == name[0] && s[1] == name[1] && s[2] == name[2] {
			month = time.Month(i + 1)
			break
		}
	}
	if month == 0 {
		return time.Time{}, fmt.Errorf("unknown month")
	}

	if s[3] != ' ' {
		return time.Time{}, fmt.Errorf("expected space after month")
	}

	// Day: s[4:6], space-padded (e.g., " 1" or "29").
	day, ok := parsePaddedInt2(s[4], s[5])
	if !ok {
		return time.Time{}, fmt.Errorf("invalid day")
	}

	if s[6] != ' ' {
		return time.Time{}, fmt.Errorf("expected space after day")
	}

	hour, ok := parseInt2(s[7], s[8])
	if !ok {
		return time.Time{}, fmt.Errorf("invalid hour")
	}

	if s[9] != ':' {
		return time.Time{}, fmt.Errorf("expected ':' after hour")
	}

	min, ok := parseInt2(s[10], s[11])
	if !ok {
		return time.Time{}, fmt.Errorf("invalid minute")
	}

	if s[12] != ':' {
		return time.Time{}, fmt.Errorf("expected ':' after minute")
	}

	sec, ok := parseInt2(s[13], s[14])
	if !ok {
		return time.Time{}, fmt.Errorf("invalid second")
	}

	now := time.Now().UTC()
	return time.Date(now.Year(), month, day, hour, min, sec, 0, time.UTC), nil
}

// parsePaddedInt2 parses a space-or-digit followed by a digit (e.g., " 1" → 1, "29" → 29).
func parsePaddedInt2(a, b byte) (int, bool) {
	var tens int
	if a == ' ' {
		tens = 0
	} else if a >= '0' && a <= '9' {
		tens = int(a-'0') * 10
	} else {
		return 0, false
	}
	if b < '0' || b > '9' {
		return 0, false
	}
	return tens + int(b-'0'), true
}

// parseInt2 parses exactly two decimal digit bytes.
func parseInt2(a, b byte) (int, bool) {
	if a < '0' || a > '9' || b < '0' || b > '9' {
		return 0, false
	}
	return int(a-'0')*10 + int(b-'0'), true
}

// extractQueueID parses an optional Postfix queue ID prefix from msg.
// It recognises uppercase hex IDs (6–20 chars) and the literal "NOQUEUE".
func extractQueueID(msg string) (queueID, rest string, ok bool) {
	i := strings.Index(msg, ": ")
	if i < 0 {
		return "", "", false
	}
	prefix := msg[:i]
	if prefix == "NOQUEUE" {
		return prefix, msg[i+2:], true
	}
	if i < 6 || i > 20 {
		return "", "", false
	}
	for j := 0; j < i; j++ {
		c := msg[j]
		if (c < '0' || c > '9') && (c < 'A' || c > 'F') {
			return "", "", false
		}
	}
	return prefix, msg[i+2:], true
}

// parseMessage tries each known pattern in turn and returns the first match.
// It falls back to Unknown when nothing matches.
func parseMessage(msg string) Message {
	if m, ok := parseConnect(msg); ok {
		return m
	}
	if m, ok := parseDisconnect(msg); ok {
		return m
	}
	if msg == "removed" {
		return Removed{}
	}
	if m, ok := parseCleanup(msg); ok {
		return m
	}
	if m, ok := parseQueued(msg); ok {
		return m
	}
	if m, ok := parseDelivery(msg); ok {
		return m
	}
	if m, ok := parseReject(msg); ok {
		return m
	}
	if m, ok := parseBounce(msg); ok {
		return m
	}
	if m, ok := parseWarning(msg); ok {
		return m
	}
	return Unknown{Text: msg}
}

func parseConnect(msg string) (Connect, bool) {
	const prefix = "connect from "
	if !strings.HasPrefix(msg, prefix) {
		return Connect{}, false
	}
	rest := msg[len(prefix):]
	// hostname ends just before the last "["; IP is between "[" and trailing "]".
	bracketOpen := strings.LastIndexByte(rest, '[')
	if bracketOpen < 0 || rest[len(rest)-1] != ']' {
		return Connect{}, false
	}
	return Connect{
		Hostname: rest[:bracketOpen],
		IP:       rest[bracketOpen+1 : len(rest)-1],
	}, true
}

func parseDisconnect(msg string) (Disconnect, bool) {
	const prefix = "disconnect from "
	if !strings.HasPrefix(msg, prefix) {
		return Disconnect{}, false
	}
	rest := msg[len(prefix):]
	bracketOpen := strings.IndexByte(rest, '[')
	if bracketOpen < 0 {
		return Disconnect{}, false
	}
	closeOff := strings.IndexByte(rest[bracketOpen:], ']')
	if closeOff < 0 {
		return Disconnect{}, false
	}
	bracketClose := bracketOpen + closeOff
	var statsStr string
	if bracketClose+1 < len(rest) {
		statsStr = strings.TrimSpace(rest[bracketClose+1:])
	}
	return Disconnect{
		Hostname: rest[:bracketOpen],
		IP:       rest[bracketOpen+1 : bracketClose],
		Stats:    parseStats(statsStr),
	}, true
}

func parseCleanup(msg string) (Cleanup, bool) {
	const prefix = "message-id=<"
	if len(msg) <= len(prefix) || !strings.HasPrefix(msg, prefix) || msg[len(msg)-1] != '>' {
		return Cleanup{}, false
	}
	return Cleanup{MessageID: msg[len(prefix) : len(msg)-1]}, true
}

func parseQueued(msg string) (Queued, bool) {
	const fromPrefix = "from=<"
	if !strings.HasPrefix(msg, fromPrefix) {
		return Queued{}, false
	}
	rest := msg[len(fromPrefix):]

	gtIdx := strings.IndexByte(rest, '>')
	if gtIdx < 0 {
		return Queued{}, false
	}
	from := rest[:gtIdx]
	rest = rest[gtIdx+1:]

	const sizePrefix = ", size="
	if !strings.HasPrefix(rest, sizePrefix) {
		return Queued{}, false
	}
	rest = rest[len(sizePrefix):]

	commaIdx := strings.IndexByte(rest, ',')
	if commaIdx < 0 {
		return Queued{}, false
	}
	size, err := strconv.Atoi(rest[:commaIdx])
	if err != nil {
		return Queued{}, false
	}
	rest = rest[commaIdx+1:]

	const nrcptPrefix = " nrcpt="
	if !strings.HasPrefix(rest, nrcptPrefix) {
		return Queued{}, false
	}
	rest = rest[len(nrcptPrefix):]

	spaceIdx := strings.IndexByte(rest, ' ')
	if spaceIdx < 0 {
		return Queued{}, false
	}
	nrcpt, err := strconv.Atoi(rest[:spaceIdx])
	if err != nil {
		return Queued{}, false
	}
	return Queued{From: from, Size: size, NRcpt: nrcpt}, true
}

func parseDelivery(msg string) (Delivery, bool) {
	const toPrefix = "to=<"
	if !strings.HasPrefix(msg, toPrefix) {
		return Delivery{}, false
	}
	rest := msg[len(toPrefix):]

	i := strings.IndexByte(rest, '>')
	if i < 0 {
		return Delivery{}, false
	}
	to := rest[:i]
	rest = rest[i+1:]

	const relayPrefix = ", relay="
	if !strings.HasPrefix(rest, relayPrefix) {
		return Delivery{}, false
	}
	rest = rest[len(relayPrefix):]

	i = strings.IndexByte(rest, ',')
	if i < 0 {
		return Delivery{}, false
	}
	relay := strings.TrimSpace(rest[:i])
	rest = rest[i+1:]

	const delayPrefix = " delay="
	if !strings.HasPrefix(rest, delayPrefix) {
		return Delivery{}, false
	}
	rest = rest[len(delayPrefix):]

	i = strings.IndexByte(rest, ',')
	if i < 0 {
		return Delivery{}, false
	}
	delay := strings.TrimSpace(rest[:i])
	rest = rest[i+1:]

	const delaysPrefix = " delays="
	if !strings.HasPrefix(rest, delaysPrefix) {
		return Delivery{}, false
	}
	rest = rest[len(delaysPrefix):]

	i = strings.IndexByte(rest, ',')
	if i < 0 {
		return Delivery{}, false
	}
	delays := strings.TrimSpace(rest[:i])
	rest = rest[i+1:]

	const dsnPrefix = " dsn="
	if !strings.HasPrefix(rest, dsnPrefix) {
		return Delivery{}, false
	}
	rest = rest[len(dsnPrefix):]

	i = strings.IndexByte(rest, ',')
	if i < 0 {
		return Delivery{}, false
	}
	dsn := strings.TrimSpace(rest[:i])
	rest = rest[i+1:]

	const statusPrefix = " status="
	if !strings.HasPrefix(rest, statusPrefix) {
		return Delivery{}, false
	}
	rest = rest[len(statusPrefix):]

	i = strings.Index(rest, " (")
	if i < 0 {
		return Delivery{}, false
	}
	status := rest[:i]
	rest = rest[i+2:]

	if len(rest) == 0 || rest[len(rest)-1] != ')' {
		return Delivery{}, false
	}
	detail := rest[:len(rest)-1]

	return Delivery{
		To:     to,
		Relay:  relay,
		Delay:  delay,
		Delays: delays,
		DSN:    dsn,
		Status: DeliveryStatus(status),
		Detail: detail,
	}, true
}

func parseReject(msg string) (Reject, bool) {
	const rejectPrefix = "reject: "
	if !strings.HasPrefix(msg, rejectPrefix) {
		return Reject{}, false
	}
	rest := msg[len(rejectPrefix):]

	// Stage is the first word.
	i := strings.IndexByte(rest, ' ')
	if i < 0 {
		return Reject{}, false
	}
	stage := rest[:i]
	rest = rest[i+1:]

	const fromPrefix = "from "
	if !strings.HasPrefix(rest, fromPrefix) {
		return Reject{}, false
	}
	rest = rest[len(fromPrefix):]

	// "hostname[ip]: code detail"
	bracketOpen := strings.IndexByte(rest, '[')
	if bracketOpen < 0 {
		return Reject{}, false
	}
	clientHostname := rest[:bracketOpen]
	rest = rest[bracketOpen+1:]

	bracketClose := strings.IndexByte(rest, ']')
	if bracketClose < 0 {
		return Reject{}, false
	}
	clientIP := rest[:bracketClose]
	rest = rest[bracketClose+1:]

	const colonPrefix = ": "
	if !strings.HasPrefix(rest, colonPrefix) {
		return Reject{}, false
	}
	rest = rest[len(colonPrefix):]

	i = strings.IndexByte(rest, ' ')
	if i < 0 {
		return Reject{}, false
	}
	code, err := strconv.Atoi(rest[:i])
	if err != nil {
		return Reject{}, false
	}

	return Reject{
		Stage:          stage,
		ClientHostname: clientHostname,
		ClientIP:       clientIP,
		Code:           code,
		Detail:         rest[i+1:],
	}, true
}

func parseBounce(msg string) (BounceNotification, bool) {
	const prefix = "sender non-delivery notification: "
	if !strings.HasPrefix(msg, prefix) {
		return BounceNotification{}, false
	}
	return BounceNotification{BounceQueueID: msg[len(prefix):]}, true
}

func parseWarning(msg string) (Warning, bool) {
	const prefix = "warning: "
	if !strings.HasPrefix(msg, prefix) {
		return Warning{}, false
	}
	return Warning{Text: msg[len(prefix):]}, true
}

// parseStats parses space-separated "key=value" pairs such as
// "ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5".
// Non-integer values are silently ignored.
// Returns nil when s is empty.
func parseStats(s string) map[string]int {
	if s == "" {
		return nil
	}
	stats := make(map[string]int)
	for s != "" {
		var part string
		if i := strings.IndexByte(s, ' '); i >= 0 {
			part, s = s[:i], s[i+1:]
		} else {
			part, s = s, ""
		}
		if i := strings.IndexByte(part, '='); i >= 0 {
			if v, err := strconv.Atoi(part[i+1:]); err == nil {
				stats[part[:i]] = v
			}
		}
	}
	return stats
}

// Scanner reads Postfix log [Record]s from an [io.Reader] one line at a time.
// Lines that do not match the expected syslog format are silently skipped,
// making it safe to use on mixed syslog files.
//
// To be notified when a line is skipped due to a parse error, register a
// callback with [Scanner.SetErrorHandler] before calling [Scanner.Scan].
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
	s        *bufio.Scanner
	record   *Record
	err      error
	onError  func(line string, err error)
}

// NewScanner returns a new Scanner that reads from r.
func NewScanner(r io.Reader) *Scanner {
	return &Scanner{s: bufio.NewScanner(r)}
}

// SetErrorHandler registers fn to be called whenever a line is skipped
// because it cannot be parsed as a Postfix log entry. fn receives the raw
// line and the parse error. Passing nil clears a previously set handler.
// SetErrorHandler must be called before the first call to [Scanner.Scan].
func (s *Scanner) SetErrorHandler(fn func(line string, err error)) {
	s.onError = fn
}

// Scan advances the scanner to the next record and returns true if one is
// available. It returns false at the end of input or on a read error. Lines
// that cannot be parsed as Postfix entries are silently skipped; register an
// error handler with [Scanner.SetErrorHandler] to observe those errors.
func (s *Scanner) Scan() bool {
	for s.s.Scan() {
		line := s.s.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		r, err := Parse(line)
		if err != nil {
			if s.onError != nil {
				s.onError(line, err)
			}
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
