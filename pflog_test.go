package pflog_test

import (
	"errors"
	"fmt"
	"io"
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
	cases := []struct {
		name   string
		line   string
		reason string
	}{
		// Shorter than a timestamp and the space that must follow it.
		{"empty", "", "line too short"},
		{"timestamp only", "Jan  1 00:00:00", "line too short"},
		{"shorter than a timestamp", "Jan  1 00:00:0", "line too short"},

		// Long enough, but the 16th character is not a space. The line is
		// not too short: it does not hold a timestamp of the right shape.
		{"not a syslog line", "not a syslog line", "missing space after timestamp"},
		{"garbage", "random garbage data", "missing space after timestamp"},
		{"day is not padded", "Jan 1 00:00:00 hostname", "missing space after timestamp"},
		{"wrong separator", "Jan  1 00:00:00Xhost postfix/qmgr[1]: removed", "missing space after timestamp"},

		// Nothing at all after the timestamp.
		{"nothing after timestamp", "Jan 29 12:34:56 ", "missing hostname"},

		// A hostname, but nothing after it.
		{"hostname only", "Jan 29 12:34:56 host", "missing process field"},

		{"no PID bracket", "Jan 29 12:34:56 host postfix", "missing PID bracket"},
		{"no closing bracket", "Jan 29 12:34:56 host postfix/smtpd[1]", "missing message separator"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pflog.Parse(tc.line)
			if err == nil {
				t.Fatalf("Parse(%q) error = nil, want an error", tc.line)
			}
			var formatErr *pflog.FormatError
			if !errors.As(err, &formatErr) {
				t.Fatalf("error type = %T, want *pflog.FormatError", err)
			}
			if formatErr.Line != tc.line {
				t.Errorf("FormatError.Line = %q, want %q", formatErr.Line, tc.line)
			}
			if formatErr.Reason != tc.reason {
				t.Errorf("FormatError.Reason = %q, want %q", formatErr.Reason, tc.reason)
			}
			if !strings.Contains(formatErr.Error(), tc.reason) {
				t.Errorf("Error() = %q, want it to hold %q", formatErr.Error(), tc.reason)
			}
		})
	}
}

func TestParse_InvalidTimestamp(t *testing.T) {
	// A line with the right structure but a bad timestamp.
	line := "Xxx 99 99:99:99 host postfix/smtpd[1]: connect from host[1.2.3.4]"
	_, err := pflog.Parse(line)
	if err == nil {
		t.Fatalf("Parse(%q) error = nil, want an error", line)
	}
	var tsErr *pflog.TimestampError
	if !errors.As(err, &tsErr) {
		t.Fatalf("Parse(%q) error type = %T, want *pflog.TimestampError", line, err)
	}
	if tsErr.Timestamp == "" {
		t.Error("TimestampError.Timestamp is empty")
	}
	if tsErr.Err == nil {
		t.Error("TimestampError.Err is nil, want an underlying error")
	}
	if errors.Unwrap(err) == nil {
		t.Error("errors.Unwrap returned nil, want an underlying error")
	}
}

// time.Date normalises a value that is out of range, so an impossible
// timestamp would otherwise become a real time that is quietly wrong.
func TestParse_TimestampOutOfRange(t *testing.T) {
	cases := []struct {
		name string
		ts   string
	}{
		{"day 0", "Jan  0 00:00:00"},
		{"day 32", "Jan 32 00:00:00"},
		{"day 99", "Jan 99 00:00:00"},
		{"31 February", "Feb 31 00:00:00"},
		{"30 February", "Feb 30 00:00:00"},
		{"31 April", "Apr 31 00:00:00"},
		{"31 June", "Jun 31 00:00:00"},
		{"31 September", "Sep 31 00:00:00"},
		{"31 November", "Nov 31 00:00:00"},
		{"hour 24", "Jan  1 24:00:00"},
		{"hour 25", "Jan  1 25:00:00"},
		{"minute 60", "Jan  1 00:60:00"},
		{"second 60", "Jan  1 00:00:60"},
		{"all above range", "Jan  1 25:61:61"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := tc.ts + ` host postfix/qmgr[1]: ABCDE12345: removed`

			r, err := pflog.Parse(line)
			if err == nil {
				t.Fatalf("Parse(%q) error = nil, want an error; Time = %s",
					line, r.Time.Format(time.RFC3339))
			}
			var tsErr *pflog.TimestampError
			if !errors.As(err, &tsErr) {
				t.Fatalf("error type = %T, want *pflog.TimestampError", err)
			}
			if tsErr.Timestamp != tc.ts {
				t.Errorf("TimestampError.Timestamp = %q, want %q", tsErr.Timestamp, tc.ts)
			}
		})
	}
}

// The edge of each range must still parse. February gets 29 days, because the
// line does not carry a year and so a leap year cannot be ruled out.
func TestParse_TimestampRangeEdges(t *testing.T) {
	cases := []struct {
		name              string
		ts                string
		month             time.Month
		day, hr, min, sec int
	}{
		{"first second of January", "Jan  1 00:00:00", time.January, 1, 0, 0, 0},
		{"last day of January", "Jan 31 23:59:59", time.January, 31, 23, 59, 59},
		{"28 February", "Feb 28 12:00:00", time.February, 28, 12, 0, 0},
		{"30 April", "Apr 30 12:00:00", time.April, 30, 12, 0, 0},
		{"last day of December", "Dec 31 23:59:59", time.December, 31, 23, 59, 59},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := tc.ts + ` host postfix/qmgr[1]: ABCDE12345: removed`
			r := mustParse(t, line)
			assertTime(t, r.Time, tc.month, tc.day, tc.hr, tc.min, tc.sec)
		})
	}
}

// A line dated 29 February is legal: the line carries no year, so a leap year
// cannot be ruled out. Parse must accept it. The date it gives moves to
// 1 March when the year that Parse assumes is not a leap year, which is the
// known limit of the year that [Record.Time] documents.
func TestParse_TwentyNinthOfFebruaryIsAccepted(t *testing.T) {
	line := `Feb 29 12:00:00 host postfix/qmgr[1]: ABCDE12345: removed`

	r, err := pflog.Parse(line)
	if err != nil {
		t.Fatalf("Parse(%q) error = %v, want nil", line, err)
	}
	if _, ok := r.Message.(pflog.Removed); !ok {
		t.Errorf("Message type = %T, want Removed", r.Message)
	}
}

// ParseAt takes the year from a reference time, so the year is finally
// something a test can hold.
func TestParseAt_Year(t *testing.T) {
	cases := []struct {
		name string
		ts   string
		ref  time.Time
		want time.Time
	}{
		{
			name: "same year",
			ts:   "Mar 29 12:34:56",
			ref:  time.Date(2021, time.June, 1, 0, 0, 0, 0, time.UTC),
			want: time.Date(2021, time.March, 29, 12, 34, 56, 0, time.UTC),
		},
		{
			name: "a December line read in January takes the year before",
			ts:   "Dec 31 23:59:59",
			ref:  time.Date(2021, time.January, 3, 8, 0, 0, 0, time.UTC),
			want: time.Date(2020, time.December, 31, 23, 59, 59, 0, time.UTC),
		},
		{
			name: "a January line read in January keeps the year",
			ts:   "Jan  2 08:00:00",
			ref:  time.Date(2021, time.January, 3, 8, 0, 0, 0, time.UTC),
			want: time.Date(2021, time.January, 2, 8, 0, 0, 0, time.UTC),
		},
		{
			name: "an entry a few hours ahead keeps the year",
			ts:   "Jan  3 20:00:00",
			ref:  time.Date(2021, time.January, 3, 8, 0, 0, 0, time.UTC),
			want: time.Date(2021, time.January, 3, 20, 0, 0, 0, time.UTC),
		},
		{
			name: "an entry more than a day ahead takes the year before",
			ts:   "Jan  5 08:00:01",
			ref:  time.Date(2021, time.January, 3, 8, 0, 0, 0, time.UTC),
			want: time.Date(2020, time.January, 5, 8, 0, 1, 0, time.UTC),
		},
		{
			name: "an entry in the next year, hours after ref",
			ts:   "Jan  1 01:00:00",
			ref:  time.Date(2020, time.December, 31, 12, 0, 0, 0, time.UTC),
			want: time.Date(2021, time.January, 1, 1, 0, 0, 0, time.UTC),
		},
		{
			name: "an entry in the next year, a minute after ref",
			ts:   "Jan  1 00:30:00",
			ref:  time.Date(2020, time.December, 31, 23, 30, 0, 0, time.UTC),
			want: time.Date(2021, time.January, 1, 0, 30, 0, 0, time.UTC),
		},
		{
			name: "an entry in the next year, at the edge of the skew",
			ts:   "Jan  1 00:00:00",
			ref:  time.Date(2020, time.December, 31, 0, 0, 0, 0, time.UTC),
			want: time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "an entry in the next year, past the edge of the skew",
			ts:   "Jan  1 00:00:01",
			ref:  time.Date(2020, time.December, 30, 23, 59, 59, 0, time.UTC),
			want: time.Date(2020, time.January, 1, 0, 0, 1, 0, time.UTC),
		},
		{
			name: "a December entry with a reference on 31 December",
			ts:   "Dec 30 09:00:00",
			ref:  time.Date(2020, time.December, 31, 12, 0, 0, 0, time.UTC),
			want: time.Date(2020, time.December, 30, 9, 0, 0, 0, time.UTC),
		},
		{
			name: "29 February with a leap year reference",
			ts:   "Feb 29 12:00:00",
			ref:  time.Date(2020, time.June, 1, 0, 0, 0, 0, time.UTC),
			want: time.Date(2020, time.February, 29, 12, 0, 0, 0, time.UTC),
		},
		{
			name: "29 February takes the most recent leap year",
			ts:   "Feb 29 12:00:00",
			ref:  time.Date(2023, time.June, 1, 0, 0, 0, 0, time.UTC),
			want: time.Date(2020, time.February, 29, 12, 0, 0, 0, time.UTC),
		},
		{
			name: "a year divisible by 100 is not a leap year",
			ts:   "Feb 29 12:00:00",
			ref:  time.Date(1900, time.June, 1, 0, 0, 0, 0, time.UTC),
			want: time.Date(1896, time.February, 29, 12, 0, 0, 0, time.UTC),
		},
		{
			name: "a year divisible by 400 is a leap year",
			ts:   "Feb 29 12:00:00",
			ref:  time.Date(2000, time.June, 1, 0, 0, 0, 0, time.UTC),
			want: time.Date(2000, time.February, 29, 12, 0, 0, 0, time.UTC),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := tc.ts + ` host postfix/qmgr[1]: ABCDE12345: removed`

			r, err := pflog.ParseAt(line, tc.ref)
			if err != nil {
				t.Fatalf("ParseAt(%q) error = %v, want nil", line, err)
			}
			if !r.Time.Equal(tc.want) {
				t.Errorf("Time = %s, want %s",
					r.Time.Format(time.RFC3339), tc.want.Format(time.RFC3339))
			}
			if r.Time.Location() != time.UTC {
				t.Errorf("Time.Location = %v, want UTC", r.Time.Location())
			}
		})
	}
}

// A whole log that crosses a year boundary keeps its order when it is read
// with one reference time.
func TestParseAt_LogAcrossAYearBoundary(t *testing.T) {
	ref := time.Date(2021, time.January, 2, 12, 0, 0, 0, time.UTC)
	lines := []string{
		`Dec 30 09:00:00 host postfix/qmgr[1]: ABCDE12345: removed`,
		`Dec 31 23:59:59 host postfix/qmgr[1]: ABCDE12346: removed`,
		`Jan  1 00:00:01 host postfix/qmgr[1]: ABCDE12347: removed`,
		`Jan  2 11:00:00 host postfix/qmgr[1]: ABCDE12348: removed`,
	}

	var last time.Time
	for i, line := range lines {
		r, err := pflog.ParseAt(line, ref)
		if err != nil {
			t.Fatalf("ParseAt(%q) error = %v", line, err)
		}
		if i > 0 && !r.Time.After(last) {
			t.Errorf("line %d time %s is not after %s",
				i, r.Time.Format(time.RFC3339), last.Format(time.RFC3339))
		}
		last = r.Time
	}

	wantFirst := time.Date(2020, time.December, 30, 9, 0, 0, 0, time.UTC)
	r, _ := pflog.ParseAt(lines[0], ref)
	if !r.Time.Equal(wantFirst) {
		t.Errorf("first entry = %s, want %s",
			r.Time.Format(time.RFC3339), wantFirst.Format(time.RFC3339))
	}
}

// ParseAt reads the same line as Parse in every way but the year.
func TestParseAt_ReadsTheSameRecord(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtp[9]: ABCDE12345: to=<user@example.com>, relay=mx[203.0.113.1]:25, delay=0.5, delays=0/0/0/0.5, dsn=2.0.0, status=sent (250 OK)`

	fromParse, err := pflog.Parse(line)
	if err != nil {
		t.Fatalf("Parse error = %v", err)
	}
	// The entry time itself is a reference that gives the same year, whatever
	// the clock says. Reading the clock a second time could straddle the edge
	// of the skew and pick a different year.
	fromParseAt, err := pflog.ParseAt(line, fromParse.Time)
	if err != nil {
		t.Fatalf("ParseAt error = %v", err)
	}

	if *fromParse != *fromParseAt {
		t.Errorf("Parse gave %+v, ParseAt gave %+v", *fromParse, *fromParseAt)
	}
}

// A bad line gives the same error from both.
func TestParseAt_Errors(t *testing.T) {
	ref := time.Date(2021, time.June, 1, 0, 0, 0, 0, time.UTC)
	for _, line := range []string{
		"",
		"not a syslog line",
		"Jan 32 00:00:00 host postfix/qmgr[1]: removed",
		"Jan 29 12:34:56 host postfix/smtpd[x]: removed",
	} {
		if _, err := pflog.ParseAt(line, ref); err == nil {
			t.Errorf("ParseAt(%q) error = nil, want an error", line)
		}
	}
}

func TestParse_InvalidPID(t *testing.T) {
	line := "Jan  1 00:00:00 host postfix/smtpd[abc]: connect from host[1.2.3.4]"
	_, err := pflog.Parse(line)
	if err == nil {
		t.Fatalf("Parse(%q) error = nil, want an error", line)
	}
	var pidErr *pflog.PIDError
	if !errors.As(err, &pidErr) {
		t.Fatalf("Parse(%q) error type = %T, want *pflog.PIDError", line, err)
	}
	if pidErr.PID != "abc" {
		t.Errorf("PIDError.PID = %q, want %q", pidErr.PID, "abc")
	}
	if pidErr.Err == nil {
		t.Error("PIDError.Err is nil, want an underlying error")
	}
	if errors.Unwrap(err) == nil {
		t.Error("errors.Unwrap returned nil, want an underlying error")
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

// Postfix writes a long queue ID when enable_long_queue_ids is yes. The ID
// uses a 52-character alphabet of digits and consonants. The example comes
// from the postconf(5) manual page.
func TestParse_QueueID_Long(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/qmgr[99]: 3Pt2mN2VXxznjll: removed`
	r := mustParse(t, line)
	if r.QueueID != "3Pt2mN2VXxznjll" {
		t.Errorf("QueueID = %q, want %q", r.QueueID, "3Pt2mN2VXxznjll")
	}
	if _, ok := r.Message.(pflog.Removed); !ok {
		t.Errorf("Message type = %T, want Removed", r.Message)
	}
}

func TestParse_QueueID_LongWithDelivery(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtp[9]: 3Pt2mN2VXxznjll: to=<user@example.com>, relay=mx[203.0.113.1]:25, delay=0.5, delays=0/0/0/0.5, dsn=2.0.0, status=sent (250 OK)`
	r := mustParse(t, line)
	if r.QueueID != "3Pt2mN2VXxznjll" {
		t.Errorf("QueueID = %q, want %q", r.QueueID, "3Pt2mN2VXxznjll")
	}
	d, ok := r.Message.(pflog.Delivery)
	if !ok {
		t.Fatalf("Message type = %T, want Delivery", r.Message)
	}
	if d.To != "user@example.com" {
		t.Errorf("To = %q, want %q", d.To, "user@example.com")
	}
}

// The queue ID alphabet holds no vowels. A message that starts with a word
// must therefore keep its own type, and must not lose the word to the queue
// ID field.
func TestParse_QueueID_WordPrefixIsNotAQueueID(t *testing.T) {
	cases := []struct {
		name string
		line string
		want any
	}{
		{
			name: "warning",
			line: `Mar 29 12:34:56 host postfix/smtpd[9]: warning: hostname does not resolve`,
			want: pflog.Warning{Text: "hostname does not resolve"},
		},
		{
			name: "reject",
			line: `Mar 29 12:34:56 host postfix/smtpd[9]: reject: RCPT from unknown[10.0.0.1]: 550 5.1.1 no such user`,
			want: pflog.Reject{
				Stage:          "RCPT",
				ClientHostname: "unknown",
				ClientIP:       "10.0.0.1",
				Code:           550,
				Detail:         "5.1.1 no such user",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := mustParse(t, tc.line)
			if r.QueueID != "" {
				t.Errorf("QueueID = %q, want empty", r.QueueID)
			}
			if r.Message != tc.want {
				t.Errorf("Message = %#v, want %#v", r.Message, tc.want)
			}
		})
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

// connect and disconnect carry the same "hostname[address]" field, so they
// must read it the same way.
func TestParse_ClientAddressReadTheSameWay(t *testing.T) {
	cases := []struct {
		name     string
		client   string
		hostname string
		ip       string
	}{
		{"named host", "mail.example.com[203.0.113.10]", "mail.example.com", "203.0.113.10"},
		{"unknown host", "unknown[10.0.0.1]", "unknown", "10.0.0.1"},
		{"IPv6", "unknown[2001:db8::1]", "unknown", "2001:db8::1"},
		{"unknown address", "unknown[unknown]", "unknown", "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const stamp = `Mar 29 12:34:56 host postfix/smtpd[1]: `

			cr := mustParse(t, stamp+"connect from "+tc.client)
			c, ok := cr.Message.(pflog.Connect)
			if !ok {
				t.Fatalf("connect Message type = %T, want Connect", cr.Message)
			}

			dr := mustParse(t, stamp+"disconnect from "+tc.client+" ehlo=1 quit=1 commands=2")
			d, ok := dr.Message.(pflog.Disconnect)
			if !ok {
				t.Fatalf("disconnect Message type = %T, want Disconnect", dr.Message)
			}

			if c.Hostname != tc.hostname {
				t.Errorf("Connect.Hostname = %q, want %q", c.Hostname, tc.hostname)
			}
			if c.IP != tc.ip {
				t.Errorf("Connect.IP = %q, want %q", c.IP, tc.ip)
			}
			if d.Hostname != tc.hostname {
				t.Errorf("Disconnect.Hostname = %q, want %q", d.Hostname, tc.hostname)
			}
			if d.IP != tc.ip {
				t.Errorf("Disconnect.IP = %q, want %q", d.IP, tc.ip)
			}
		})
	}
}

// A hostname from DNS cannot hold a bracket, so this line cannot occur. It is
// kept because the two parsers used to give different answers for it: connect
// searched from the right and gave "a[b].example.com" with the address
// "1.2.3.4", while disconnect searched from the left and gave "a" with the
// address "b". Both now search from the left, so connect no longer finds a
// client that reaches the end of the line, and refuses the line instead of
// giving an answer that disagrees with disconnect.
func TestParse_BracketInsideHostname(t *testing.T) {
	const stamp = `Mar 29 12:34:56 host postfix/smtpd[1]: `
	const client = "a[b].example.com[1.2.3.4]"

	cr := mustParse(t, stamp+"connect from "+client)
	if _, ok := cr.Message.(pflog.Unknown); !ok {
		t.Errorf("connect Message type = %T, want Unknown", cr.Message)
	}

	dr := mustParse(t, stamp+"disconnect from "+client+" commands=1")
	d, ok := dr.Message.(pflog.Disconnect)
	if !ok {
		t.Fatalf("disconnect Message type = %T, want Disconnect", dr.Message)
	}
	if d.Hostname != "a" || d.IP != "b" {
		t.Errorf("Disconnect hostname/IP = %q/%q, want %q/%q", d.Hostname, d.IP, "a", "b")
	}
}

// A connect line ends at the client. Text after the closing bracket means the
// line is not the shape that Postfix writes.
func TestParse_ConnectWithTrailingText(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtpd[1]: connect from unknown[1.2.3.4] extra`
	r := mustParse(t, line)
	if _, ok := r.Message.(pflog.Unknown); !ok {
		t.Errorf("Message type = %T, want Unknown", r.Message)
	}
}

// A rejection reason can hold a bracket. Reading the client field from the
// left keeps the search away from it.
func TestParse_RejectDetailWithBracket(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtpd[1]: NOQUEUE: reject: RCPT from unknown[10.0.0.1]: 550 5.1.1 blocked [see http://example.com/why]`
	r := mustParse(t, line)

	rj, ok := r.Message.(pflog.Reject)
	if !ok {
		t.Fatalf("Message type = %T, want Reject", r.Message)
	}
	if rj.ClientHostname != "unknown" {
		t.Errorf("ClientHostname = %q, want %q", rj.ClientHostname, "unknown")
	}
	if rj.ClientIP != "10.0.0.1" {
		t.Errorf("ClientIP = %q, want %q", rj.ClientIP, "10.0.0.1")
	}
	want := "5.1.1 blocked [see http://example.com/why]"
	if rj.Detail != want {
		t.Errorf("Detail = %q, want %q", rj.Detail, want)
	}
}

// A client field with no closing bracket must fall back to Unknown.
func TestParse_ClientAddressUnclosed(t *testing.T) {
	cases := []struct {
		name string
		msg  string
	}{
		{"connect, no brackets", `connect from localhost`},
		{"connect, no closing bracket", `connect from unknown[1.2.3.4`},
		{"disconnect, no brackets", `disconnect from localhost`},
		{"disconnect, no closing bracket", `disconnect from unknown[1.2.3.4 ehlo=1`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := mustParse(t, `Mar 29 12:34:56 host postfix/smtpd[1]: `+tc.msg)
			if _, ok := r.Message.(pflog.Unknown); !ok {
				t.Errorf("Message type = %T, want Unknown", r.Message)
			}
		})
	}
}

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

// The nrcpt value can end the line. Postfix normally writes " (queue active)"
// after it, but the parser must not need that text to be there.
func TestParse_QueuedWithoutTrailingText(t *testing.T) {
	cases := []struct {
		name  string
		msg   string
		from  string
		size  int
		nrcpt int
	}{
		{
			name: "nrcpt ends the line",
			msg:  `from=<sender@example.com>, size=12345, nrcpt=1`,
			from: "sender@example.com", size: 12345, nrcpt: 1,
		},
		{
			name: "nrcpt of more than one digit ends the line",
			msg:  `from=<sender@example.com>, size=12345, nrcpt=42`,
			from: "sender@example.com", size: 12345, nrcpt: 42,
		},
		{
			name: "empty sender and nrcpt ends the line",
			msg:  `from=<>, size=500, nrcpt=2`,
			from: "", size: 500, nrcpt: 2,
		},
		{
			name: "trailing text is still accepted",
			msg:  `from=<sender@example.com>, size=12345, nrcpt=1 (queue active)`,
			from: "sender@example.com", size: 12345, nrcpt: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := `Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: ` + tc.msg
			r := mustParse(t, line)

			q, ok := r.Message.(pflog.Queued)
			if !ok {
				t.Fatalf("Message type = %T, want Queued", r.Message)
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
		})
	}
}

// A broken nrcpt value must still fall back to Unknown.
func TestParse_QueuedBadNRcpt(t *testing.T) {
	cases := []struct {
		name string
		msg  string
	}{
		{"no value", `from=<s@example.com>, size=100, nrcpt=`},
		{"not a number", `from=<s@example.com>, size=100, nrcpt=x`},
		{"not a number, with trailing text", `from=<s@example.com>, size=100, nrcpt=x (queue active)`},
		{"no nrcpt field", `from=<s@example.com>, size=100`},
		{"no size field", `from=<s@example.com>, nrcpt=1`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := `Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: ` + tc.msg
			r := mustParse(t, line)
			if _, ok := r.Message.(pflog.Unknown); !ok {
				t.Errorf("Message type = %T, want Unknown", r.Message)
			}
		})
	}
}

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

func TestParse_Delivery_OrigTo(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/local[9]: ABCDE12345: to=<real@example.com>, orig_to=<alias@example.com>, relay=local, delay=0.05, delays=0.02/0/0/0.03, dsn=2.0.0, status=sent (delivered to mailbox)`
	r := mustParse(t, line)

	d, ok := r.Message.(pflog.Delivery)
	if !ok {
		t.Fatalf("Message type = %T, want Delivery", r.Message)
	}
	if d.To != "real@example.com" {
		t.Errorf("To = %q, want %q", d.To, "real@example.com")
	}
	if d.OrigTo != "alias@example.com" {
		t.Errorf("OrigTo = %q, want %q", d.OrigTo, "alias@example.com")
	}
	if d.Relay != "local" {
		t.Errorf("Relay = %q, want %q", d.Relay, "local")
	}
	if d.Status != pflog.StatusSent {
		t.Errorf("Status = %q, want %q", d.Status, pflog.StatusSent)
	}
	if d.Detail != "delivered to mailbox" {
		t.Errorf("Detail = %q, want %q", d.Detail, "delivered to mailbox")
	}
}

func TestParse_Delivery_ConnUse(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtp[9]: ABCDE12345: to=<user@example.com>, relay=mx.example.com[203.0.113.1]:25, conn_use=3, delay=0.5, delays=0.1/0/0.1/0.3, dsn=2.0.0, status=sent (250 2.0.0 OK)`
	r := mustParse(t, line)

	d, ok := r.Message.(pflog.Delivery)
	if !ok {
		t.Fatalf("Message type = %T, want Delivery", r.Message)
	}
	if d.To != "user@example.com" {
		t.Errorf("To = %q, want %q", d.To, "user@example.com")
	}
	if d.Relay != "mx.example.com[203.0.113.1]:25" {
		t.Errorf("Relay = %q, want %q", d.Relay, "mx.example.com[203.0.113.1]:25")
	}
	if d.Delay != "0.5" {
		t.Errorf("Delay = %q, want %q", d.Delay, "0.5")
	}
	if d.DSN != "2.0.0" {
		t.Errorf("DSN = %q, want %q", d.DSN, "2.0.0")
	}
	if d.Status != pflog.StatusSent {
		t.Errorf("Status = %q, want %q", d.Status, pflog.StatusSent)
	}
}

func TestParse_Delivery_OrigToAndConnUse(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtp[9]: ABCDE12345: to=<real@example.com>, orig_to=<alias@example.com>, relay=mx[203.0.113.1]:25, conn_use=2, delay=1.2, delays=0.1/0/0.1/1, dsn=2.0.0, status=sent (250 OK)`
	r := mustParse(t, line)

	d, ok := r.Message.(pflog.Delivery)
	if !ok {
		t.Fatalf("Message type = %T, want Delivery", r.Message)
	}
	if d.To != "real@example.com" {
		t.Errorf("To = %q, want %q", d.To, "real@example.com")
	}
	if d.OrigTo != "alias@example.com" {
		t.Errorf("OrigTo = %q, want %q", d.OrigTo, "alias@example.com")
	}
	if d.Delays != "0.1/0/0.1/1" {
		t.Errorf("Delays = %q, want %q", d.Delays, "0.1/0/0.1/1")
	}
}

// An unrecognised field must not push the record to Unknown, so that a future
// Postfix field keeps working.
func TestParse_Delivery_UnknownFieldIgnored(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtp[9]: ABCDE12345: to=<user@example.com>, relay=mx[203.0.113.1]:25, future_field=xyz, delay=0.5, delays=0/0/0/0.5, dsn=2.0.0, status=sent (250 OK)`
	r := mustParse(t, line)

	d, ok := r.Message.(pflog.Delivery)
	if !ok {
		t.Fatalf("Message type = %T, want Delivery", r.Message)
	}
	if d.To != "user@example.com" {
		t.Errorf("To = %q, want %q", d.To, "user@example.com")
	}
	if d.Status != pflog.StatusSent {
		t.Errorf("Status = %q, want %q", d.Status, pflog.StatusSent)
	}
}

// The status detail may contain commas and parentheses. It must survive whole.
func TestParse_Delivery_DetailWithCommas(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtp[9]: ABCDE12345: to=<user@example.com>, relay=mx[203.0.113.1]:25, delay=0.5, delays=0/0/0/0.5, dsn=5.1.1, status=bounced (host mx said: 550 5.1.1 no such user, try again (in reply to RCPT TO command))`
	r := mustParse(t, line)

	d, ok := r.Message.(pflog.Delivery)
	if !ok {
		t.Fatalf("Message type = %T, want Delivery", r.Message)
	}
	if d.Status != pflog.StatusBounced {
		t.Errorf("Status = %q, want %q", d.Status, pflog.StatusBounced)
	}
	want := "host mx said: 550 5.1.1 no such user, try again (in reply to RCPT TO command)"
	if d.Detail != want {
		t.Errorf("Detail = %q, want %q", d.Detail, want)
	}
}

// A missing mandatory field must still fall back to Unknown.
func TestParse_Delivery_MissingFieldsFallBackToUnknown(t *testing.T) {
	cases := []struct {
		name string
		msg  string
	}{
		{"no relay", `to=<user@example.com>, delay=0.5, delays=0/0/0/0.5, dsn=2.0.0, status=sent (250 OK)`},
		{"no status", `to=<user@example.com>, relay=mx[203.0.113.1]:25, delay=0.5, delays=0/0/0/0.5, dsn=2.0.0`},
		{"unterminated address", `to=<user@example.com, relay=mx[203.0.113.1]:25, status=sent (250 OK)`},
		{"status without detail", `to=<user@example.com>, relay=mx[203.0.113.1]:25, status=sent`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := mustParse(t, `Mar 29 12:34:56 host postfix/smtp[9]: ABCDE12345: `+tc.msg)
			if _, ok := r.Message.(pflog.Unknown); !ok {
				t.Errorf("Message type = %T, want Unknown", r.Message)
			}
		})
	}
}

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

func TestScanner_ErrorHandler(t *testing.T) {
	input := strings.Join([]string{
		`this is not a syslog line`,
		`Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: removed`,
		`another garbage line`,
		`Mar 29 12:34:57 host postfix/smtpd[2]: connect from unknown[1.2.3.4]`,
	}, "\n")

	s := pflog.NewScanner(strings.NewReader(input))

	var errLines []string
	var errs []error
	s.SetErrorHandler(func(line string, err error) {
		errLines = append(errLines, line)
		errs = append(errs, err)
	})

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
	if len(errLines) != 2 {
		t.Fatalf("error handler called %d times, want 2", len(errLines))
	}
	if errLines[0] != "this is not a syslog line" {
		t.Errorf("errLines[0] = %q, want %q", errLines[0], "this is not a syslog line")
	}
	if errLines[1] != "another garbage line" {
		t.Errorf("errLines[1] = %q, want %q", errLines[1], "another garbage line")
	}
	for i, err := range errs {
		if err == nil {
			t.Errorf("errs[%d] is nil, want a non-nil error", i)
		}
	}
}

// A line above the limit must not end the scan. The reader has to carry on
// with the lines that follow it.
func TestScanner_SkipsOverLongLine(t *testing.T) {
	long := `Mar 29 12:34:56 host postfix/smtpd[1]: warning: ` + strings.Repeat("x", 70000)
	input := strings.Join([]string{
		`Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: removed`,
		long,
		`Mar 29 12:34:57 host postfix/smtpd[2]: connect from unknown[1.2.3.4]`,
	}, "\n")

	s := pflog.NewScanner(strings.NewReader(input))

	var count int
	for s.Scan() {
		count++
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Err() = %v, want nil", err)
	}
	if count != 2 {
		t.Errorf("scanned %d records, want 2", count)
	}
}

func TestScanner_OverLongLineGoesToErrorHandler(t *testing.T) {
	long := `Mar 29 12:34:56 host postfix/smtpd[1]: warning: ` + strings.Repeat("x", 70000)
	input := long + "\n" + `Mar 29 12:34:57 host postfix/qmgr[1]: ABCDE12345: removed`

	s := pflog.NewScanner(strings.NewReader(input))

	var errs []error
	var lines []string
	s.SetErrorHandler(func(line string, err error) {
		lines = append(lines, line)
		errs = append(errs, err)
	})

	var count int
	for s.Scan() {
		count++
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Err() = %v, want nil", err)
	}
	if count != 1 {
		t.Errorf("scanned %d records, want 1", count)
	}
	if len(errs) != 1 {
		t.Fatalf("error handler called %d times, want 1", len(errs))
	}

	var tooLong *pflog.LineTooLongError
	if !errors.As(errs[0], &tooLong) {
		t.Fatalf("error type = %T, want *pflog.LineTooLongError", errs[0])
	}
	if tooLong.Len != len(long) {
		t.Errorf("Len = %d, want %d", tooLong.Len, len(long))
	}
	if tooLong.Limit != pflog.DefaultMaxLineLen {
		t.Errorf("Limit = %d, want %d", tooLong.Limit, pflog.DefaultMaxLineLen)
	}
	// The handler must not receive more than the limit, or the memory bound
	// has no value.
	if len(lines[0]) > pflog.DefaultMaxLineLen {
		t.Errorf("handler line length = %d, want at most %d", len(lines[0]), pflog.DefaultMaxLineLen)
	}
}

// The scanner must read past a long line without holding all of it. This
// test feeds a line of 4 MiB from a reader that makes the bytes as they are
// asked for, so the test itself never holds the line either. A scanner that
// buffered the whole line would still pass, but the memory it took would
// grow with the input.
func TestScanner_DrainsOverLongLineWithoutHoldingIt(t *testing.T) {
	const lineLen = 4 << 20

	r := io.MultiReader(
		&repeatReader{b: 'x', n: lineLen},
		strings.NewReader("\n"+`Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: removed`),
	)

	s := pflog.NewScanner(r)

	var got *pflog.LineTooLongError
	var handlerLineLen int
	s.SetErrorHandler(func(line string, err error) {
		handlerLineLen = len(line)
		errors.As(err, &got)
	})

	var count int
	for s.Scan() {
		count++
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Err() = %v, want nil", err)
	}
	if count != 1 {
		t.Errorf("scanned %d records, want 1", count)
	}
	if got == nil {
		t.Fatal("no LineTooLongError reached the handler")
	}
	if got.Len != lineLen {
		t.Errorf("Len = %d, want %d", got.Len, lineLen)
	}
	if handlerLineLen != pflog.DefaultMaxLineLen {
		t.Errorf("handler line length = %d, want %d", handlerLineLen, pflog.DefaultMaxLineLen)
	}
}

// repeatReader gives n copies of one byte and then stops.
type repeatReader struct {
	b byte
	n int
}

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.n == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.n {
		n = r.n
	}
	for i := 0; i < n; i++ {
		p[i] = r.b
	}
	r.n -= n
	return n, nil
}

func TestScanner_SetMaxLineLen(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: removed`
	s := pflog.NewScanner(strings.NewReader(line))
	s.SetMaxLineLen(10)

	var errs []error
	s.SetErrorHandler(func(_ string, err error) { errs = append(errs, err) })

	if s.Scan() {
		t.Error("Scan() = true, want false: the line is above the limit")
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Err() = %v, want nil", err)
	}
	if len(errs) != 1 {
		t.Fatalf("error handler called %d times, want 1", len(errs))
	}
	var tooLong *pflog.LineTooLongError
	if !errors.As(errs[0], &tooLong) {
		t.Fatalf("error type = %T, want *pflog.LineTooLongError", errs[0])
	}
	if tooLong.Limit != 10 {
		t.Errorf("Limit = %d, want 10", tooLong.Limit)
	}
}

// A long line below the limit must still parse.
func TestScanner_LongLineBelowLimit(t *testing.T) {
	detail := strings.Repeat("y", 40000)
	line := `Mar 29 12:34:56 host postfix/smtpd[1]: warning: ` + detail

	s := pflog.NewScanner(strings.NewReader(line))
	if !s.Scan() {
		t.Fatalf("Scan() = false, want true; Err() = %v", s.Err())
	}
	w, ok := s.Record().Message.(pflog.Warning)
	if !ok {
		t.Fatalf("Message type = %T, want Warning", s.Record().Message)
	}
	if w.Text != detail {
		t.Errorf("Warning.Text length = %d, want %d", len(w.Text), len(detail))
	}
}

// The reader must handle a final line that carries no newline, and must strip
// a carriage return from CRLF input.
func TestScanner_LineEndings(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{"no trailing newline", `Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: removed`, 1},
		{"trailing newline", "Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: removed\n", 1},
		{"crlf", "Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: removed\r\n", 1},
		{"two crlf lines", "Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: removed\r\nMar 29 12:34:57 host postfix/qmgr[1]: ABCDE12345: removed\r\n", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := pflog.NewScanner(strings.NewReader(tc.input))
			var count int
			for s.Scan() {
				if _, ok := s.Record().Message.(pflog.Removed); !ok {
					t.Errorf("Message type = %T, want Removed", s.Record().Message)
				}
				count++
			}
			if err := s.Err(); err != nil {
				t.Fatalf("Err() = %v, want nil", err)
			}
			if count != tc.want {
				t.Errorf("scanned %d records, want %d", count, tc.want)
			}
		})
	}
}

// A read error must reach Err, and must not look like the end of the input.
func TestScanner_ReadError(t *testing.T) {
	want := errors.New("boom")
	r := io.MultiReader(
		strings.NewReader("Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: removed\n"),
		&errReader{err: want},
	)

	s := pflog.NewScanner(r)
	var count int
	for s.Scan() {
		count++
	}
	if count != 1 {
		t.Errorf("scanned %d records, want 1", count)
	}
	if !errors.Is(s.Err(), want) {
		t.Errorf("Err() = %v, want %v", s.Err(), want)
	}
}

type errReader struct{ err error }

func (r *errReader) Read([]byte) (int, error) { return 0, r.err }

// io.Reader allows a reader to give data and an error in the same call. The
// data must still reach the caller, and the error must arrive after it.
func TestScanner_ReadErrorWithFinalLine(t *testing.T) {
	want := errors.New("boom")
	cases := []struct {
		name string
		data string
	}{
		{"no trailing newline", `Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: removed`},
		{"trailing newline", "Mar 29 12:34:56 host postfix/qmgr[1]: ABCDE12345: removed\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := pflog.NewScanner(&dataThenErrReader{data: tc.data, err: want})

			var count int
			for s.Scan() {
				if _, ok := s.Record().Message.(pflog.Removed); !ok {
					t.Errorf("Message type = %T, want Removed", s.Record().Message)
				}
				count++
			}
			if count != 1 {
				t.Errorf("scanned %d records, want 1", count)
			}
			if !errors.Is(s.Err(), want) {
				t.Errorf("Err() = %v, want %v", s.Err(), want)
			}
		})
	}
}

// dataThenErrReader gives data and an error in the same Read call.
type dataThenErrReader struct {
	data string
	err  error
	done bool
}

func (r *dataThenErrReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, r.err
	}
	r.done = true
	return copy(p, r.data), r.err
}

// The end-of-line bytes are not part of the line. A line of exactly the limit
// followed by CRLF is therefore within the limit, not above it.
func TestScanner_LineExactlyAtLimitWithCRLF(t *testing.T) {
	const prefix = `Mar 29 12:34:56 host postfix/smtpd[1]: warning: `
	body := strings.Repeat("z", pflog.DefaultMaxLineLen-len(prefix))

	s := pflog.NewScanner(strings.NewReader(prefix + body + "\r\n"))
	var skipped error
	s.SetErrorHandler(func(_ string, err error) { skipped = err })

	if !s.Scan() {
		t.Fatalf("Scan() = false, want true; skipped = %v, Err() = %v", skipped, s.Err())
	}
	w, ok := s.Record().Message.(pflog.Warning)
	if !ok {
		t.Fatalf("Message type = %T, want Warning", s.Record().Message)
	}
	if w.Text != body {
		t.Errorf("Warning.Text length = %d, want %d", len(w.Text), len(body))
	}
	if skipped != nil {
		t.Errorf("error handler got %v, want no call", skipped)
	}
}

// A CRLF pair can fall across two reads of the buffer inside the reader. The
// carriage return must still leave the line, whatever the length.
func TestScanner_CRLFAcrossReads(t *testing.T) {
	const prefix = `Mar 29 12:34:56 host postfix/smtpd[1]: warning: `
	// The reader buffer holds 4096 bytes, so these lengths put the carriage
	// return on both sides of a read boundary.
	for _, total := range []int{4094, 4095, 4096, 4097, 8192} {
		t.Run(fmt.Sprintf("%d", total), func(t *testing.T) {
			body := strings.Repeat("z", total-len(prefix))

			s := pflog.NewScanner(strings.NewReader(prefix + body + "\r\n"))
			if !s.Scan() {
				t.Fatalf("Scan() = false, want true; Err() = %v", s.Err())
			}
			w, ok := s.Record().Message.(pflog.Warning)
			if !ok {
				t.Fatalf("Message type = %T, want Warning", s.Record().Message)
			}
			if w.Text != body {
				t.Errorf("Warning.Text length = %d, want %d", len(w.Text), len(body))
			}
		})
	}
}

// A CRLF line above the limit must report the length of the line itself,
// without the end-of-line bytes.
func TestScanner_OverLongCRLFLineReportsLength(t *testing.T) {
	line := `Mar 29 12:34:56 host postfix/smtpd[1]: warning: ` + strings.Repeat("z", 70000)

	s := pflog.NewScanner(strings.NewReader(line + "\r\n"))
	var got *pflog.LineTooLongError
	s.SetErrorHandler(func(_ string, err error) { errors.As(err, &got) })

	for s.Scan() {
	}
	if got == nil {
		t.Fatal("no LineTooLongError reached the handler")
	}
	if got.Len != len(line) {
		t.Errorf("Len = %d, want %d", got.Len, len(line))
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

// ParseAt with a reference time held outside the loop, which is how a caller
// reads a whole log. It shows the cost of reading the clock for each line.
func BenchmarkParseAt_Connect(b *testing.B) {
	line := `Mar 29 12:34:56 host postfix/smtpd[1]: connect from mail.example.com[203.0.113.10]`
	ref := time.Now()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		pflog.ParseAt(line, ref) //nolint:errcheck
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
