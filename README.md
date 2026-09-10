# pflog

[![Go Reference](https://pkg.go.dev/badge/github.com/chrj/pflog.svg)](https://pkg.go.dev/github.com/chrj/pflog)

`pflog` is a Go package for parsing [Postfix](https://www.postfix.org/) mail log entries. It handles the standard BSD syslog format that Postfix writes to, turning raw log lines into structured Go values.

## Features

- Parse individual log lines with `Parse`, or iterate over a log file with `Scanner`.
- `ParseAt` takes a reference time for the year, which the BSD syslog format omits. Use it for a log from another period, for a log that crosses a year boundary, and to keep the clock read out of a loop over many lines.
- Each entry is returned as a `Record` containing the timestamp, hostname, Postfix daemon name, process ID, queue ID, and a typed `Message`.
- Recognised message types: `Connect`, `Disconnect`, `Queued`, `Removed`, `Cleanup`, `Delivery`, `Reject`, `BounceNotification`, `Warning`, and `Unknown`.
- `Scanner` skips a line that it cannot parse, and a line above `SetMaxLineLen`, so one bad line does not stop the scan. Use `SetErrorHandler` to see the skipped lines.

## Benchmarks

Measured on an AMD EPYC 7R13 with Go 1.26.1. The numbers are the median of
16 runs of `go test -bench=. -benchmem`.

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `Parse` — Connect | 274 | 128 | 2 |
| `ParseAt` — Connect | 202 | 128 | 2 |
| `Parse` — Disconnect (with stats) | 644 | 400 | 4 |
| `Parse` — Queued | 347 | 128 | 2 |
| `Parse` — Delivery | 494 | 224 | 2 |
| `Parse` — Reject | 374 | 176 | 2 |
| `Parse` — Unknown | 294 | 112 | 2 |
| `Scanner` — 10 mixed lines | 6,533 | 6,960 | 34 |

`Parse` reads the clock for every line, which takes most of the time that it
gives to the timestamp. `ParseAt` takes the reference time from the caller, so
a loop over many lines reads the clock one time. The two rows above measure
the same line.

The `Scanner` benchmark builds a new scanner for every 10 lines, so it also
measures the cost to set one up.

## Installation

```sh
go get github.com/chrj/pflog
```

## Usage

```go
package main

import (
    "fmt"
    "log"
    "os"

    "github.com/chrj/pflog"
)

func main() {
    f, err := os.Open("/var/log/mail.log")
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

    s := pflog.NewScanner(f)
    for s.Scan() {
        rec := s.Record()
        switch msg := rec.Message.(type) {
        case pflog.Delivery:
            fmt.Printf("to=%s relay=%s status=%s\n", msg.To, msg.Relay, msg.Status)
        case pflog.Reject:
            fmt.Printf("rejected at %s: %s\n", msg.Stage, msg.Detail)
        }
    }
    if err := s.Err(); err != nil {
        log.Fatal(err)
    }
}
```
