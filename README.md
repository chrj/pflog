# pflog

[![Go Reference](https://pkg.go.dev/badge/github.com/chrj/pflog.svg)](https://pkg.go.dev/github.com/chrj/pflog)

`pflog` is a Go package for parsing [Postfix](https://www.postfix.org/) mail log entries. It handles the standard BSD syslog format that Postfix writes to, turning raw log lines into structured Go values.

## Features

- Parse individual log lines with `Parse`, or iterate over a log file with `Scanner`.
- Each entry is returned as a `Record` containing the timestamp, hostname, Postfix daemon name, process ID, queue ID, and a typed `Message`.
- Recognised message types: `Connect`, `Disconnect`, `Queued`, `Removed`, `Cleanup`, `Delivery`, `Reject`, `BounceNotification`, `Warning`, and `Unknown`.

## Benchmarks

Measured on an AMD EPYC 7763 with `go test -bench=. -benchmem`:

| Benchmark                         | ns/op |  B/op | allocs/op |
| --------------------------------- | ----: | ----: | --------: |
| `Parse` — Connect                 |   203 |   128 |         2 |
| `Parse` — Disconnect (with stats) |   500 |   400 |         4 |
| `Parse` — Queued                  |   261 |   128 |         2 |
| `Parse` — Delivery                |   328 |   208 |         2 |
| `Parse` — Reject                  |   303 |   176 |         2 |
| `Parse` — Unknown                 |   230 |   112 |         2 |
| `Scanner` — 10 mixed lines        | 4,484 | 6,848 |        33 |

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
