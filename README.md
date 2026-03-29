# pflog

`pflog` is a Go package for parsing [Postfix](https://www.postfix.org/) mail log entries. It handles the standard BSD syslog format that Postfix writes to, turning raw log lines into structured Go values.

## Features

- Parse individual log lines with `Parse`, or iterate over a log file with `Scanner`.
- Each entry is returned as a `Record` containing the timestamp, hostname, Postfix daemon name, process ID, queue ID, and a typed `Message`.
- Recognised message types: `Connect`, `Disconnect`, `Queued`, `Removed`, `Cleanup`, `Delivery`, `Reject`, `BounceNotification`, `Warning`, and `Unknown`.

## Benchmarks

Measured on an AMD EPYC 7763 with `go test -bench=. -benchmem`:

| Benchmark | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| `Parse` — Connect | 2,962 | 433 | 6 |
| `Parse` — Disconnect (with stats) | 4,595 | 1,010 | 15 |
| `Parse` — Queued | 3,989 | 561 | 8 |
| `Parse` — Delivery | 6,888 | 770 | 8 |
| `Parse` — Reject | 5,351 | 673 | 8 |
| `Parse` — Unknown | 2,110 | 304 | 4 |
| `Scanner` — 10 mixed lines | 42,229 | 10,772 | 87 |

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
