// Package traffic measures what an observer sees on a TLS connection: the
// direction and size of each record. It also holds simple detectors that stand
// in for a censor, so the effect of a traffic shaper can be measured.
//
// The detectors are small and made up for this project. They show whether
// shaping moves the numbers a censor could use. They do not predict what a
// real censor does.
package traffic

import (
	"net"
	"sync"
	"testing"
	"time"
)

// TLS record content types, from RFC 8446.
const (
	TypeChangeCipherSpec = 20
	TypeAlert            = 21
	TypeHandshake        = 22
	TypeApplicationData  = 23

	recordHeaderLen = 5
	maxRecordLen    = 16384 + 256
)

// Record is one TLS record as seen on the wire.
type Record struct {
	// Up is true for records sent by the client.
	Up bool
	// Type is the record content type.
	Type byte
	// Len is the length of the record body.
	Len int
}

// Step is the part of a record an observer can still use after the handshake:
// who sent it and how long it was.
type Step struct {
	Up  bool
	Len int
}

// recordParser turns one direction of a TCP stream into records.
type recordParser struct {
	up     bool
	buf    []byte
	broken bool
}

// feed adds stream bytes and returns the records that are now complete. A
// stream that stops looking like TLS is abandoned.
func (p *recordParser) feed(b []byte) []Record {
	if p.broken {
		return nil
	}
	p.buf = append(p.buf, b...)
	var out []Record
	for len(p.buf) >= recordHeaderLen {
		typ, version := p.buf[0], p.buf[1]
		length := int(p.buf[3])<<8 | int(p.buf[4])
		if typ < TypeChangeCipherSpec || typ > TypeApplicationData || version != 3 || length > maxRecordLen {
			p.broken = true
			return out
		}
		if len(p.buf) < recordHeaderLen+length {
			break
		}
		out = append(out, Record{Up: p.up, Type: typ, Len: length})
		p.buf = p.buf[recordHeaderLen+length:]
	}
	return out
}

// Trace is an ordered list of the records of one connection.
type Trace struct {
	mu      sync.Mutex
	records []Record
}

func (t *Trace) add(rs []Record) {
	if len(rs) == 0 {
		return
	}
	t.mu.Lock()
	t.records = append(t.records, rs...)
	t.mu.Unlock()
}

// Records returns a copy of the records seen so far.
func (t *Trace) Records() []Record {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]Record(nil), t.records...)
}

// AfterHandshake returns the application data records that follow the
// client's Finished message, which is the first application data record the
// client sends. This is the part of a TLS 1.3 connection that carries the
// payload, and where the handshake of a protocol inside the tunnel shows.
func AfterHandshake(records []Record) []Step {
	start := -1
	for i, r := range records {
		if r.Up && r.Type == TypeApplicationData {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil
	}
	var steps []Step
	for _, r := range records[start:] {
		if r.Type == TypeApplicationData {
			steps = append(steps, Step{Up: r.Up, Len: r.Len})
		}
	}
	return steps
}

// Tap is a TCP proxy that records the TLS records of the first connection it
// carries, in both directions.
type Tap struct {
	// Addr is where clients connect.
	Addr string

	trace *Trace
	done  chan struct{}
}

// StartTap listens on a loopback port and forwards to target.
func StartTap(t testing.TB, target string) *Tap {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	tap := &Tap{Addr: ln.Addr().String(), trace: &Trace{}, done: make(chan struct{})}
	go func() {
		first := true
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			record := first
			first = false
			go tap.carry(client, target, record)
		}
	}()
	return tap
}

// Wait returns the records once the first connection has closed, or whatever
// was recorded if it is still open after timeout.
func (p *Tap) Wait(timeout time.Duration) []Record {
	select {
	case <-p.done:
	case <-time.After(timeout):
	}
	return p.trace.Records()
}

func (p *Tap) carry(client net.Conn, target string, record bool) {
	defer client.Close()
	server, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer server.Close()

	var up, down *recordParser
	if record {
		defer close(p.done)
		up, down = &recordParser{up: true}, &recordParser{}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pump(server, client, up, p.trace) }()
	go func() { defer wg.Done(); pump(client, server, down, p.trace) }()
	wg.Wait()
}

// pump copies src to dst and feeds the bytes to parser, if there is one. When
// src ends it closes both sides so the other direction ends too.
func pump(dst, src net.Conn, parser *recordParser, trace *Trace) {
	defer dst.Close()
	defer src.Close()
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if parser != nil {
				trace.add(parser.feed(buf[:n]))
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
