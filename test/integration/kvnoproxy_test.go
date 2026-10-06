//go:build integration

package integration

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/messages"
)

// kvnoProxy forwards Kerberos over TCP to a KDC and puts a fixed kvno into the encrypted part
// of every AS-REP, as Active Directory does with the kvno of the client's key. An MIT KDC
// leaves the kvno out, and then a keytab whose entries all have kvno 0 works anyway: without
// the proxy, plan finding 8 could not be reproduced. The kvno is not covered by the
// encryption, so the proxy needs no keys.
type kvnoProxy struct {
	addr      string // host:port to put into krb5.conf
	kdc       string
	kvno      int
	rewritten atomic.Int64 // AS-REPs changed so far
}

// startKVNOProxy starts a proxy to the KDC at kdcAddr; it stops when the test ends.
func startKVNOProxy(t *testing.T, kdcAddr string, kvno int) *kvnoProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("kvno proxy: %v", err)
	}
	p := &kvnoProxy{addr: ln.Addr().String(), kdc: kdcAddr, kvno: kvno}
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		conns  = map[net.Conn]struct{}{}
		closed bool
	)
	wg.Go(func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // closed
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = conn.Close()
				return
			}
			conns[conn] = struct{}{}
			mu.Unlock()
			wg.Go(func() {
				err := p.serve(conn)
				mu.Lock()
				defer mu.Unlock()
				delete(conns, conn)
				if err != nil && !closed {
					t.Errorf("kvno proxy: %v", err)
				}
			})
		}
	})
	t.Cleanup(func() {
		mu.Lock()
		closed = true
		_ = ln.Close()
		for conn := range conns {
			_ = conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return p
}

// serve forwards the requests of one client connection, each over its own connection to the
// KDC.
func (p *kvnoProxy) serve(conn net.Conn) error {
	defer conn.Close()
	for {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		req, err := readFrame(conn)
		if errors.Is(err, io.EOF) {
			return nil // the client is done
		}
		if err != nil {
			return fmt.Errorf("read request: %w", err)
		}
		resp, err := p.exchange(req)
		if err != nil {
			return err
		}
		if err := writeFrame(conn, p.rewrite(resp)); err != nil {
			return fmt.Errorf("write response: %w", err)
		}
	}
}

func (p *kvnoProxy) exchange(req []byte) ([]byte, error) {
	kdc, err := net.DialTimeout("tcp", p.kdc, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to the KDC: %w", err)
	}
	defer kdc.Close()
	_ = kdc.SetDeadline(time.Now().Add(30 * time.Second))
	if err := writeFrame(kdc, req); err != nil {
		return nil, fmt.Errorf("send to the KDC: %w", err)
	}
	resp, err := readFrame(kdc)
	if err != nil {
		return nil, fmt.Errorf("read the KDC's response: %w", err)
	}
	return resp, nil
}

// rewrite sets the kvno of an AS-REP; other messages (KRB-ERROR, TGS-REP) pass unchanged.
func (p *kvnoProxy) rewrite(msg []byte) []byte {
	var rep messages.ASRep
	if rep.Unmarshal(msg) != nil {
		return msg
	}
	rep.EncPart.KVNO = p.kvno
	b, err := rep.Marshal()
	if err != nil {
		return msg
	}
	p.rewritten.Add(1)
	return b
}

// maxFrame bounds a Kerberos message over TCP; real ones are a few KiB.
const maxFrame = 1 << 20

// readFrame reads a Kerberos message over TCP: a 4-byte big-endian length, then the message
// (RFC 4120 §7.2.2).
func readFrame(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n > maxFrame {
		return nil, fmt.Errorf("message of %d bytes", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func writeFrame(w io.Writer, b []byte) error {
	frame := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(b)), uint32(len(b)))
	_, err := w.Write(append(frame, b...))
	return err
}
