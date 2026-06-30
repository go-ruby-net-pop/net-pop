// Copyright (c) the go-ruby-net-pop/net-pop authors
//
// SPDX-License-Identifier: BSD-3-Clause

package netpop

import (
	"errors"
	"strings"
	"testing"
)

// memTransport is a deterministic, in-memory Transport: it records every written
// line and replays a scripted sequence of server reply lines. It is the test
// stand-in for the real TCP/TLS socket — the package's socket seam — so the whole
// suite runs without a network or a Ruby runtime.
type memTransport struct {
	written []string // command lines, CRLF stripped
	replies []string // scripted server lines, WITHOUT CRLF (added on read)
	pos     int
	failOn  int  // 1-based write index to fail on (0 = never)
	readErr bool // make the next Readline/ReadRawLine fail
}

func (m *memTransport) Writeline(line string) error {
	m.written = append(m.written, line)
	if m.failOn != 0 && len(m.written) == m.failOn {
		return errTransport
	}
	return nil
}

func (m *memTransport) next() (string, error) {
	if m.readErr {
		return "", errTransport
	}
	if m.pos >= len(m.replies) {
		return "", errTransport
	}
	r := m.replies[m.pos]
	m.pos++
	return r, nil
}

func (m *memTransport) Readline() (string, error) { return m.next() }

func (m *memTransport) ReadRawLine() (string, error) {
	s, err := m.next()
	if err != nil {
		return "", err
	}
	return s + "\r\n", nil
}

var errTransport = errors.New("transport boom")

func newConn(replies ...string) (*Conn, *memTransport) {
	t := &memTransport{replies: replies}
	return NewConn(t), t
}

func TestGreet(t *testing.T) {
	c, _ := newConn("+OK POP3 ready <1896.697170952@dbc.mtview.ca.us>")
	if err := c.Greet(); err != nil {
		t.Fatalf("Greet = %v", err)
	}
	stamp, ok := c.ApopStamp()
	if !ok || stamp != "<1896.697170952@dbc.mtview.ca.us>" {
		t.Errorf("stamp = (%q,%v)", stamp, ok)
	}
}

func TestGreetNoStamp(t *testing.T) {
	c, _ := newConn("+OK ready")
	if err := c.Greet(); err != nil {
		t.Fatalf("Greet = %v", err)
	}
	if _, ok := c.ApopStamp(); ok {
		t.Error("expected no stamp")
	}
}

func TestGreetError(t *testing.T) {
	c, _ := newConn("-ERR locked")
	err := c.Greet()
	var pe *POPError
	if !errors.As(err, &pe) {
		t.Errorf("Greet err = %v, want *POPError", err)
	}
}

func TestGreetReadError(t *testing.T) {
	c, tr := newConn()
	tr.readErr = true
	if err := c.Greet(); err != errTransport {
		t.Errorf("Greet read err = %v, want errTransport", err)
	}
}

func TestAuth(t *testing.T) {
	c, tr := newConn("+OK send PASS", "+OK logged in")
	if err := c.Auth("alice", "secret"); err != nil {
		t.Fatalf("Auth = %v", err)
	}
	want := []string{"USER alice", "PASS secret"}
	if strings.Join(tr.written, "|") != strings.Join(want, "|") {
		t.Errorf("written = %v, want %v", tr.written, want)
	}
}

func TestAuthUserRejected(t *testing.T) {
	c, _ := newConn("-ERR unknown user")
	err := c.Auth("bob", "x")
	var ae *POPAuthenticationError
	if !errors.As(err, &ae) {
		t.Errorf("Auth err = %v, want *POPAuthenticationError", err)
	}
}

func TestAuthPassRejected(t *testing.T) {
	c, _ := newConn("+OK", "-ERR bad password")
	err := c.Auth("bob", "x")
	var ae *POPAuthenticationError
	if !errors.As(err, &ae) {
		t.Errorf("Auth pass err = %v, want *POPAuthenticationError", err)
	}
}

func TestAuthWriteError(t *testing.T) {
	c, tr := newConn("+OK")
	tr.failOn = 1
	if err := c.Auth("a", "b"); err != errTransport {
		t.Errorf("Auth write err = %v", err)
	}
}

func TestAuthPassWriteError(t *testing.T) {
	c, tr := newConn("+OK")
	tr.failOn = 2 // fail on the PASS write
	if err := c.Auth("a", "b"); err != errTransport {
		t.Errorf("Auth PASS write err = %v", err)
	}
}

func TestApop(t *testing.T) {
	c, tr := newConn("+OK <1896.697170952@dbc.mtview.ca.us>", "+OK maildrop locked")
	if err := c.Greet(); err != nil {
		t.Fatal(err)
	}
	if err := c.Apop("mrose", "tanstaaf"); err != nil {
		t.Fatalf("Apop = %v", err)
	}
	if tr.written[0] != "APOP mrose c4c9334bac560ecc979e58001b3e22fb" {
		t.Errorf("APOP line = %q", tr.written[0])
	}
}

func TestApopNoStamp(t *testing.T) {
	c, _ := newConn("+OK ready")
	if err := c.Greet(); err != nil {
		t.Fatal(err)
	}
	err := c.Apop("mrose", "tanstaaf")
	var ae *POPAuthenticationError
	if !errors.As(err, &ae) || ae.Response != "not APOP server; cannot login" {
		t.Errorf("Apop no-stamp err = %v", err)
	}
}

func TestApopRejected(t *testing.T) {
	c, _ := newConn("+OK <a@b>", "-ERR permission denied")
	if err := c.Greet(); err != nil {
		t.Fatal(err)
	}
	err := c.Apop("mrose", "tanstaaf")
	var ae *POPAuthenticationError
	if !errors.As(err, &ae) {
		t.Errorf("Apop reject err = %v", err)
	}
}

func TestApopWriteError(t *testing.T) {
	c, tr := newConn("+OK <a@b>")
	if err := c.Greet(); err != nil {
		t.Fatal(err)
	}
	tr.failOn = 1
	if err := c.Apop("m", "p"); err != errTransport {
		t.Errorf("Apop write err = %v", err)
	}
}

func TestStat(t *testing.T) {
	c, _ := newConn("+OK 2 320")
	count, size, err := c.Stat()
	if err != nil || count != 2 || size != 320 {
		t.Errorf("Stat = (%d,%d,%v)", count, size, err)
	}
}

func TestStatError(t *testing.T) {
	c, _ := newConn("-ERR no mailbox")
	_, _, err := c.Stat()
	var pe *POPError
	if !errors.As(err, &pe) {
		t.Errorf("Stat err = %v, want *POPError", err)
	}
}

func TestStatBadResponse(t *testing.T) {
	c, _ := newConn("+OK garbage")
	_, _, err := c.Stat()
	var be *POPBadResponse
	if !errors.As(err, &be) {
		t.Errorf("Stat bad = %v, want *POPBadResponse", err)
	}
}

func TestStatWriteError(t *testing.T) {
	c, tr := newConn()
	tr.failOn = 1
	if _, _, err := c.Stat(); err != errTransport {
		t.Errorf("Stat write err = %v", err)
	}
}

func TestList(t *testing.T) {
	c, _ := newConn("+OK 2 messages", "1 120", "2 200", ".")
	mails, err := c.List()
	if err != nil {
		t.Fatalf("List = %v", err)
	}
	if len(mails) != 2 || mails[0].Number != 1 || mails[0].Length != 120 ||
		mails[1].Number != 2 || mails[1].Length != 200 {
		t.Errorf("List mails = %+v", mails)
	}
}

func TestListEmpty(t *testing.T) {
	c, _ := newConn("+OK 0 messages", ".")
	mails, err := c.List()
	if err != nil || len(mails) != 0 {
		t.Errorf("List empty = (%v,%v)", mails, err)
	}
}

func TestListError(t *testing.T) {
	c, _ := newConn("-ERR nope")
	if _, err := c.List(); err == nil {
		t.Error("List err = nil")
	}
}

func TestListBadItem(t *testing.T) {
	c, _ := newConn("+OK", "bogus line", ".")
	_, err := c.List()
	var be *POPBadResponse
	if !errors.As(err, &be) {
		t.Errorf("List bad item = %v, want *POPBadResponse", err)
	}
}

func TestListWriteError(t *testing.T) {
	c, tr := newConn()
	tr.failOn = 1
	if _, err := c.List(); err != errTransport {
		t.Errorf("List write err = %v", err)
	}
}

func TestListReadError(t *testing.T) {
	c, _ := newConn("+OK") // no terminator -> read past end -> error
	if _, err := c.List(); err != errTransport {
		t.Errorf("List read err = %v", err)
	}
}

func TestUIDL(t *testing.T) {
	c, _ := newConn("+OK", "1 abc", "2 def", ".")
	table, err := c.UIDL()
	if err != nil {
		t.Fatalf("UIDL = %v", err)
	}
	if table[1] != "abc" || table[2] != "def" {
		t.Errorf("UIDL table = %v", table)
	}
}

func TestUIDLSkipsDegenerate(t *testing.T) {
	// A whitespace-only line yields ok==false and is skipped, exercising that
	// branch of UIDL's callback.
	c, _ := newConn("+OK", "   ", "3 xyz", ".")
	table, err := c.UIDL()
	if err != nil || len(table) != 1 || table[3] != "xyz" {
		t.Errorf("UIDL skip = (%v,%v)", table, err)
	}
}

func TestUIDLError(t *testing.T) {
	c, _ := newConn("-ERR")
	if _, err := c.UIDL(); err == nil {
		t.Error("UIDL err = nil")
	}
}

func TestUIDLWriteError(t *testing.T) {
	c, tr := newConn()
	tr.failOn = 1
	if _, err := c.UIDL(); err != errTransport {
		t.Errorf("UIDL write err = %v", err)
	}
}

func TestUIDLReadError(t *testing.T) {
	c, _ := newConn("+OK")
	if _, err := c.UIDL(); err != errTransport {
		t.Errorf("UIDL read err = %v", err)
	}
}

func TestUIDLNum(t *testing.T) {
	c, tr := newConn("+OK 2 QhdPYR")
	uid, err := c.UIDLNum(2)
	if err != nil || uid != "2" {
		t.Errorf("UIDLNum = (%q,%v)", uid, err)
	}
	if tr.written[0] != "UIDL 2" {
		t.Errorf("UIDLNum line = %q", tr.written[0])
	}
}

func TestUIDLNumError(t *testing.T) {
	c, _ := newConn("-ERR no such message")
	if _, err := c.UIDLNum(9); err == nil {
		t.Error("UIDLNum err = nil")
	}
}

func TestUIDLNumWriteError(t *testing.T) {
	c, tr := newConn()
	tr.failOn = 1
	if _, err := c.UIDLNum(1); err != errTransport {
		t.Errorf("UIDLNum write err = %v", err)
	}
}

func TestRetr(t *testing.T) {
	// ..stuffed line un-stuffs to .stuffed; terminator ends the body.
	c, tr := newConn("+OK 11 octets", "Subject: hi\r", "..dotted\r", "body\r", ".")
	msg, err := c.Retr(3)
	if err != nil {
		t.Fatalf("Retr = %v", err)
	}
	want := "Subject: hi\r\r\n.dotted\r\r\nbody\r\r\n"
	if msg != want {
		t.Errorf("Retr = %q, want %q", msg, want)
	}
	if tr.written[0] != "RETR 3" {
		t.Errorf("Retr line = %q", tr.written[0])
	}
}

func TestRetrError(t *testing.T) {
	c, _ := newConn("-ERR no such message")
	if _, err := c.Retr(99); err == nil {
		t.Error("Retr err = nil")
	}
}

func TestRetrWriteError(t *testing.T) {
	c, tr := newConn()
	tr.failOn = 1
	if _, err := c.Retr(1); err != errTransport {
		t.Errorf("Retr write err = %v", err)
	}
}

func TestRetrReadError(t *testing.T) {
	c, _ := newConn("+OK") // missing terminator
	if _, err := c.Retr(1); err != errTransport {
		t.Errorf("Retr read err = %v", err)
	}
}

func TestTop(t *testing.T) {
	c, tr := newConn("+OK", "From: a\r", "To: b\r", ".")
	msg, err := c.Top(1, 0)
	if err != nil || msg != "From: a\r\r\nTo: b\r\r\n" {
		t.Errorf("Top = (%q,%v)", msg, err)
	}
	if tr.written[0] != "TOP 1 0" {
		t.Errorf("Top line = %q", tr.written[0])
	}
}

func TestDele(t *testing.T) {
	c, tr := newConn("+OK marked deleted")
	if err := c.Dele(4); err != nil {
		t.Fatalf("Dele = %v", err)
	}
	if tr.written[0] != "DELE 4" {
		t.Errorf("Dele line = %q", tr.written[0])
	}
}

func TestDeleError(t *testing.T) {
	c, _ := newConn("-ERR no such message")
	if err := c.Dele(99); err == nil {
		t.Error("Dele err = nil")
	}
}

func TestDeleWriteError(t *testing.T) {
	c, tr := newConn()
	tr.failOn = 1
	if err := c.Dele(1); err != errTransport {
		t.Errorf("Dele write err = %v", err)
	}
}

func TestRset(t *testing.T) {
	c, tr := newConn("+OK")
	if err := c.Rset(); err != nil || tr.written[0] != "RSET" {
		t.Errorf("Rset = (%v, %q)", err, tr.written)
	}
}

func TestRsetError(t *testing.T) {
	c, _ := newConn("-ERR")
	if err := c.Rset(); err == nil {
		t.Error("Rset err = nil")
	}
}

func TestRsetWriteError(t *testing.T) {
	c, tr := newConn()
	tr.failOn = 1
	if err := c.Rset(); err != errTransport {
		t.Errorf("Rset write err = %v", err)
	}
}

func TestNoop(t *testing.T) {
	c, tr := newConn("+OK")
	if err := c.Noop(); err != nil || tr.written[0] != "NOOP" {
		t.Errorf("Noop = (%v, %q)", err, tr.written)
	}
}

func TestNoopError(t *testing.T) {
	c, _ := newConn("-ERR")
	if err := c.Noop(); err == nil {
		t.Error("Noop err = nil")
	}
}

func TestNoopWriteError(t *testing.T) {
	c, tr := newConn()
	tr.failOn = 1
	if err := c.Noop(); err != errTransport {
		t.Errorf("Noop write err = %v", err)
	}
}

func TestQuit(t *testing.T) {
	c, tr := newConn("+OK bye")
	if err := c.Quit(); err != nil || tr.written[0] != "QUIT" {
		t.Errorf("Quit = (%v, %q)", err, tr.written)
	}
}

func TestQuitError(t *testing.T) {
	c, _ := newConn("-ERR")
	if err := c.Quit(); err == nil {
		t.Error("Quit err = nil")
	}
}

func TestQuitWriteError(t *testing.T) {
	c, tr := newConn()
	tr.failOn = 1
	if err := c.Quit(); err != errTransport {
		t.Errorf("Quit write err = %v", err)
	}
}

func TestStls(t *testing.T) {
	c, tr := newConn("+OK begin TLS")
	if err := c.Stls(); err != nil || tr.written[0] != "STLS" {
		t.Errorf("Stls = (%v, %q)", err, tr.written)
	}
}

func TestStlsError(t *testing.T) {
	c, _ := newConn("-ERR TLS unavailable")
	if err := c.Stls(); err == nil {
		t.Error("Stls err = nil")
	}
}

func TestStlsWriteError(t *testing.T) {
	c, tr := newConn()
	tr.failOn = 1
	if err := c.Stls(); err != errTransport {
		t.Errorf("Stls write err = %v", err)
	}
}

func TestErrorMessages(t *testing.T) {
	if (&POPError{Response: "a"}).Error() != "a" {
		t.Error("POPError.Error")
	}
	if (&POPAuthenticationError{Response: "b"}).Error() != "b" {
		t.Error("POPAuthenticationError.Error")
	}
	if (&POPBadResponse{Response: "c"}).Error() != "c" {
		t.Error("POPBadResponse.Error")
	}
}

func TestPOPMail(t *testing.T) {
	mails := []*POPMail{{Number: 1, Length: 10}, {Number: 2, Length: 20}}
	if mails[0].Size() != 10 {
		t.Errorf("Size = %d", mails[0].Size())
	}
	SetAllUIDs(mails, map[int]string{1: "u1"}) // 2 absent -> empty UID
	if mails[0].UID != "u1" || mails[1].UID != "" {
		t.Errorf("SetAllUIDs = %q,%q", mails[0].UID, mails[1].UID)
	}
}

func TestMessageReadErrorAfterChunk(t *testing.T) {
	// "+OK" then one body chunk then EOF (no terminator) -> read error inside the
	// message loop after at least one chunk was consumed.
	c, _ := newConn("+OK", "line\r")
	if _, err := c.Retr(1); err != errTransport {
		t.Errorf("message read-after-chunk err = %v", err)
	}
}

func TestListReadErrorAfterItem(t *testing.T) {
	c, _ := newConn("+OK", "1 10") // valid item then EOF
	if _, err := c.List(); err != errTransport {
		t.Errorf("list read-after-item err = %v", err)
	}
}
