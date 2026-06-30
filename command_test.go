// Copyright (c) the go-ruby-net-pop/net-pop authors
//
// SPDX-License-Identifier: BSD-3-Clause

package netpop

import (
	"errors"
	"testing"
)

func TestCommandBuilders(t *testing.T) {
	cases := []struct {
		got, want string
	}{
		{UserCommand("alice"), "USER alice"},
		{PassCommand("s3cret"), "PASS s3cret"},
		{StatCommand(), "STAT"},
		{ListCommand(), "LIST"},
		{UidlCommand(), "UIDL"},
		{UidlNumCommand(7), "UIDL 7"},
		{RetrCommand(3), "RETR 3"},
		{TopCommand(2, 10), "TOP 2 10"},
		{DeleCommand(5), "DELE 5"},
		{RsetCommand(), "RSET"},
		{NoopCommand(), "NOOP"},
		{QuitCommand(), "QUIT"},
		{StlsCommand(), "STLS"},
		{ApopCommand("alice", "<1896.697170952@dbc.mtview.ca.us>", "tanstaaf"),
			"APOP alice c4c9334bac560ecc979e58001b3e22fb"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("command = %q, want %q", c.got, c.want)
		}
	}
}

func TestWriteline(t *testing.T) {
	if got := Writeline("STAT"); got != "STAT\r\n" {
		t.Errorf("Writeline = %q, want %q", got, "STAT\r\n")
	}
}

func TestApopDigest(t *testing.T) {
	// RFC 1939 §7 worked example.
	got := ApopDigest("<1896.697170952@dbc.mtview.ca.us>", "tanstaaf")
	want := "c4c9334bac560ecc979e58001b3e22fb"
	if got != want {
		t.Errorf("ApopDigest = %q, want %q", got, want)
	}
}

func TestApopStamp(t *testing.T) {
	cases := []struct {
		greeting string
		want     string
		ok       bool
	}{
		{"+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>", "<1896.697170952@dbc.mtview.ca.us>", true},
		{"+OK <a@b>", "<a@b>", true},
		{"+OK no stamp here", "", false},
		{"+OK <missing-at>", "", false},
		{"+OK <a@>", "", false}, // no vchar after @
		{"+OK <@b>", "", false}, // no vchar before @
		{"+OK plain <x@y> tail", "<x@y>", true},
		{"+OK <>", "", false},  // empty
		{"+OK <ab", "", false}, // no closing >
		// Two '@' / multiple '>' — greedy: ends at last '>', '@' is last before it.
		{"+OK <a@b@c>", "<a@b@c>", true},
		{"+OK <a@b><c@d>", "<a@b><c@d>", true}, // greedy spans both
	}
	for _, c := range cases {
		got, ok := ApopStamp(c.greeting)
		if got != c.want || ok != c.ok {
			t.Errorf("ApopStamp(%q) = (%q,%v), want (%q,%v)", c.greeting, got, ok, c.want, c.ok)
		}
	}
}

func TestIsOK(t *testing.T) {
	cases := []struct {
		res string
		ok  bool
	}{
		{"+OK", true},
		{"+ok done", true},
		{"+Ok", true},
		{"+oK x", true},
		{"-ERR bad", false},
		{"+O", false},
		{"", false},
		{"+X", false},
		{"+OX", false}, // third char not K
	}
	for _, c := range cases {
		if got := IsOK(c.res); got != c.ok {
			t.Errorf("IsOK(%q) = %v, want %v", c.res, got, c.ok)
		}
	}
}

func TestCheckResponse(t *testing.T) {
	if err := CheckResponse("+OK ready"); err != nil {
		t.Errorf("CheckResponse(+OK) = %v, want nil", err)
	}
	err := CheckResponse("-ERR nope")
	var pe *POPError
	if !errors.As(err, &pe) || pe.Response != "-ERR nope" {
		t.Errorf("CheckResponse(-ERR) = %v, want *POPError{-ERR nope}", err)
	}
}

func TestCheckResponseAuth(t *testing.T) {
	if err := CheckResponseAuth("+OK"); err != nil {
		t.Errorf("CheckResponseAuth(+OK) = %v, want nil", err)
	}
	err := CheckResponseAuth("-ERR auth failed")
	var ae *POPAuthenticationError
	if !errors.As(err, &ae) || ae.Response != "-ERR auth failed" {
		t.Errorf("CheckResponseAuth(-ERR) = %v, want *POPAuthenticationError", err)
	}
}

func TestParseStat(t *testing.T) {
	count, size, err := ParseStat("+OK 3 1024")
	if err != nil || count != 3 || size != 1024 {
		t.Errorf("ParseStat = (%d,%d,%v), want (3,1024,nil)", count, size, err)
	}
	// Tab + extra whitespace allowed by \s+.
	count, size, err = ParseStat("+OK\t10  \t 2048 ignored")
	if err != nil || count != 10 || size != 2048 {
		t.Errorf("ParseStat tabs = (%d,%d,%v)", count, size, err)
	}
	// Lowercase +ok also accepted (check_response is case-insensitive upstream).
	count, size, err = ParseStat("+ok 0 0")
	if err != nil || count != 0 || size != 0 {
		t.Errorf("ParseStat +ok = (%d,%d,%v)", count, size, err)
	}
}

func TestParseStatBad(t *testing.T) {
	bad := []string{
		"-ERR x",      // not +OK at all
		"+OK",         // no whitespace/numbers
		"+OK 3",       // only one number
		"+OK abc def", // non-numeric
		"+OKxyz",      // no \s after +OK
		"+OK 3 ",      // second number missing
		"+OK  ",       // whitespace then no digit
	}
	for _, res := range bad {
		_, _, err := ParseStat(res)
		var be *POPBadResponse
		if !errors.As(err, &be) {
			t.Errorf("ParseStat(%q) err = %v, want *POPBadResponse", res, err)
		}
	}
}

func TestParseListItem(t *testing.T) {
	num, length, err := ParseListItem("1 1200")
	if err != nil || num != 1 || length != 1200 {
		t.Errorf("ParseListItem = (%d,%d,%v)", num, length, err)
	}
	// Tab separator and trailing text are tolerated (MRI's regexp is anchored at
	// start only).
	num, length, err = ParseListItem("42\t \t99 trailing")
	if err != nil || num != 42 || length != 99 {
		t.Errorf("ParseListItem tabs = (%d,%d,%v)", num, length, err)
	}
}

func TestParseListItemBad(t *testing.T) {
	bad := []string{"x 1", "1", "1x", "1 ", " 1 2"}
	for _, line := range bad {
		_, _, err := ParseListItem(line)
		var be *POPBadResponse
		if !errors.As(err, &be) || be.Response != line {
			t.Errorf("ParseListItem(%q) = %v, want *POPBadResponse", line, err)
		}
	}
}

func TestParseUidlItem(t *testing.T) {
	cases := []struct {
		line   string
		number int
		uid    string
		ok     bool
	}{
		{"1 whqtswO00WBw418f9t5JxYwZ", 1, "whqtswO00WBw418f9t5JxYwZ", true},
		{"  2   QhdPYR:00WBw1Ph7x7", 2, "QhdPYR:00WBw1Ph7x7", true}, // split(' ') trims/collapses
		{"3", 3, "", true},          // number only
		{"xyz abc", 0, "abc", true}, // to_i of non-numeric leading -> 0
		{"-4 uid", -4, "uid", true}, // to_i handles sign
		{"", 0, "", false},          // empty line
		{"   ", 0, "", false},       // whitespace only
	}
	for _, c := range cases {
		num, uid, ok := ParseUidlItem(c.line)
		if num != c.number || uid != c.uid || ok != c.ok {
			t.Errorf("ParseUidlItem(%q) = (%d,%q,%v), want (%d,%q,%v)",
				c.line, num, uid, ok, c.number, c.uid, c.ok)
		}
	}
}

func TestParseUidlSingle(t *testing.T) {
	// res.split(/ /)[1] — second space-delimited field.
	if got := ParseUidlSingle("+OK 2 QhdPYR:00WBw1Ph7x7"); got != "2" {
		t.Errorf("ParseUidlSingle = %q, want %q", got, "2")
	}
	// split(/ /) keeps empty fields: "+OK  uid" -> ["+OK","","uid"], [1]=="".
	if got := ParseUidlSingle("+OK  uid"); got != "" {
		t.Errorf("ParseUidlSingle double space = %q, want empty", got)
	}
	if got := ParseUidlSingle("+OK"); got != "" {
		t.Errorf("ParseUidlSingle no field = %q, want empty", got)
	}
}

func TestUnstuff(t *testing.T) {
	cases := []struct{ in, want string }{
		{"hello\r\n", "hello\r\n"},
		{".hidden\r\n", "hidden\r\n"},
		{"..dotted\r\n", ".dotted\r\n"},
		{".\r\n", "\r\n"},
		{"", ""},
	}
	for _, c := range cases {
		if got := Unstuff(c.in); got != c.want {
			t.Errorf("Unstuff(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestIsTerminator(t *testing.T) {
	if !IsTerminator(".\r\n") {
		t.Error("IsTerminator(.\\r\\n) = false")
	}
	if IsTerminator("..\r\n") || IsTerminator(".\n") || IsTerminator("x\r\n") {
		t.Error("IsTerminator matched a non-terminator")
	}
}

func TestRubyToIEdge(t *testing.T) {
	// Exercised indirectly via ParseUidlItem, but check the +sign and no-digit
	// branches directly.
	if got := rubyToI("+12abc"); got != 12 {
		t.Errorf("rubyToI(+12abc) = %d, want 12", got)
	}
	if got := rubyToI("nope"); got != 0 {
		t.Errorf("rubyToI(nope) = %d, want 0", got)
	}
	if got := rubyToI("-7zz"); got != -7 {
		t.Errorf("rubyToI(-7zz) = %d, want -7", got)
	}
	if got := rubyToI("-"); got != 0 {
		t.Errorf("rubyToI(-) = %d, want 0", got)
	}
}

func TestChop(t *testing.T) {
	cases := []struct{ in, want string }{
		{"abc\r\n", "abc"},
		{"abc\n", "abc"},
		{"abc", "ab"},
		{"", ""},
	}
	for _, c := range cases {
		if got := chop(c.in); got != c.want {
			t.Errorf("chop(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
