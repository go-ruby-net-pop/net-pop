// Copyright (c) the go-ruby-net-pop/net-pop authors
//
// SPDX-License-Identifier: BSD-3-Clause

package netpop

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// rubyBin locates a usable `ruby` once. The oracle tests skip themselves when it
// is absent (the qemu cross-arch lanes and the Windows lane), so the deterministic
// in-memory suite alone drives the 100% gate there.
func rubyBin(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("ruby")
	if err != nil {
		t.Skip("ruby not on PATH; skipping MRI net/pop oracle")
	}
	return path
}

// rubyEval runs a Ruby script with net/pop + digest/md5 loaded and returns stdout.
// $stdout.binmode keeps Windows text-mode from rewriting the CRLFs we compare —
// the POP3 wire bytes are CRLF-significant, so a stray translation would corrupt
// the comparison. (Windows skips these tests anyway via the no-ruby guard, but the
// binmode keeps the oracle honest on any platform.)
func rubyEval(t *testing.T, bin, script string) string {
	t.Helper()
	cmd := exec.Command(bin, "-rnet/pop", "-rdigest/md5", "-e", "$stdout.binmode\n"+script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ruby error: %v\nscript:\n%s\noutput:\n%s", err, script, out)
	}
	return string(out)
}

// TestOracleCommandBytes proves the command lines this package builds are exactly
// what MRI's Net::POP3Command writes: sprintf(fmt, *args) for every command form
// net/pop.rb uses. We ask Ruby to render each sprintf and compare byte-for-byte.
func TestOracleCommandBytes(t *testing.T) {
	bin := rubyBin(t)
	out := rubyEval(t, bin, `
puts (sprintf 'USER %s', 'alice')
puts (sprintf 'PASS %s', 's3cret')
puts (sprintf 'APOP %s %s', 'alice', Digest::MD5.hexdigest('<1896.697170952@dbc.mtview.ca.us>' + 'tanstaaf'))
puts 'STAT'
puts 'LIST'
puts 'UIDL'
puts (sprintf 'UIDL %d', 7)
puts (sprintf 'RETR %d', 3)
puts (sprintf 'TOP %d %d', 2, 10)
puts (sprintf 'DELE %d', 5)
puts 'RSET'
puts 'QUIT'
`)
	want := []string{
		UserCommand("alice"),
		PassCommand("s3cret"),
		ApopCommand("alice", "<1896.697170952@dbc.mtview.ca.us>", "tanstaaf"),
		StatCommand(),
		ListCommand(),
		UidlCommand(),
		UidlNumCommand(7),
		RetrCommand(3),
		TopCommand(2, 10),
		DeleCommand(5),
		RsetCommand(),
		QuitCommand(),
	}
	got := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(got) != len(want) {
		t.Fatalf("ruby produced %d lines, want %d:\n%q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("command[%d] ruby=%q go=%q", i, got[i], want[i])
		}
	}
}

// TestOracleApopDigest proves the APOP digest matches MRI's
// Digest::MD5.hexdigest(stamp + password) across several inputs.
func TestOracleApopDigest(t *testing.T) {
	bin := rubyBin(t)
	cases := []struct{ stamp, pass string }{
		{"<1896.697170952@dbc.mtview.ca.us>", "tanstaaf"},
		{"<a@b>", ""},
		{"<x.y@host.example>", "p@ss w0rd!"},
	}
	for _, c := range cases {
		out := rubyEval(t, bin, `print Digest::MD5.hexdigest(`+
			strconv.Quote(c.stamp)+`+`+strconv.Quote(c.pass)+`)`)
		if got := ApopDigest(c.stamp, c.pass); got != out {
			t.Errorf("APOP digest stamp=%q pass=%q go=%q ruby=%q", c.stamp, c.pass, got, out)
		}
	}
}

// TestOracleApopStamp proves the greeting-stamp extraction matches MRI's
// res.slice(/<[!-~]+@[!-~]+>/) on a spread of greeting shapes (matching and not).
func TestOracleApopStamp(t *testing.T) {
	bin := rubyBin(t)
	greetings := []string{
		"+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>",
		"+OK <a@b>",
		"+OK no stamp here",
		"+OK <missing-at>",
		"+OK <a@>",
		"+OK <@b>",
		"+OK plain <x@y> tail",
		"+OK <>",
		"+OK <ab",
		"+OK <a@b@c>",
		"+OK <a@b><c@d>",
	}
	for _, g := range greetings {
		out := rubyEval(t, bin, `s=`+strconv.Quote(g)+`.slice(/<[!-~]+@[!-~]+>/); print(s.nil? ? "\x00NIL" : s)`)
		gotStamp, ok := ApopStamp(g)
		wantStamp, wantOK := "", true
		if out == "\x00NIL" {
			wantStamp, wantOK = "", false
		} else {
			wantStamp = out
		}
		if gotStamp != wantStamp || ok != wantOK {
			t.Errorf("ApopStamp(%q) go=(%q,%v) ruby=(%q,%v)", g, gotStamp, ok, wantStamp, wantOK)
		}
	}
}

// TestOracleStat proves the STAT parse matches MRI's
// /\A\+OK\s+(\d+)\s+(\d+)/ capture-to-Integer.
func TestOracleStat(t *testing.T) {
	bin := rubyBin(t)
	replies := []string{"+OK 3 1024", "+OK\t10  \t 2048", "+OK 0 0"}
	for _, res := range replies {
		out := rubyEval(t, bin, `m=/\A\+OK\s+(\d+)\s+(\d+)/.match(`+strconv.Quote(res)+`); print "#{m[1].to_i} #{m[2].to_i}"`)
		count, size, err := ParseStat(res)
		want := strconv.Itoa(count) + " " + strconv.Itoa(size)
		if err != nil || want != out {
			t.Errorf("ParseStat(%q) go=%q ruby=%q err=%v", res, want, out, err)
		}
	}
}

// TestOracleListItem proves the LIST item parse matches MRI's
// /\A(\d+)[ \t]+(\d+)/ capture-to-Integer.
func TestOracleListItem(t *testing.T) {
	bin := rubyBin(t)
	lines := []string{"1 1200", "42\t \t99 trailing", "7   33"}
	for _, line := range lines {
		out := rubyEval(t, bin, `m=/\A(\d+)[ \t]+(\d+)/.match(`+strconv.Quote(line)+`); print "#{m[1].to_i} #{m[2].to_i}"`)
		num, length, err := ParseListItem(line)
		want := strconv.Itoa(num) + " " + strconv.Itoa(length)
		if err != nil || want != out {
			t.Errorf("ParseListItem(%q) go=%q ruby=%q err=%v", line, want, out, err)
		}
	}
}

// TestOracleUidlItem proves the multiline-UIDL item parse matches MRI's
// num, uid = line.split(' '); table[num.to_i] = uid.
func TestOracleUidlItem(t *testing.T) {
	bin := rubyBin(t)
	lines := []string{"1 whqtswO00WBw418f9t5JxYwZ", "  2   QhdPYR:00WBw1Ph7x7", "3", "xyz abc"}
	for _, line := range lines {
		out := rubyEval(t, bin, `num, uid = `+strconv.Quote(line)+`.split(' '); print "#{num.to_i}\x01#{uid}"`)
		number, uid, ok := ParseUidlItem(line)
		if !ok {
			t.Fatalf("ParseUidlItem(%q) ok=false unexpectedly", line)
		}
		want := strconv.Itoa(number) + "\x01" + uid
		if want != out {
			t.Errorf("ParseUidlItem(%q) go=%q ruby=%q", line, want, out)
		}
	}
}

// TestOracleUidlSingle proves the single-message UIDL parse matches MRI's
// res.split(/ /)[1].
func TestOracleUidlSingle(t *testing.T) {
	bin := rubyBin(t)
	replies := []string{"+OK 2 QhdPYR:00WBw1Ph7x7", "+OK  uid", "+OK"}
	for _, res := range replies {
		out := rubyEval(t, bin, `v=`+strconv.Quote(res)+`.split(/ /)[1]; print(v.nil? ? "" : v)`)
		if got := ParseUidlSingle(res); got != out {
			t.Errorf("ParseUidlSingle(%q) go=%q ruby=%q", res, got, out)
		}
	}
}

// TestOracleUnstuff proves multiline chunk un-stuffing matches MRI's
// line.delete_prefix('.') (each_message_chunk).
func TestOracleUnstuff(t *testing.T) {
	bin := rubyBin(t)
	lines := []string{"hello\r\n", ".hidden\r\n", "..dotted\r\n", ".\r\n", "plain"}
	for _, line := range lines {
		out := rubyEval(t, bin, `print `+strconv.Quote(line)+`.delete_prefix('.')`)
		if got := Unstuff(line); got != out {
			t.Errorf("Unstuff(%q) go=%q ruby=%q", line, got, out)
		}
	}
}

// TestOracleChop proves the LIST/UIDL item CRLF trim matches MRI's String#chop.
func TestOracleChop(t *testing.T) {
	bin := rubyBin(t)
	lines := []string{"1 120\r\n", "abc\n", "x", ""}
	for _, line := range lines {
		out := rubyEval(t, bin, `print `+strconv.Quote(line)+`.chop`)
		if got := chop(line); got != out {
			t.Errorf("chop(%q) go=%q ruby=%q", line, got, out)
		}
	}
}

// TestOracleMultilineRoundTrip proves the full multiline decode (terminator
// detection + un-stuffing) reproduces MRI's each_message_chunk over a body that a
// server would have dot-stuffed. We build a body, dot-stuff it the way a server
// must (MRI's dot_stuff: leading "." -> ".."), feed the wire form through this
// package's Conn, and check we recover the original — matching what MRI's
// POPMail#pop would accumulate.
func TestOracleMultilineRoundTrip(t *testing.T) {
	bin := rubyBin(t)
	// The "original" message lines (each terminated with CRLF on the wire).
	bodyLines := []string{"Subject: test", ".signature", "..already", "regular"}

	// Ask Ruby to produce the dot-stuffed wire form (server side) and the decoded
	// form (client side), so the oracle owns both directions.
	script := `
lines = ["Subject: test", ".signature", "..already", "regular"]
wire = lines.map { |l| (l.sub(/\A\./, '..')) + "\r\n" }.join + ".\r\n"
print wire`
	wire := rubyEval(t, bin, script)

	// Drive the same wire bytes through this package via a scripted transport.
	raws := splitKeepCRLF(wire)
	tr := &memTransport{replies: prepReplies(raws)}
	c := NewConn(tr)
	got, err := c.Retr(1)
	if err != nil {
		t.Fatalf("Retr over oracle wire: %v", err)
	}
	want := strings.Join(bodyLines, "\r\n") + "\r\n"
	if got != want {
		t.Errorf("multiline decode go=%q want=%q (wire=%q)", got, want, wire)
	}
}

// splitKeepCRLF splits a CRLF-delimited blob into lines, each WITHOUT its CRLF
// (the memTransport re-adds CRLF on ReadRawLine). The leading "+OK" status line is
// not part of wire; we prepend it in prepReplies.
func splitKeepCRLF(s string) []string {
	parts := strings.Split(s, "\r\n")
	// Trailing element after the final CRLF is empty; drop it.
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// prepReplies prepends the "+OK" status line the Retr command expects before the
// multiline body lines.
func prepReplies(bodyLines []string) []string {
	return append([]string{"+OK message follows"}, bodyLines...)
}
