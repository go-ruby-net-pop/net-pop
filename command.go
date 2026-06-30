// Copyright (c) the go-ruby-net-pop/net-pop authors
//
// SPDX-License-Identifier: BSD-3-Clause

// Package netpop is a pure-Go (CGO=0) reimplementation of the POP3 protocol
// codec at the heart of Ruby's Net::POP3 — MRI's net-pop gem (net/pop.rb on top
// of net/protocol.rb).
//
// It builds the POP3 command bytes (USER/PASS/APOP/STAT/LIST/UIDL/RETR/TOP/DELE/
// RSET/NOOP/QUIT/STLS), computes the APOP MD5 digest, parses the "+OK"/"-ERR"
// status replies, and decodes a multiline response — the ".\r\n" terminator plus
// the leading-dot un-stuffing — into the Net::POPMail model (number / length /
// unique-id). It matches MRI byte-for-byte on the wire bytes and on the parsed
// values, without any Ruby runtime.
//
// The connect / read / write / TLS is the host's job, injected as a small
// Transport interface (Writeline + Readline). rbgo wires a real TCP/TLS socket;
// tests use an in-memory transport, so the whole suite is deterministic and
// Ruby-free — exactly mirroring how MRI layers Net::POP3Command over the
// Net::InternetMessageIO socket.
package netpop

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

// crlf is the line terminator POP3 (and Net::InternetMessageIO#writeline) append
// to every command line.
const crlf = "\r\n"

//
// Command builders — the exact bytes MRI's POP3Command writes.
//
// MRI builds each command with sprintf(fmt, *args) and then InternetMessageIO#
// writeline, which appends "\r\n". So the wire bytes are sprintf-result + "\r\n".
// We reproduce sprintf for the handful of formats net/pop.rb actually uses:
//
//	'USER %s'   'PASS %s'   'APOP %s %s'
//	'STAT'      'LIST'      'UIDL'        'UIDL %d'
//	'RETR %d'   'TOP %d %d' 'DELE %d'
//	'RSET'      'QUIT'
//
// The numeric arguments are Integers in Ruby, so '%d' is a plain base-10 render.
// STLS / NOOP are not used by this net-pop release, but POP3 (RFC 2449 / RFC 2595)
// defines them with no arguments; we expose the obvious "<VERB>" form for callers
// that drive STLS-then-TLS upgrades or keepalive NOOPs.

// UserCommand builds the USER command line (without the trailing CRLF):
// "USER <account>". Equivalent to sprintf('USER %s', account).
func UserCommand(account string) string { return "USER " + account }

// PassCommand builds the PASS command line: "PASS <password>".
func PassCommand(password string) string { return "PASS " + password }

// ApopCommand builds the APOP command line: "APOP <account> <digest>", where
// digest is the lowercase hex MD5 of (stamp + password). This is the exact line
// MRI's POP3Command#apop writes.
func ApopCommand(account, stamp, password string) string {
	return "APOP " + account + " " + ApopDigest(stamp, password)
}

// StatCommand builds the STAT command line: "STAT".
func StatCommand() string { return "STAT" }

// ListCommand builds the multiline-LIST command line: "LIST".
func ListCommand() string { return "LIST" }

// UidlCommand builds the multiline-UIDL command line: "UIDL".
func UidlCommand() string { return "UIDL" }

// UidlNumCommand builds the single-message UIDL command line: "UIDL <num>".
// Equivalent to sprintf('UIDL %d', num).
func UidlNumCommand(num int) string { return "UIDL " + strconv.Itoa(num) }

// RetrCommand builds the RETR command line: "RETR <num>".
func RetrCommand(num int) string { return "RETR " + strconv.Itoa(num) }

// TopCommand builds the TOP command line: "TOP <num> <lines>".
// Equivalent to sprintf('TOP %d %d', num, lines).
func TopCommand(num, lines int) string {
	return "TOP " + strconv.Itoa(num) + " " + strconv.Itoa(lines)
}

// DeleCommand builds the DELE command line: "DELE <num>".
func DeleCommand(num int) string { return "DELE " + strconv.Itoa(num) }

// RsetCommand builds the RSET command line: "RSET".
func RsetCommand() string { return "RSET" }

// NoopCommand builds the NOOP command line: "NOOP".
func NoopCommand() string { return "NOOP" }

// QuitCommand builds the QUIT command line: "QUIT".
func QuitCommand() string { return "QUIT" }

// StlsCommand builds the STLS command line: "STLS" (RFC 2595 STARTTLS for POP3).
func StlsCommand() string { return "STLS" }

// Writeline renders a command line as the bytes MRI's
// InternetMessageIO#writeline puts on the wire: the line plus a single CRLF.
func Writeline(line string) string { return line + crlf }

//
// APOP digest.
//

// ApopDigest computes the APOP authentication digest exactly as MRI does:
// Digest::MD5.hexdigest(stamp + password), where stamp is the server-greeting
// timestamp token (including its surrounding angle brackets) and the result is
// lowercase hex. See RFC 1939 §7.
func ApopDigest(stamp, password string) string {
	sum := md5.Sum([]byte(stamp + password))
	return hex.EncodeToString(sum[:])
}

//
// Greeting / APOP-stamp extraction.
//

// ApopStamp extracts the APOP timestamp from a server greeting line, matching
// MRI's POP3Command#initialize: res.slice(/<[!-~]+@[!-~]+>/). It returns the
// "<...@...>" token (brackets included) and ok==true, or ("", false) when the
// greeting carries no APOP stamp.
//
// The Ruby regexp /<[!-~]+@[!-~]+>/ matches the *first* "<", one-or-more printable
// ASCII (0x21..0x7e) characters, an "@", one-or-more printable ASCII, and a ">".
// Because "@" and ">" are themselves in [!-~], the "+" quantifiers backtrack to
// the last "@" / first ">" that still satisfies the whole pattern; we reproduce
// that leftmost-longest-with-required-tail behaviour directly.
func ApopStamp(greeting string) (string, bool) {
	for start := 0; start < len(greeting); start++ {
		if greeting[start] != '<' {
			continue
		}
		// Scan the maximal run of printable ASCII after '<'.
		i := start + 1
		for i < len(greeting) && isVchar(greeting[i]) {
			i++
		}
		// The run must contain an '@' (with >=1 vchar each side) and end at a '>'.
		// Ruby's regexp requires the final char be '>' and an '@' to exist with at
		// least one vchar before it and after it. We look for a '@' position p with
		// start+1 <= p (one vchar before) ... '>' after at least one vchar.
		// Because '>' is a vchar it is included in the run; the pattern's trailing
		// literal '>' means the match ends at some '>' within [start+1, i).
		// Greedy [!-~]+ before '>' takes as much as possible, so the match ends at
		// the LAST '>' in the run; the '@' is the LAST '@' before that '>' that
		// still leaves >=1 vchar on each side.
		end := -1
		for j := i - 1; j > start; j-- {
			if greeting[j] == '>' {
				end = j
				break
			}
		}
		if end == -1 {
			continue
		}
		// Need an '@' strictly between start+1 and end, with a vchar on each side.
		at := -1
		for j := end - 1; j > start+1; j-- {
			if greeting[j] == '@' {
				at = j
				break
			}
		}
		// Require >=1 vchar before '@' (at > start+1) and >=1 after it (end-at >= 2).
		if at <= start+1 || end-at < 2 {
			continue
		}
		return greeting[start : end+1], true
	}
	return "", false
}

// isVchar reports whether b is in the Ruby [!-~] class: printable ASCII excluding
// space (0x21 through 0x7e inclusive).
func isVchar(b byte) bool { return b >= 0x21 && b <= 0x7e }

//
// Status-reply parsing.
//

// IsOK reports whether a status reply indicates success, matching MRI's
// check_response: /\A\+OK/i — a case-insensitive "+OK" anchored at the start.
func IsOK(res string) bool {
	if len(res) < 3 {
		return false
	}
	return res[0] == '+' &&
		(res[1] == 'O' || res[1] == 'o') &&
		(res[2] == 'K' || res[2] == 'k')
}

// CheckResponse returns a *POPError when res is not a "+OK" reply, matching MRI's
// POP3Command#check_response. The error carries res verbatim (MRI raises
// POPError with the response string).
func CheckResponse(res string) error {
	if !IsOK(res) {
		return &POPError{Response: res}
	}
	return nil
}

// CheckResponseAuth returns a *POPAuthenticationError when res is not a "+OK"
// reply, matching MRI's POP3Command#check_response_auth.
func CheckResponseAuth(res string) error {
	if !IsOK(res) {
		return &POPAuthenticationError{Response: res}
	}
	return nil
}

//
// STAT parsing.
//

// ParseStat parses a STAT "+OK" reply into the (count, size) pair, matching MRI's
// POP3Command#stat: /\A\+OK\s+(\d+)\s+(\d+)/. The reply must begin with "+OK"
// (any case — MRI's regexp uses a literal "+OK", but the reply has already been
// validated by check_response which is case-insensitive; we accept either case
// here for the literal "+OK", then the two whitespace-separated decimals). On a
// shape mismatch it returns a *POPBadResponse carrying res, exactly as MRI raises
// "wrong response format: <res>".
//
// Note: MRI raises POPBadResponse with the *message* "wrong response format:
// #{res}". We surface res itself in the typed error and leave the human prefix to
// the caller's formatting, so the parsed-value comparison stays byte-exact.
func ParseStat(res string) (count, size int, err error) {
	rest, ok := stripOKLiteral(res)
	if !ok {
		return 0, 0, &POPBadResponse{Response: res}
	}
	// \s+ then \d+ then \s+ then \d+.
	rest, ok = skipSpaces(rest, true)
	if !ok {
		return 0, 0, &POPBadResponse{Response: res}
	}
	count, rest, ok = scanDigits(rest)
	if !ok {
		return 0, 0, &POPBadResponse{Response: res}
	}
	rest, ok = skipSpaces(rest, true)
	if !ok {
		return 0, 0, &POPBadResponse{Response: res}
	}
	size, _, ok = scanDigits(rest)
	if !ok {
		return 0, 0, &POPBadResponse{Response: res}
	}
	return count, size, nil
}

// stripOKLiteral consumes a leading "+OK" (matched case-insensitively, as the
// reply has already passed check_response) and returns the remainder.
func stripOKLiteral(res string) (string, bool) {
	if !IsOK(res) {
		return "", false
	}
	return res[3:], true
}

// skipSpaces consumes a run of Ruby \s whitespace ([ \t\r\n\f\v]). When required
// is true it demands at least one whitespace character (the \s+ in MRI's regexp).
func skipSpaces(s string, required bool) (string, bool) {
	i := 0
	for i < len(s) && isSpace(s[i]) {
		i++
	}
	if required && i == 0 {
		return s, false
	}
	return s[i:], true
}

// isSpace matches Ruby's \s character class for ASCII: space, tab, newline,
// carriage return, form feed, vertical tab.
func isSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	}
	return false
}

// scanDigits consumes a run of ASCII decimal digits and returns its integer value
// and the remainder. ok is false when no digit is present.
func scanDigits(s string) (val int, rest string, ok bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, s, false
	}
	n, _ := strconv.Atoi(s[:i])
	return n, s[i:], true
}

//
// LIST / UIDL item parsing.
//

// ParseListItem parses one line of a multiline LIST response into (number,
// length), matching MRI's POP3Command#list: /\A(\d+)[ \t]+(\d+)/ over a line that
// has already had its CRLF chopped. On mismatch it returns a *POPBadResponse
// (MRI raises POPBadResponse, "bad response: #{line}").
func ParseListItem(line string) (number, length int, err error) {
	number, rest, ok := scanDigits(line)
	if !ok {
		return 0, 0, &POPBadResponse{Response: line}
	}
	// [ \t]+ — at least one space or tab.
	i := 0
	for i < len(rest) && (rest[i] == ' ' || rest[i] == '\t') {
		i++
	}
	if i == 0 {
		return 0, 0, &POPBadResponse{Response: line}
	}
	length, _, ok = scanDigits(rest[i:])
	if !ok {
		return 0, 0, &POPBadResponse{Response: line}
	}
	return number, length, nil
}

// ParseUidlItem parses one line of a multiline UIDL response into (number, uid),
// matching MRI's POP3Command#uidl: num, uid = line.split(' '). Ruby's String#split
// with a single ASCII-space argument splits on runs of *any* whitespace and
// discards leading whitespace, so "  3   abc " yields ["3", "abc"]. We reproduce
// that. A line with no fields yields ok==false (MRI would leave num/uid nil; the
// caller skips such a degenerate line — it never reaches here for a well-formed
// terminator).
func ParseUidlItem(line string) (number int, uid string, ok bool) {
	fields := splitWhitespace(line)
	if len(fields) == 0 {
		return 0, "", false
	}
	n, err := strconv.Atoi(fields[0])
	if err != nil {
		// MRI does num.to_i, which yields 0 for a non-numeric leading token.
		n = rubyToI(fields[0])
	}
	if len(fields) < 2 {
		return n, "", true
	}
	return n, fields[1], true
}

// ParseUidlSingle parses a single-message "UIDL <num>" "+OK" reply into the uid,
// matching MRI's POP3Command#uidl(num): res.split(/ /)[1]. Ruby's split(/ /) on a
// single-space *regexp* (not the special " " string) does NOT collapse runs and
// keeps leading empty fields, so the second field is res.split(/ /)[1]. We
// reproduce that exact indexing.
func ParseUidlSingle(res string) string {
	parts := strings.Split(res, " ")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// splitWhitespace mimics Ruby's String#split(' '): split on runs of whitespace,
// ignoring leading whitespace, producing no empty fields.
func splitWhitespace(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', '\f', '\v':
			return true
		}
		return false
	})
}

// rubyToI mimics Ruby's String#to_i for the leading-integer case: parse an
// optional sign and the leading decimal digits, yielding 0 when none are present.
func rubyToI(s string) int {
	i := 0
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == start {
		return 0
	}
	n, _ := strconv.Atoi(s[start:i])
	if neg {
		return -n
	}
	return n
}

//
// Multiline-response decoding (the ".\r\n" terminator + dot-unstuffing).
//

// Unstuff removes one leading "." from a multiline message chunk, matching MRI's
// each_message_chunk: line.delete_prefix('.'). Only a single leading dot is
// stripped (so a line that was ".." on the wire becomes "."), and a line with no
// leading dot is returned unchanged.
func Unstuff(line string) string {
	if len(line) > 0 && line[0] == '.' {
		return line[1:]
	}
	return line
}

// IsTerminator reports whether a raw read line (still bearing its CRLF) is the
// "." -on-its-own-line multiline terminator ".\r\n", matching MRI's loop guard
// `(line = readuntil("\r\n")) != ".\r\n"`.
func IsTerminator(rawLine string) bool { return rawLine == ".\r\n" }
