// Copyright (c) the go-ruby-net-pop/net-pop authors
//
// SPDX-License-Identifier: BSD-3-Clause

package netpop

import "strings"

// Transport is the socket seam. It is the pure-compute boundary of this package:
// everything above it (command bytes, APOP digest, response parsing, multiline
// dot-unstuffing, the POPMail model) is deterministic and Ruby-free; everything
// below it (TCP connect, TLS handshake, timeouts, the actual read/write syscalls)
// is the host's job.
//
// It mirrors the two methods MRI's POP3Command leans on from
// Net::InternetMessageIO:
//
//   - Writeline(line) corresponds to writeline(str): the implementation MUST
//     append a single CRLF — exactly what Net::InternetMessageIO#writeline does.
//     Callers therefore pass the bare command line (e.g. "STAT", "RETR 3").
//   - Readline() corresponds to readline: it returns one response line WITHOUT its
//     trailing CRLF (Net::BufferedIO#readline strips it). The status-line parsers
//     here expect that stripped form.
//
// rbgo wires a real *net.Conn / *tls.Conn behind this; tests use an in-memory
// transport, so the whole suite is deterministic.
type Transport interface {
	// Writeline writes one command line, appending CRLF.
	Writeline(line string) error
	// Readline reads one response line and returns it without the trailing CRLF.
	Readline() (string, error)
	// ReadRawLine reads one line of a multiline body and returns it WITH its
	// trailing CRLF intact, mirroring Net::BufferedIO#readuntil("\r\n"). The
	// terminator detection ((line) != ".\r\n") and the dot-unstuffing depend on
	// the CRLF being present, so multiline reads use this rather than Readline.
	ReadRawLine() (string, error)
}

// Conn drives a POP3 session over a Transport. It is the Go analogue of MRI's
// Net::POP3Command: it issues the commands, validates the "+OK"/"-ERR" status
// replies, parses STAT/LIST/UIDL, and decodes the multiline RETR/TOP bodies — all
// without owning the socket.
type Conn struct {
	t Transport

	// apopStamp is the APOP timestamp extracted from the greeting (empty when the
	// server is not APOP-capable). It is set by Greet.
	apopStamp string
	haveStamp bool
}

// NewConn returns a Conn driving the given Transport. The greeting is not read
// here; call Greet (mirroring how MRI's POP3Command#initialize reads the banner)
// before authenticating.
func NewConn(t Transport) *Conn { return &Conn{t: t} }

// ApopStamp returns the APOP timestamp captured from the greeting, and whether one
// was present. Valid only after Greet.
func (c *Conn) ApopStamp() (string, bool) { return c.apopStamp, c.haveStamp }

// Greet reads and validates the server greeting, capturing the APOP stamp,
// mirroring MRI's POP3Command#initialize:
//
//	res = check_response(critical { recv_response() })
//	@apop_stamp = res.slice(/<[!-~]+@[!-~]+>/)
//
// It returns a *POPError when the greeting is not "+OK".
func (c *Conn) Greet() error {
	res, err := c.t.Readline()
	if err != nil {
		return err
	}
	if err := CheckResponse(res); err != nil {
		return err
	}
	c.apopStamp, c.haveStamp = ApopStamp(res)
	return nil
}

// command writes a line and returns the raw status reply (CRLF already stripped).
func (c *Conn) command(line string) (string, error) {
	if err := c.t.Writeline(line); err != nil {
		return "", err
	}
	return c.t.Readline()
}

// Auth performs USER/PASS authentication, mirroring POP3Command#auth: send USER,
// require "+OK", send PASS, require "+OK". A non-"+OK" reply at either step yields
// a *POPAuthenticationError.
func (c *Conn) Auth(account, password string) error {
	res, err := c.command(UserCommand(account))
	if err != nil {
		return err
	}
	if err := CheckResponseAuth(res); err != nil {
		return err
	}
	res, err = c.command(PassCommand(password))
	if err != nil {
		return err
	}
	return CheckResponseAuth(res)
}

// Apop performs APOP authentication, mirroring POP3Command#apop. It requires that
// the greeting carried an APOP stamp (else MRI raises POPAuthenticationError,
// "not APOP server; cannot login"). A non-"+OK" reply yields a
// *POPAuthenticationError.
func (c *Conn) Apop(account, password string) error {
	if !c.haveStamp {
		return &POPAuthenticationError{Response: "not APOP server; cannot login"}
	}
	res, err := c.command(ApopCommand(account, c.apopStamp, password))
	if err != nil {
		return err
	}
	return CheckResponseAuth(res)
}

// Stat issues STAT and returns (count, totalSize), mirroring POP3Command#stat.
func (c *Conn) Stat() (count, size int, err error) {
	res, err := c.command(StatCommand())
	if err != nil {
		return 0, 0, err
	}
	if err := CheckResponse(res); err != nil {
		return 0, 0, err
	}
	return ParseStat(res)
}

// List issues a multiline LIST and returns one POPMail per message (number +
// length; uid empty until set via SetAllUIDs), mirroring POP3Command#list mapped
// through POP3#mails.
func (c *Conn) List() ([]*POPMail, error) {
	res, err := c.command(ListCommand())
	if err != nil {
		return nil, err
	}
	if err := CheckResponse(res); err != nil {
		return nil, err
	}
	var mails []*POPMail
	err = c.eachListItem(func(line string) error {
		num, length, perr := ParseListItem(line)
		if perr != nil {
			return perr
		}
		mails = append(mails, &POPMail{Number: num, Length: length})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return mails, nil
}

// UIDL issues a multiline UIDL and returns a number->uid table, mirroring
// POP3Command#uidl (no argument).
func (c *Conn) UIDL() (map[int]string, error) {
	res, err := c.command(UidlCommand())
	if err != nil {
		return nil, err
	}
	if err := CheckResponse(res); err != nil {
		return nil, err
	}
	table := map[int]string{}
	err = c.eachListItem(func(line string) error {
		num, uid, ok := ParseUidlItem(line)
		if ok {
			table[num] = uid
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return table, nil
}

// UIDLNum issues a single-message "UIDL <num>" and returns its uid, mirroring
// POP3Command#uidl(num).
func (c *Conn) UIDLNum(num int) (string, error) {
	res, err := c.command(UidlNumCommand(num))
	if err != nil {
		return "", err
	}
	if err := CheckResponse(res); err != nil {
		return "", err
	}
	return ParseUidlSingle(res), nil
}

// Retr issues "RETR <num>" and returns the full message bytes, mirroring
// POP3Command#retr feeding each_message_chunk. Each multiline chunk is
// dot-unstuffed; the ".\r\n" terminator ends the body. The returned bytes are the
// concatenation of the (CRLF-bearing) un-stuffed chunks — exactly what MRI's
// POPMail#pop accumulates.
func (c *Conn) Retr(num int) (string, error) {
	return c.message(RetrCommand(num))
}

// Top issues "TOP <num> <lines>" and returns the header plus the first `lines`
// body lines, mirroring POP3Command#top.
func (c *Conn) Top(num, lines int) (string, error) {
	return c.message(TopCommand(num, lines))
}

// Dele issues "DELE <num>", mirroring POP3Command#dele. A non-"+OK" reply yields
// a *POPError.
func (c *Conn) Dele(num int) error {
	res, err := c.command(DeleCommand(num))
	if err != nil {
		return err
	}
	return CheckResponse(res)
}

// Rset issues RSET, mirroring POP3Command#rset.
func (c *Conn) Rset() error {
	res, err := c.command(RsetCommand())
	if err != nil {
		return err
	}
	return CheckResponse(res)
}

// Noop issues NOOP and requires a "+OK" reply. NOOP is not used by MRI's net-pop,
// but is a standard no-argument POP3 keepalive (RFC 1939); we validate the reply
// the same way the other single-line commands do.
func (c *Conn) Noop() error {
	res, err := c.command(NoopCommand())
	if err != nil {
		return err
	}
	return CheckResponse(res)
}

// Quit issues QUIT, mirroring POP3Command#quit.
func (c *Conn) Quit() error {
	res, err := c.command(QuitCommand())
	if err != nil {
		return err
	}
	return CheckResponse(res)
}

// Stls issues STLS (RFC 2595 STARTTLS for POP3) and requires a "+OK" reply. After
// a "+OK" the host is expected to upgrade the underlying Transport to TLS; that
// upgrade is the socket seam's concern, not this codec's.
func (c *Conn) Stls() error {
	res, err := c.command(StlsCommand())
	if err != nil {
		return err
	}
	return CheckResponse(res)
}

// eachListItem reads a multiline list response, invoking fn with each item line
// (CRLF chopped), mirroring InternetMessageIO#each_list_item:
//
//	while (str = readuntil("\r\n")) != ".\r\n"
//	  yield str.chop
//	end
//
// Ruby's String#chop removes a trailing "\r\n" pair (or a single trailing char).
func (c *Conn) eachListItem(fn func(line string) error) error {
	for {
		raw, err := c.t.ReadRawLine()
		if err != nil {
			return err
		}
		if IsTerminator(raw) {
			return nil
		}
		if err := fn(chop(raw)); err != nil {
			return err
		}
	}
}

// message reads a multiline message body after a command whose "+OK" must hold,
// mirroring POP3Command#retr/#top driving InternetMessageIO#each_message_chunk:
//
//	while (line = readuntil("\r\n")) != ".\r\n"
//	  yield line.delete_prefix('.')
//	end
//
// The yielded chunks (each still CRLF-terminated) are concatenated and returned.
func (c *Conn) message(line string) (string, error) {
	res, err := c.command(line)
	if err != nil {
		return "", err
	}
	if err := CheckResponse(res); err != nil {
		return "", err
	}
	var b strings.Builder
	for {
		raw, err := c.t.ReadRawLine()
		if err != nil {
			return "", err
		}
		if IsTerminator(raw) {
			return b.String(), nil
		}
		b.WriteString(Unstuff(raw))
	}
}

// chop mimics Ruby's String#chop: remove a trailing "\r\n" pair, or otherwise a
// single trailing character. An empty string is returned unchanged.
func chop(s string) string {
	if strings.HasSuffix(s, "\r\n") {
		return s[:len(s)-2]
	}
	if len(s) == 0 {
		return s
	}
	return s[:len(s)-1]
}
