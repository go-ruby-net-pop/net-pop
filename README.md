<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-net-pop/brand/main/social/go-ruby-net-pop-net-pop.png" alt="go-ruby-net-pop/net-pop" width="720"></p>

# net-pop — go-ruby-net-pop

[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-net-pop.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![Coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#tests--coverage)

**A pure-Go (no cgo) reimplementation of the POP3 protocol codec at the heart of
Ruby's [Net::POP3](https://docs.ruby-lang.org/en/master/Net/POP3.html)** — MRI
4.0.5's `net-pop` gem (`net/pop.rb` layered over `net/protocol.rb`). It builds the
POP3 command bytes, computes the APOP digest, parses the `+OK`/`-ERR` status
replies, and decodes the multiline responses (the `.`-on-its-own-line terminator
plus the leading-dot un-stuffing) into the `Net::POPMail` model — so the bytes on
the wire and the parsed values are **byte-compatible with MRI's Net::POP3**,
**without any Ruby runtime**.

It is the `Net::POP3` backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby), but is a
**standalone, reusable** module — a sibling of
[go-ruby-marshal](https://github.com/go-ruby-marshal/marshal),
[go-ruby-yaml](https://github.com/go-ruby-yaml/yaml),
[go-ruby-syslog](https://github.com/go-ruby-syslog/syslog),
[go-ruby-regexp](https://github.com/go-ruby-regexp/regexp), and
[go-ruby-erb](https://github.com/go-ruby-erb/erb).

> **What it is — and isn't.** The protocol codec — the command bytes
> (`USER`/`PASS`/`APOP`/`STAT`/`LIST`/`UIDL`/`RETR`/`TOP`/`DELE`/`RSET`/`NOOP`/
> `QUIT`/`STLS`), the `Digest::MD5.hexdigest(stamp + password)` APOP digest, the
> `/\A\+OK/i` status check, the STAT/LIST/UIDL field parsing, and the multiline
> dot-unstuffing — is fully deterministic and needs **no interpreter**, so it
> lives here as pure Go. The *socket* half — opening the TCP connection, the TLS
> (`STLS`) upgrade, timeouts, the actual `read`/`write` syscalls that MRI's
> `Net::InternetMessageIO` performs — is the host's job, injected as a small
> `Transport` interface (`Writeline` / `Readline` / `ReadRawLine`). rbgo wires the
> real socket; tests use an in-memory transport, so the whole suite is
> deterministic and Ruby-free.

## Features

A faithful port of `Net::POP3`'s protocol layer, validated against the `ruby`
binary on every supported platform:

- **Command codec** — every command line MRI's `Net::POP3Command` writes, built
  exactly as `sprintf(fmt, *args)` + `writeline`'s trailing CRLF:
  `USER`/`PASS`/`APOP`/`STAT`/`LIST`/`UIDL`/`UIDL n`/`RETR n`/`TOP n m`/`DELE n`/
  `RSET`/`NOOP`/`QUIT`/`STLS`.
- **APOP digest** — `ApopDigest(stamp, password)` reproduces
  `Digest::MD5.hexdigest(stamp + password)` (RFC 1939 §7), and `ApopStamp`
  extracts the greeting timestamp exactly as `res.slice(/<[!-~]+@[!-~]+>/)`.
- **Status parsing** — `IsOK` / `CheckResponse` / `CheckResponseAuth` mirror the
  `/\A\+OK/i` check; the typed `POPError` / `POPAuthenticationError` /
  `POPBadResponse` hierarchy mirrors `Net::POPError` < `ProtocolError`,
  `Net::POPAuthenticationError` < `ProtoAuthError`, and `Net::POPBadResponse` <
  `POPError`.
- **Field parsing** — `STAT` (`/\A\+OK\s+(\d+)\s+(\d+)/`), `LIST`
  (`/\A(\d+)[ \t]+(\d+)/`), multiline `UIDL` (`line.split(' ')`), and single
  `UIDL n` (`res.split(/ /)[1]`) → the `POPMail` model (number / length / UID).
- **Multiline decode** — the `.\r\n` terminator detection and the
  `line.delete_prefix('.')` dot-unstuffing of `each_message_chunk`, plus the
  `str.chop` of `each_list_item`.

## Usage

```go
import netpop "github.com/go-ruby-net-pop/net-pop"

// Wire your TCP/TLS socket behind the Transport seam, then:
c := netpop.NewConn(transport)
if err := c.Greet(); err != nil {        // read the +OK banner, capture APOP stamp
    return err
}
if err := c.Auth("alice", "secret"); err != nil {
    return err
}
mails, err := c.List()                   // []*POPMail with Number + Length
if err != nil {
    return err
}
body, err := c.Retr(mails[0].Number)     // full message, dot-unstuffed
```

The pure-compute helpers (`UserCommand`, `ApopDigest`, `ParseStat`,
`ParseListItem`, `Unstuff`, …) are exported too, so a host can drive the protocol
itself and reuse only the codec.

## Tests & coverage

`go test` keeps **100% statement coverage**. The differential-vs-MRI oracle tests
drive a real `ruby -rnet/pop` to confirm byte-parity on the command bytes, the
APOP digest, the greeting-stamp regexp, the STAT/LIST/UIDL parses, and the
multiline dot-unstuffing; they skip themselves where `ruby` is absent (the Windows
lane and the qemu cross-arch lanes), so the deterministic in-memory suite alone
holds the gate there. CI runs on Linux/macOS/Windows and on all six supported
64-bit architectures (amd64/arm64/riscv64/loong64/ppc64le/s390x).

```sh
go test -race -coverprofile=cover.out ./...
go tool cover -func=cover.out | tail -1
```

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright (c) 2026, the
go-ruby-net-pop/net-pop authors.
