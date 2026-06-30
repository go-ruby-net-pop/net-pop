// Copyright (c) the go-ruby-net-pop/net-pop authors
//
// SPDX-License-Identifier: BSD-3-Clause

package netpop

// The error hierarchy mirrors MRI's net/pop.rb, where:
//
//	POPError              < ProtocolError
//	POPAuthenticationError < ProtoAuthError
//	POPBadResponse        < POPError
//
// MRI raises POPError for an ordinary "-ERR" reply, POPAuthenticationError when
// the USER/PASS/APOP exchange fails, and POPBadResponse when a reply that should
// match a fixed shape (the "+OK" line of STAT, a LIST/UIDL item) does not. We
// expose each as a distinct Go error type carrying the offending server line, so
// callers can switch on the kind exactly as a Ruby program would rescue on class.

// POPError is the base error: an ordinary non-authentication "-ERR" reply (or any
// reply that does not begin with "+OK"). It corresponds to Net::POPError.
type POPError struct {
	// Response is the raw server line that triggered the error, with its CRLF
	// terminator already stripped — exactly the String MRI passes to raise.
	Response string
}

func (e *POPError) Error() string { return e.Response }

// POPAuthenticationError is raised when authentication (USER/PASS or APOP) fails.
// It corresponds to Net::POPAuthenticationError.
type POPAuthenticationError struct {
	Response string
}

func (e *POPAuthenticationError) Error() string { return e.Response }

// POPBadResponse is raised when the server returns a reply that does not match
// the expected shape for STAT/LIST/UIDL. It corresponds to Net::POPBadResponse.
type POPBadResponse struct {
	Response string
}

func (e *POPBadResponse) Error() string { return e.Response }
