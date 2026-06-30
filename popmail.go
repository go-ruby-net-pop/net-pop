// Copyright (c) the go-ruby-net-pop/net-pop authors
//
// SPDX-License-Identifier: BSD-3-Clause

package netpop

// POPMail is the Go analogue of Net::POPMail: a message that exists on the POP
// server, identified by its sequence Number, with its Length in octets and,
// optionally, its unique-id (UID). MRI constructs these from the LIST reply and
// fills the UID lazily from a UIDL reply.
//
// Unlike MRI's POPMail, this struct holds no back-reference to a live session and
// performs no I/O — it is the parsed data model. The session-driving (pop / top /
// delete / unique_id) lives on Conn, which owns the Transport seam.
type POPMail struct {
	// Number is the message's sequence number on the server (Net::POPMail#number).
	Number int
	// Length is the message size in octets (Net::POPMail#length / #size).
	Length int
	// UID is the message's unique-id (Net::POPMail#unique_id / #uidl), empty until
	// populated from a UIDL response.
	UID string
	// Deleted records whether the message has been marked for deletion this
	// session (Net::POPMail#deleted?). DELE on the server defers actual removal to
	// session end; RSET clears the mark.
	Deleted bool
}

// Size returns the message length in octets, mirroring Net::POPMail#size (an alias
// of #length).
func (m *POPMail) Size() int { return m.Length }

// SetAllUIDs fills the UID of each mail from a number->uid table (as produced by
// Conn.UIDL), mirroring POP3#set_all_uids: m.uid = uidl[m.number]. Mails whose
// number is absent from the table get an empty UID.
func SetAllUIDs(mails []*POPMail, table map[int]string) {
	for _, m := range mails {
		m.UID = table[m.Number]
	}
}
