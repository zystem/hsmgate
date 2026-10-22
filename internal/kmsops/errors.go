// Package kmsops is what the key-service faces share (the KMS-JSON face, the gRPC face, the REST face): the judgement of a request (is the key on this face, is the client
// allowed, is the key used for what it is made for, is there budget), the additional data, the sealing and opening of a blob that names its key and version, signing, the derived
// MAC key, the public key. A face parses its own protocol, asks this package, and puts the answer into its own words. Errors are typed, so that each face maps them to the
// codes its clients know; nothing here knows HTTP or a protocol.
package kmsops

import "fmt"

// Kind is the sort of a failure.
type Kind int

const (
	Denied        Kind = iota + 1 // the key does not exist on this face, or the client has no right to it: one answer for both
	Usage                         // the key cannot be used this way (a sealing key asked to sign)
	Invalid                       // the request is wrong: a size, a context, a digest
	Throttled                     // the budget of the client is spent
	Busy                          // the line to the token is full or the wait is over
	BadCiphertext                 // the blob is damaged, or not for this key, version or context
	Locked                        // the token is locked
	Unavailable                   // the token cannot answer now
	Internal                      // anything else; nothing about it is said to the client
)

// Error is a typed failure. Result is the word of the audit log; Retry says that asking again later may work.
type Error struct {
	Kind   Kind
	Msg    string
	Result string
	Retry  bool
}

func (e *Error) Error() string { return fmt.Sprintf("%s (%s)", e.Msg, e.Result) }

func fail(k Kind, result, msg string, retry bool) *Error {
	return &Error{Kind: k, Msg: msg, Result: result, Retry: retry}
}
