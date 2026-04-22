package frameio

import "bytes"

// newBytesReader wraps a byte slice into a ReadSeeker compatible with
// http.NewRequest's expectations (io.Reader with implicit rewind support).
func newBytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
