package tls

import "io"

type memorizingReader struct {
	r   io.Reader
	buf []byte
}

func (mr *memorizingReader) Read(b []byte) (n int, err error) {
	n, err = mr.r.Read(b)
	mr.buf = append(mr.buf, b[:n]...)
	return n, err
}
