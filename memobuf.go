package fourtosix

import "io"

type MemorizingReader struct {
	Reader io.Reader
	buf    []byte
}

func (mr *MemorizingReader) Read(b []byte) (n int, err error) {
	n, err = mr.Reader.Read(b)
	mr.buf = append(mr.buf, b[:n]...)
	return n, err
}

func (mr *MemorizingReader) Buffer() []byte {
	return mr.buf
}
