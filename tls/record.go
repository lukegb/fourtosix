package tls

import (
	"fmt"
	"io"
)

func readRecord(r io.Reader, contentType uint8) ([]byte, error) {
	head := make([]byte, 5)
	if n, err := r.Read(head); err != nil {
		return nil, err
	} else if n != 5 {
		return nil, fmt.Errorf("read %d bytes, wanted %d", n, 5)
	}

	if head[0] != contentType {
		return nil, fmt.Errorf("unexpected content type %d, wanted %d", head[0], contentType)
	}

	ln := uint16(head[3])<<8 | uint16(head[4])
	fragment := make([]byte, ln)
	if n, err := r.Read(fragment); err != nil {
		return nil, err
	} else if n != int(ln) {
		return nil, fmt.Errorf("read %d bytes of fragment, wanted %d", n, ln)
	}

	return fragment, nil
}
