package tls

import "fmt"

type tlsError struct {
	err   error
	alert uint8
}

func (err *tlsError) Error() string {
	return err.err.Error()
}

func tlsErrorf(alert uint8, msgf string, params ...interface{}) *tlsError {
	return &tlsError{
		err:   fmt.Errorf(msgf, params...),
		alert: alert,
	}
}
