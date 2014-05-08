package main

import (
	"crypto/tls"
	"github.com/gdbelvin/starttls_scan/smtp"
)

type ConnInfo struct {
	domain     string
	hastls     bool
	tlssuccess bool
	tcp        bool
	conn       *tls.Conn
}

func DoConnect(addr string) (ConnInfo, error) {
	ret := ConnInfo{domain: addr}

	tls_conn, err := smtp.DialSTARTTLS(addr)
	if err != nil {
		return ret, err
	}
	ret.conn = tls_conn
	return ret, nil
}
