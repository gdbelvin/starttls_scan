package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/gdbelvin/starttls_scan/smtp"
	"log"
	"strings"
	"time"
)

func DoConnect(addr string) (ConnInfo, error) {
	ret.conn = tls_conn
	return ret, nil
}

func scanDomain(domain string, mxDomain string, address string) (scanResult, error) {
	result := scanResult{}
	result.Timestamp = time.Now().UnixNano()
	result.Address = address

	conn, has_tls, did_smtp, did_tcp, err := smtp.DialSTARTTLS(addr)
	result.TlsConnectionSucceeded = (result.Conn != nil)
	if err != nil {
		return result, err
	}
	result.TlsVersion = result.Conn.vers
	result.CipherSuite = result.Conn.cipherSuite
	result.PeerCertificates = result.Conn.peerCertificates

	return result, nil
}

// scan scans a single domain, given a flexible scan config.
// config.value: (string) domain mxDomain address
func scan(config *scanConfig) (scanResult, error) {
	parts := strings.Split(config.value, " ")

	result := scanResult{}
	switch config.scanInputType {
	case DOMAIN:
		if len(parts) != 3 {
			return result, fmt.Errorf("Invalid number of parts (%v)", len(parts))
		}
		return scanDomain(parts[0], parts[1], parts[2])

	default:
		return result, errors.New("Unknown scan input type")
	}

	return result, nil
}

func scanner(taskChan chan scanConfig, resultChan chan scanResult, doneChan chan int) {
	for config := range taskChan {
		result, err := scan(&config)
		if err != nil {
			log.Printf("WARNING: Failed to handle config line [%v], err: [%v]", config, err)
		} else {
			resultChan <- result
		}
	}
	doneChan <- 1
}
