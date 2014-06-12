package main

import (
	"errors"
	"fmt"
	"github.com/gdbelvin/starttls_scan/smtp"
	"log"
	"strings"
	"time"
)

func scanDomain(domain string, mxDomain string, address string) ScanResult {
	result := ScanResult{}
	result.Timestamp = time.Now().UnixNano()
	result.Address = address

	client, _ := smtp.DialSMTP(address)
	if client != nil {
		result.ConnectionSuceeded = true
		//result.SmtpConnectionState = client.SmtpConnectionState()
	}
	//result.Error = err
	return result
}

// scan scans a single domain, given a flexible scan config.
// config.value: (string) domain mxDomain address
func scan(config *scanConfig) (ScanResult, error) {
	parts := strings.Split(config.value, " ")

	result := ScanResult{}
	switch config.scanInputType {
	case DOMAIN:
		if len(parts) != 3 {
			return result, fmt.Errorf("Invalid number of parts (%v)", len(parts))
		}
		return scanDomain(parts[0], parts[1], parts[2]), nil
	case MXADDR:
		mxaddr := fmt.Sprintf("%s:25", config.value)
		return scanDomain("", "", mxaddr), nil

	default:
		return result, errors.New("Unknown scan input type")
	}

	return result, nil
}

func scanner(taskChan chan scanConfig, resultChan chan ScanResult, doneChan chan int) {
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
