package main

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

func scanDomain(domain string, mxDomain string, address string) (scanResult, error) {
	result := scanResult{}
	result.Timestamp = time.Now().UnixNano()
	result.Address = address
	result.TlsVersion = 0
	result.HasTls = false
	result.TlsConnectionSucceeded = false

	return result, nil
}

func scan(config *scanConfig) (scanResult, error) {
	parts := strings.Split(config.value, " ")

	result := scanResult{}
	switch config.scanInputType {
	case DOMAIN:
		if len(parts) != 3 {
			return result, errors.New(fmt.Sprintf("Invalid number of parts (%v)", len(parts)))
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
			log.Println(fmt.Sprintf("WARNING: Failed to handle config line [%v]", config), err)
		} else {
			resultChan <- result
		}
	}
	doneChan <- 1
}
